// Package captcha: behavioral signal scoring + math fallback.
//
// Input signal (POSTed by the JS inside the challenge HTML):
//
//	mouseTrail      [][x, y, t]       up to 200 points (clientX, clientY, performance.now() ms)
//	scrolls         [][scrollY, t]
//	keys            int (key press count)
//	clickAt         float (= ms after load)
//	hasMouseEvents  bool
//	hasTouchEvents  bool
//	windowSize      [w, h]
//	screenSize      [w, h]
//
// Scoring (1.0 = clearly human):
//
//	no input device events                        -0.6
//	clickAt < 500ms (= clicked immediately)       -0.5
//	mouseEvents present yet mouseTrail <=1 pt     -0.6  (= headless click, no mousemove run)
//	mouseEvents present yet mouseTrail 2-4 pts    -0.3
//	mouseTrail is a perfect line (mean dev <2px)  -0.3
//	windowSize = [0,0] / missing (= headless)     -0.4
package captcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
)

type Signal struct {
	MouseTrail     [][]float64 `json:"mouseTrail"`
	Scrolls        [][]float64 `json:"scrolls"`
	Keys           int         `json:"keys"`
	ClickAt        float64     `json:"clickAt"`
	HasMouseEvents bool        `json:"hasMouseEvents"`
	HasTouchEvents bool        `json:"hasTouchEvents"`
	WindowSize     []float64   `json:"windowSize"`
	ScreenSize     []float64   `json:"screenSize"`
	// Untrusted: at least one input event arrived with isTrusted false, i.e.
	// the page dispatched it to itself.  A browser sets this flag itself and a
	// page cannot forge it upward, so a real person never trips it.
	Untrusted bool `json:"untrusted"`
	// MaxTouchPoints: navigator.maxTouchPoints.  Used against the user agent:
	// a phone that reports no touch capability is not a phone.
	MaxTouchPoints int `json:"maxTouchPoints"`
}

// Score returns a [0, 1] human-likelihood score.  ua is the request's own
// User-Agent as the server saw it: some of what separates a person from a
// driver is not in the input at all but in whether the input agrees with the
// device being claimed.
func Score(s *Signal, ua string) float64 {
	if s == nil {
		return 0
	}
	score := 1.0

	// Self-dispatched events.  dispatchEvent() cannot set isTrusted, so a page
	// that fakes its own interaction is saying so in the flag.  (Automation
	// driven through the browser's input layer -- CDP and friends -- produces
	// trusted events, so this catches the cheap tier and only the cheap tier.)
	if s.Untrusted {
		score -= 0.6
	}

	// A device that cannot be what it says it is.  A phone reporting no touch
	// points, or one whose only input was a mouse cursor, is a desktop
	// automation wearing a phone's name -- and the name is the part that is
	// free to change.  Only this direction is a contradiction: touch-capable
	// laptops are ordinary, so touch from a desktop UA says nothing.
	if isMobileUA(ua) {
		if s.MaxTouchPoints == 0 && (s.HasMouseEvents || len(s.MouseTrail) > 0) {
			// No touch capability at all while a cursor moved across the page:
			// every phone browser in circulation reports touch points, so this
			// pair cannot both be true of one device.  Decisive on its own.
			score -= 0.6
		} else if s.HasMouseEvents && !s.HasTouchEvents && len(s.MouseTrail) >= 5 {
			score -= 0.4
		}
	}

	// Motion that no hand produced.  The trail carries a timestamp per point
	// and nothing here used to read it, which left the whole time axis
	// unguarded: a driver can shape a curve to satisfy the geometry checks
	// below while still stepping it at a fixed interval and a constant speed,
	// neither of which survives contact with a human arm.  Both tests are
	// deliberately extreme -- real hardware jitters -- so a person tripping one
	// still clears the threshold on the rest.
	if m := motionRegularity(s.MouseTrail); m.samples >= 8 {
		// How many DIFFERENT step lengths the movement contains.  A driver
		// interpolating a path divides each leg by a step count and emits that
		// one delta for the whole leg, so a long trail carries a handful of
		// lengths; a hand accelerating and slowing between clock-driven
		// samples produces a different length almost every time.
		//
		// Measured against a real CDP-driven browser rather than assumed.  Its
		// timing jittered like any other input (5-30ms gaps) and the spread of
		// lengths across the whole trail was wide, because each leg used its
		// own step -- so neither the interval nor the variance says anything.
		// What it could not hide: 69 segments carrying 8 distinct lengths.
		//
		// Only steps beyond a few pixels count.  Below that, integer
		// coordinates quantise a slow hand's movement into a small set of
		// lengths for reasons that have nothing to do with automation.
		if m.qualifying >= 15 && m.distinctRatio <= 0.25 {
			score -= 0.6
		}
		// Equal gaps: the cruder shape, a loop dispatching on a timer.
		if m.identicalRatio >= 0.8 {
			score -= 0.4
		}
		if m.speedCV >= 0 && m.speedCV < 0.05 {
			score -= 0.4
		}
	}

	hasInput := s.HasMouseEvents || s.HasTouchEvents
	if !hasInput {
		score -= 0.6
	}

	if s.ClickAt > 0 && s.ClickAt < 500 {
		score -= 0.5
	}

	// A client that reports mouse events but almost no trail is contradictory:
	// moving a cursor to the checkbox produces a stream of mousemove points, so
	// a trail of <=1 point (just the click coordinate) is a headless-automation
	// tell -- Playwright/Puppeteer .click() synthesizes the click without the
	// human mousemove run, which is how a headless browser scored 0.7 and cleared
	// the behavioral check on behavioral signal alone.  Penalize that hard; a
	// merely short trail (2-4 pts, a fast but real cursor move) stays a soft -0.3.
	if s.HasMouseEvents {
		if len(s.MouseTrail) <= 1 {
			score -= 0.6
		} else if len(s.MouseTrail) < 5 {
			score -= 0.3
		}
	}

	// Straightness check: mean distance of mid-trail points from the first→last line.
	if len(s.MouseTrail) >= 10 {
		first := s.MouseTrail[0]
		last := s.MouseTrail[len(s.MouseTrail)-1]
		if len(first) >= 2 && len(last) >= 2 {
			dx := last[0] - first[0]
			dy := last[1] - first[1]
			lineLen := math.Hypot(dx, dy)
			if lineLen > 30 {
				var total float64
				var count int
				for _, pt := range s.MouseTrail[1 : len(s.MouseTrail)-1] {
					if len(pt) < 2 {
						continue
					}
					x, y := pt[0], pt[1]
					// |dy*x - dx*y + last_x*first_y - last_y*first_x| / lineLen
					d := math.Abs(dy*x-dx*y+last[0]*first[1]-last[1]*first[0]) / lineLen
					total += d
					count++
				}
				if count > 0 && total/float64(count) < 2 {
					score -= 0.3
				}
			}
		}
	}

	if len(s.WindowSize) >= 2 && (s.WindowSize[0] == 0 || s.WindowSize[1] == 0) {
		score -= 0.4
	}

	if score < 0 {
		return 0
	}
	return score
}

// motionStats: what the trail's time axis says about who moved the cursor.
type motionStats struct {
	samples        int
	identicalRatio float64 // share of inter-point gaps that are exactly equal
	speedCV        float64 // coefficient of variation of per-segment speed; -1 = not computable
	distCV         float64 // coefficient of variation of per-segment distance; -1 = not computable
	// qualifying: segments long enough to be deliberate movement rather than
	// coordinate rounding.  distinctRatio: how many different lengths those
	// carry, over how many there are -- interpolation's signature is a
	// handful of lengths spread over a long trail.
	qualifying    int
	distinctRatio float64
}

// motionRegularity reads the timestamps the trail already carried.  A hand
// moving a mouse produces gaps that scatter (the OS samples at its own rate,
// the arm accelerates and stops) and speeds that rise and fall.  A driver
// stepping a path emits one gap and one speed.
func motionRegularity(trail [][]float64) motionStats {
	out := motionStats{speedCV: -1, distCV: -1}
	if len(trail) < 3 {
		return out
	}
	gaps := map[int]int{}
	var speeds, dists []float64
	prev := trail[0]
	for _, pt := range trail[1:] {
		if len(pt) < 3 || len(prev) < 3 {
			prev = pt
			continue
		}
		dt := pt[2] - prev[2]
		if dt <= 0 {
			prev = pt
			continue
		}
		gaps[int(dt)]++
		out.samples++
		d := math.Hypot(pt[0]-prev[0], pt[1]-prev[1])
		dists = append(dists, d)
		speeds = append(speeds, d/dt)
		prev = pt
	}
	if out.samples == 0 {
		return out
	}
	most := 0
	for _, n := range gaps {
		if n > most {
			most = n
		}
	}
	out.identicalRatio = float64(most) / float64(out.samples)

	out.speedCV = coeffVar(speeds)
	out.distCV = coeffVar(dists)

	// Only movements of a few pixels or more: below that, rounding to integer
	// coordinates gives a hand few distinct lengths for its own reasons.
	seen := map[int]struct{}{}
	for _, d := range dists {
		if d <= 3 {
			continue
		}
		out.qualifying++
		seen[int(d*10)] = struct{}{} // 0.1px resolution
	}
	if out.qualifying > 0 {
		out.distinctRatio = float64(len(seen)) / float64(out.qualifying)
	}
	return out
}

// coeffVar: standard deviation over mean, or -1 when the sample says nothing.
func coeffVar(xs []float64) float64 {
	if len(xs) < 3 {
		return -1
	}
	var sum float64
	for _, v := range xs {
		sum += v
	}
	mean := sum / float64(len(xs))
	if mean <= 0 {
		return -1
	}
	var vr float64
	for _, v := range xs {
		vr += (v - mean) * (v - mean)
	}
	return math.Sqrt(vr/float64(len(xs))) / mean
}

// isMobileUA: does this user agent claim a phone or tablet?  Only the claim
// matters here -- the point of the check above is comparing it against what
// the device actually did.
func isMobileUA(ua string) bool {
	u := strings.ToLower(ua)
	for _, tok := range []string{"android", "iphone", "ipad", "ipod", "windows phone", "mobile safari"} {
		if strings.Contains(u, tok) {
			return true
		}
	}
	return false
}

// MathChallenge returns (a, b, token) for the client at ip.  token is
// "<issued>.<hmac>" with hmac = HMAC(mathSecret(base, today), "math:<issued>:<ip>:<a+b>"),
// so a solved (answer, token) pair is bound to the issuing IP and a freshness
// window (see VerifyMath) -- it can't be harvested once and replayed from
// another IP, nor reused after it goes stale.  True single-use is intentionally
// not enforced: math is a trivially-solvable fallback behind PoW, and the
// /verify path additionally requires the IP-bound ct proof-of-load token.
func MathChallenge(captchaSecretBase, ip string) (int, int, string) {
	a := randomInt(1, 20)
	b := randomInt(1, 20)
	issued := time.Now().Unix()
	mac := hmac.New(sha256.New, mathSecret(captchaSecretBase, today()))
	mac.Write([]byte("math:" + strconv.FormatInt(issued, 10) + ":" + ip + ":" + strconv.Itoa(a+b)))
	return a, b, strconv.FormatInt(issued, 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

// VerifyMath returns true iff answerStr is a non-negative integer and token is a
// fresh, IP-matching HMAC for that answer: issued within validSecs for ip and
// signed with today's secret.  Returns false on any malformation.
func VerifyMath(answerStr, token, captchaSecretBase, ip string, validSecs int64) bool {
	s := strings.TrimSpace(answerStr)
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	dot := strings.IndexByte(token, '.')
	if dot <= 0 || dot >= len(token)-1 {
		return false
	}
	issuedStr, sig := token[:dot], token[dot+1:]
	issued, err := strconv.ParseInt(issuedStr, 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	if issued > now+60 || now-issued > validSecs {
		return false
	}
	mac := hmac.New(sha256.New, mathSecret(captchaSecretBase, today()))
	mac.Write([]byte("math:" + issuedStr + ":" + ip + ":" + s))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

// IssueToken returns a proof-of-load token bound to the client IP and the
// current time: "<issued>.<hmac>", hmac = HMAC(mathSecret(base, today), "ct:<issued>:<ip>").
// The challenge page embeds it (window.UNMASK.ct) and challenge.js echoes it on
// the behavioral-CAPTCHA submit, so the server can require that the client
// actually fetched THIS challenge for THIS IP before accepting a behavioral
// score (which the client fully controls and can forge from a blind POST).
func IssueToken(captchaSecretBase, ip string) string {
	issued := time.Now().Unix()
	mac := hmac.New(sha256.New, mathSecret(captchaSecretBase, today()))
	mac.Write([]byte("ct:" + strconv.FormatInt(issued, 10) + ":" + ip))
	return strconv.FormatInt(issued, 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

// VerifyToken validates a token from IssueToken for the given IP: the HMAC must
// match and issued must be within validSecs (and the daily secret rotation
// bounds it further).  Returns false on any malformation.
func VerifyToken(token, captchaSecretBase, ip string, validSecs int64) bool {
	dot := strings.IndexByte(token, '.')
	if dot <= 0 || dot >= len(token)-1 {
		return false
	}
	issuedStr, sig := token[:dot], token[dot+1:]
	issued, err := strconv.ParseInt(issuedStr, 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	if issued > now+60 || now-issued > validSecs {
		return false
	}
	mac := hmac.New(sha256.New, mathSecret(captchaSecretBase, today()))
	mac.Write([]byte("ct:" + issuedStr + ":" + ip))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

func today() int64 { return time.Now().Unix() / 86400 }

func mathSecret(base string, day int64) []byte {
	mac := hmac.New(sha256.New, []byte(base))
	mac.Write([]byte(strconv.FormatInt(day, 10)))
	return mac.Sum(nil)
}

func randomInt(min, max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		// CSPRNG failure should be effectively impossible; fall back to a time-based value.
		return min + int(time.Now().UnixNano())%int(max-min+1)
	}
	return min + int(n.Int64())
}
