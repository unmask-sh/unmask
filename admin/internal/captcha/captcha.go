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
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/big"
	"strconv"
	"strings"
	"sync"
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

	// Any input device counts, the keyboard included: a visitor who tabs to
	// the box and presses space produces no mouse or touch event at all, and
	// used to lose 0.6 here for it -- straight into the arithmetic fallback on
	// every visit.  (A script can claim key presses as easily as mouse events;
	// the signal was never what kept scripts out, the proof-of-load token is.)
	hasInput := s.HasMouseEvents || s.HasTouchEvents || s.Keys > 0
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

// TokenValidSeconds bounds the life of a proof-of-load token and of a math
// token: a visitor gets this long between the challenge page (or the question)
// and the answer.  TokenTTL is the same span for UsedSet, so a consumed token
// is remembered for exactly as long as it could still verify.
const TokenValidSeconds int64 = 900

const TokenTTL = time.Duration(TokenValidSeconds) * time.Second

// MathChallenge returns (a, b, token) for a fresh arithmetic question.  token
// is "<issued>.<hmac>" with hmac = HMAC(mathSecret(base, dayOf(issued)), "math:<issued>:<a+b>"),
// so a solved (answer, token) pair is bound to a freshness window (see
// VerifyMath) and to the secret of the day it was issued.
//
// The token is deliberately not bound to the client's address.  It used to be,
// so a harvested (answer, token) pair could not be replayed from another
// network -- and that binding locked out every visitor whose connections leave
// through more than one exit (a two-uplink NAT, a relay that picks a fresh
// egress per request): the question went out through one address and the
// answer came back through another, every time, so the fallback meant to
// rescue them never could.  What keeps one fetch of the question from minting
// more than one pass is the ct proof-of-load token the /verify math path also
// requires, which is single-use (UsedSet).
func MathChallenge(captchaSecretBase string) (int, int, string) {
	return mathChallengeAt(captchaSecretBase, time.Now())
}

func mathChallengeAt(captchaSecretBase string, now time.Time) (int, int, string) {
	a := randomInt(1, 20)
	b := randomInt(1, 20)
	issued := now.Unix()
	mac := hmac.New(sha256.New, mathSecret(captchaSecretBase, dayOf(issued)))
	mac.Write([]byte("math:" + strconv.FormatInt(issued, 10) + ":" + strconv.Itoa(a+b)))
	return a, b, strconv.FormatInt(issued, 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

// VerifyMath returns true iff answerStr is a non-negative integer and token is a
// fresh HMAC for that answer: issued within validSecs and signed with the
// secret of the day the token names.  Returns false on any malformation.
func VerifyMath(answerStr, token, captchaSecretBase string, validSecs int64) bool {
	return verifyMathAt(answerStr, token, captchaSecretBase, validSecs, time.Now())
}

func verifyMathAt(answerStr, token, captchaSecretBase string, validSecs int64, now time.Time) bool {
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
	nowSec := now.Unix()
	if issued > nowSec+60 || nowSec-issued > validSecs {
		return false
	}
	mac := hmac.New(sha256.New, mathSecret(captchaSecretBase, dayOf(issued)))
	mac.Write([]byte("math:" + issuedStr + ":" + s))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

// IssueToken returns a proof-of-load token: "<issued>.<nonce>.<hmac>", hmac =
// HMAC(mathSecret(base, dayOf(issued)), "ct:<issued>:<nonce>").  The nonce makes every
// token distinct, which is what lets UsedSet refuse a second pass on the same
// one; the timestamp bounds its life (VerifyToken).  Like the math token it is
// not bound to the client's address -- MathChallenge has the reason.
func IssueToken(captchaSecretBase string) string {
	return issueTokenAt(captchaSecretBase, time.Now())
}

func issueTokenAt(captchaSecretBase string, now time.Time) string {
	issuedSec := now.Unix()
	issued := strconv.FormatInt(issuedSec, 10)
	nonce := tokenNonce()
	mac := hmac.New(sha256.New, mathSecret(captchaSecretBase, dayOf(issuedSec)))
	mac.Write([]byte("ct:" + issued + ":" + nonce))
	return issued + "." + nonce + "." + hex.EncodeToString(mac.Sum(nil))
}

// VerifyToken validates a token from IssueToken: the HMAC must match and
// issued must be within validSecs.  Returns false on any malformation.  It
// does not consume the token; the caller does that with UsedSet once the
// token has earned a pass.
func VerifyToken(token, captchaSecretBase string, validSecs int64) bool {
	return verifyTokenAt(token, captchaSecretBase, validSecs, time.Now())
}

func verifyTokenAt(token, captchaSecretBase string, validSecs int64, now time.Time) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}
	issuedStr, nonce, sig := parts[0], parts[1], parts[2]
	issued, err := strconv.ParseInt(issuedStr, 10, 64)
	if err != nil {
		return false
	}
	nowSec := now.Unix()
	if issued > nowSec+60 || nowSec-issued > validSecs {
		return false
	}
	mac := hmac.New(sha256.New, mathSecret(captchaSecretBase, dayOf(issued)))
	mac.Write([]byte("ct:" + issuedStr + ":" + nonce))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

// tokenNonce: 64 random bits as 16 hex chars.  crypto/rand failing on a
// running server is vanishingly rare; the nanosecond clock then still gives
// consecutive tokens distinct values rather than refusing to issue one.
func tokenNonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
	}
	return hex.EncodeToString(b[:])
}

// UsedSet remembers the proof-of-load tokens that have already earned a pass,
// so each one earns exactly one.  Before this the token was bound to the
// client's address instead, which kept a harvested token from being replayed
// from other networks but also failed every visitor whose own requests arrive
// from more than one (MathChallenge has the story).  Single use keeps the
// property that mattered -- one fetch of a challenge, one pass -- and drops
// the one that did not.
//
// The set lives in this process: on a multi-node install behind a balancer a
// token could earn one pass per node before it expires, which is still a
// bound a blind POST flood never had.  Entries expire with the token (the
// caller passes the same window VerifyToken enforces) and are swept as the
// set is used; a flood of distinct tokens cannot grow it without limit
// because past maxUsedTokens the sweep drops everything, trading a short
// replay window for bounded memory.  The zero value is ready to use.
type UsedSet struct {
	mu  sync.Mutex
	m   map[string]int64 // token -> expiry (unix seconds)
	ops int
}

// maxUsedTokens: the set is dropped wholesale when it still holds more than
// this after expired entries are swept (= a flood of distinct, unexpired
// tokens).  At ~100 bytes a token that is on the order of 15 MB.
const maxUsedTokens = 1 << 17

// Consume records token as used.  It returns true the first time it sees a
// token and false for every later call until the token has been held for ttl.
func (u *UsedSet) Consume(token string, ttl time.Duration) bool {
	return u.consumeAt(token, ttl, time.Now())
}

func (u *UsedSet) consumeAt(token string, ttl time.Duration, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.m == nil {
		u.m = make(map[string]int64)
	}
	n := now.Unix()
	if exp, seen := u.m[token]; seen && exp > n {
		return false
	}
	exp := now.Add(ttl).Unix()
	u.m[token] = exp
	u.ops++
	if u.ops >= 1024 || len(u.m) > maxUsedTokens {
		u.ops = 0
		for k, e := range u.m {
			if e <= n {
				delete(u.m, k)
			}
		}
		if len(u.m) > maxUsedTokens {
			u.m = map[string]int64{token: exp}
		}
	}
	return true
}

// dayOf is the UTC day a unix timestamp falls in, which selects the daily
// key.  It is taken from the day a token was ISSUED, which the token itself
// states, so a token issued in the last minutes of a day still verifies in
// the first minutes of the next, inside its freshness window.  The key used
// to be the day of VERIFICATION: a page served at 23:55 UTC whose visitor
// answered at 00:05 was refused as stale, and the arithmetic fallback it fell
// to was refused the same way.  Nothing is weakened: the day is written in
// the clear in the token either way, and the freshness window still bounds
// how long any token lives.
func dayOf(unixSec int64) int64 { return unixSec / 86400 }

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
