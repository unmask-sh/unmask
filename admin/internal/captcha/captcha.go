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
// is "<issued>.<hmac>" with hmac = HMAC(mathSecret(base, dayOf(issued)), "math:<issued>:<a+b>:<ct>"),
// so a solved (answer, token) pair is bound to a freshness window (see
// VerifyMath), to the secret of the day it was issued, and to ct: the
// proof-of-load token of the page the question was drawn for.  The question
// used to sign the sum alone, and a sum is one of 39 values -- a script that
// drew a question once could answer it under any page's token.  Now the
// answer is accepted only with the ct it was asked under, and that ct is
// consumed by the answer.
//
// The question's token carries no binding of its own: the ct it is bound to
// is bound to the client (Binding), and the /verify math path checks that
// ct for the request answering, so a question drawn through one exit of a
// relay and answered through another still holds, the way the pass cookie
// does.  What keeps one fetch of the question from minting more than one
// pass is that same ct, which is single-use (UsedSet).
func MathChallenge(captchaSecretBase, ct string) (int, int, string) {
	return mathChallengeAt(captchaSecretBase, ct, time.Now())
}

func mathChallengeAt(captchaSecretBase, ct string, now time.Time) (int, int, string) {
	a := randomInt(1, 20)
	b := randomInt(1, 20)
	issued := now.Unix()
	mac := hmac.New(sha256.New, mathSecret(captchaSecretBase, dayOf(issued)))
	mac.Write([]byte("math:" + strconv.FormatInt(issued, 10) + ":" + strconv.Itoa(a+b) + ":" + ct))
	return a, b, strconv.FormatInt(issued, 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

// VerifyMath returns true iff answerStr is a non-negative integer and token is a
// fresh HMAC for that answer under ct: issued within validSecs and signed with
// the secret of the day the token names.  Returns false on any malformation.
func VerifyMath(answerStr, token, ct, captchaSecretBase string, validSecs int64) bool {
	return verifyMathAt(answerStr, token, ct, captchaSecretBase, validSecs, time.Now())
}

func verifyMathAt(answerStr, token, ct, captchaSecretBase string, validSecs int64, now time.Time) bool {
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
	mac.Write([]byte("math:" + issuedStr + ":" + s + ":" + ct))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

// Binding is what a proof-of-load token is tied to: the client the page was
// served to and the chain it was served.
//
//   - Key is the bind key the pass cookie minted from this page is bound to
//     (the address, or a relay's range / id), Host the vhost -- the same two
//     values cookies.IssueValue binds, through the same derivation, so a
//     visitor whose own requests leave through several exits of one relay
//     keeps the token the way they keep the cookie.  A token used to be bound
//     to nothing on this side, and a page fetched from one address could be
//     answered from any other: a script spent tokens harvested anywhere.
//   - JA4 is the fingerprint of the connection the page went out on, as the
//     daemon saw it ("" when the deployment hands it none); VerifyToken reads
//     the answer's against it through SameTLSStack.
//   - Chain is the challenge chain the page ran (pow_only / captcha_only /
//     pow_then_captcha).  The verify reads it back to know what the page owed
//     before the CAPTCHA -- a proof-of-work leg or none -- and what grade of
//     pass clearing the CAPTCHA earns.  Signed, so a client cannot answer a
//     proof-of-work page as if it had been a CAPTCHA-only one.
type Binding struct {
	Key   string
	Host  string
	JA4   string
	Chain string
}

// Claims is what VerifyToken read out of a token it accepted.
type Claims struct {
	Issued int64
	JA4    string
	Chain  string
}

// IssueToken returns a proof-of-load token for the page served at now to the
// client b describes: "<issued>.<nonce>.<chain>.<ja4>.<hmac>", hmac =
// HMAC(mathSecret(base, dayOf(issued)), the fields and the binding, newline
// separated).  The nonce makes every token distinct, which is what lets
// UsedSet refuse a second pass on the same one; the timestamp bounds its life
// (VerifyToken); the chain and the fingerprint travel in the clear because
// the verifier needs them back, and the signature covers them.
func IssueToken(captchaSecretBase string, now time.Time, b Binding) string {
	issuedSec := now.Unix()
	issued := strconv.FormatInt(issuedSec, 10)
	nonce := tokenNonce()
	sig := tokenMAC(captchaSecretBase, issuedSec, issued, nonce, b)
	return issued + "." + nonce + "." + b.Chain + "." + b.JA4 + "." + sig
}

// tokenMAC: the token's signature over its own fields and the binding.  The
// separator cannot occur in any field (a header value carries no newline, and
// the chain and the nonce are the daemon's own), so no two bindings share an
// input.
func tokenMAC(base string, issuedSec int64, issued, nonce string, b Binding) string {
	mac := hmac.New(sha256.New, mathSecret(base, dayOf(issuedSec)))
	mac.Write([]byte("ct2\n" + issued + "\n" + nonce + "\n" + b.Chain + "\n" + b.Key + "\n" + b.Host + "\n" + b.JA4))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyToken validates a token from IssueToken for the client answering
// under it -- key and host as the answer's request binds them, ja4 as the
// daemon sees the answer's connection: the HMAC must match under the
// token's own chain and fingerprint, issued must be within validSecs, and
// the answer's fingerprint must be the same TLS stack as the page's
// (SameTLSStack).  Returns the claims the token carries, and false on any
// malformation or mismatch.  It does not consume the token; the caller does
// that with UsedSet once the token has earned a pass.
func VerifyToken(token, captchaSecretBase string, validSecs int64, key, host, ja4 string) (Claims, bool) {
	return verifyTokenAt(token, captchaSecretBase, validSecs, key, host, ja4, time.Now())
}

func verifyTokenAt(token, captchaSecretBase string, validSecs int64, key, host, ja4 string, now time.Time) (Claims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[0] == "" || parts[1] == "" || parts[4] == "" {
		return Claims{}, false
	}
	issuedStr, nonce, chain, tokJA4, sig := parts[0], parts[1], parts[2], parts[3], parts[4]
	issued, err := strconv.ParseInt(issuedStr, 10, 64)
	if err != nil {
		return Claims{}, false
	}
	nowSec := now.Unix()
	if issued > nowSec+60 || nowSec-issued > validSecs {
		return Claims{}, false
	}
	expected := tokenMAC(captchaSecretBase, issued, issuedStr, nonce, Binding{Key: key, Host: host, JA4: tokJA4, Chain: chain})
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return Claims{}, false
	}
	if !SameTLSStack(tokJA4, ja4) {
		return Claims{}, false
	}
	return Claims{Issued: issued, JA4: tokJA4, Chain: chain}, true
}

// SameTLSStack reports whether two JA4 fingerprints can be one device's.  A
// token is spent on the fingerprint it was issued under, with the two ways a
// browser's own fingerprint moves between the page and the answer allowed
// for: the connection was resumed (a resumed TLS 1.3 session carries one
// more extension, so the extension count and hash differ while the cipher
// list is the same), or the device moved to its other transport (HTTP/3 over
// QUIC against HTTP/2 over TCP differs in every field).  So two fingerprints
// agree when they are equal, when they share the cipher hash (the middle
// field), or when their transports differ.  An empty side is unknown rather
// than a contradiction: a deployment that hands the daemon no fingerprint
// hands it none on either request.  What this refuses is the page fetched
// by one TLS stack and answered by another over the same transport -- a
// browser's page answered by a script.
func SameTLSStack(a, b string) bool {
	if a == b || a == "" || b == "" {
		return true
	}
	if (a[0] == 't' && b[0] == 'q') || (a[0] == 'q' && b[0] == 't') {
		return true
	}
	ca, cb := ja4CipherHash(a), ja4CipherHash(b)
	return ca != "" && ca == cb
}

// ja4CipherHash is the middle field of a JA4 ("t13d1516h2_<ciphers>_<exts>"),
// "" when the string is not shaped like one.
func ja4CipherHash(s string) string {
	parts := strings.Split(s, "_")
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}

// TokenMinAgeSeconds is how old a proof-of-load token has to be before an
// answer under it is taken: the page was served this many seconds ago, at
// least.  A person meets the card, reads it and moves to the box, which takes
// longer than this from the moment the daemon wrote the page; a script that
// fetches the page and posts a fabricated signal in the same breath does not.
// Two seconds of the token's clock, which is whole seconds, is between one
// and two seconds of real time.  A faster answer is not refused for good:
// the behavioral one is sent to the arithmetic, which takes time of its own.
const TokenMinAgeSeconds int64 = 2

// TokenAge is how many whole seconds ago the token says it was issued, for a
// token VerifyToken has already accepted; false when the token does not
// carry a time at all.
func TokenAge(token string, now time.Time) (int64, bool) {
	issuedStr, _, _ := strings.Cut(token, ".")
	issued, err := strconv.ParseInt(issuedStr, 10, 64)
	if err != nil {
		return 0, false
	}
	return now.Unix() - issued, true
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
// so each one earns exactly one: one fetch of a challenge, one pass.  The
// binding (Binding) says who may spend a token; this says how often.
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
