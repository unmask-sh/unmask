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
}

// Score returns a [0, 1] human-likelihood score.
func Score(s *Signal) float64 {
	if s == nil {
		return 0
	}
	score := 1.0

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

// MathChallenge returns (a, b, token).  Verify the answer with VerifyMath.
//
// token is HMAC(answer, secret_for_today).  secret rotates daily, so old
// challenges naturally expire.
func MathChallenge(captchaSecretBase string) (int, int, string) {
	a := randomInt(1, 20)
	b := randomInt(1, 20)
	token := hmac.New(sha256.New, mathSecret(captchaSecretBase, today()))
	token.Write([]byte(strconv.Itoa(a + b)))
	return a, b, hex.EncodeToString(token.Sum(nil))
}

// VerifyMath returns true iff answerStr is a non-negative integer whose HMAC
// matches token.
func VerifyMath(answerStr, token, captchaSecretBase string) bool {
	s := strings.TrimSpace(answerStr)
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	mac := hmac.New(sha256.New, mathSecret(captchaSecretBase, today()))
	mac.Write([]byte(s))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(token))
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
