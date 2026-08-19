package captcha

import (
	"math"
	"testing"
)

// Fully human-like signal: input events present, slow click, jittery trail.
func TestScore_HumanLike(t *testing.T) {
	s := &Signal{
		HasMouseEvents: true,
		ClickAt:        3000,
		MouseTrail: [][]float64{
			{10, 10, 0}, {25, 18, 30}, {42, 31, 60}, {55, 50, 90},
			{72, 68, 120}, {90, 85, 150}, {100, 99, 180},
		},
		WindowSize: []float64{1280, 800},
	}
	if got := Score(s, ""); got < 0.9 {
		t.Errorf("human-like score should stay near 1.0, got %f", got)
	}
}

// No input events + instant click + window 0 = clearly a bot.
func TestScore_BotLike(t *testing.T) {
	s := &Signal{
		HasMouseEvents: false,
		HasTouchEvents: false,
		ClickAt:        50,
		WindowSize:     []float64{0, 0},
	}
	if got := Score(s, ""); got >= 0.5 {
		t.Errorf("bot-like score should be below threshold, got %f", got)
	}
}

// Headless automation tell: reports mouse events but the trail is just the
// click point (Playwright/Puppeteer .click() with no human mousemove run),
// while clickAt and windowSize look innocuous.  This is the real signal a
// headless Chromium POSTed (scoring 0.7 before the <=1-pt penalty); it must now
// fall below threshold so the math fallback engages instead of clearing on
// behavioral alone.
func TestScore_HeadlessEmptyTrail(t *testing.T) {
	s := &Signal{
		HasMouseEvents: true,
		ClickAt:        1073,
		MouseTrail:     [][]float64{{584, 394, 1612}},
		WindowSize:     []float64{1280, 720},
		ScreenSize:     []float64{1280, 720},
	}
	if got := Score(s, ""); got >= 0.5 {
		t.Errorf("headless empty-trail score should be below 0.5, got %f", got)
	}
}

// A fast but real cursor move (2-4 trail points) should stay above threshold:
// the <=1-pt headless penalty must not catch a hurried human.
func TestScore_ShortButRealTrail(t *testing.T) {
	s := &Signal{
		HasMouseEvents: true,
		ClickAt:        1500,
		MouseTrail:     [][]float64{{200, 150, 40}, {260, 210, 80}, {305, 248, 120}},
		WindowSize:     []float64{1280, 800},
		ScreenSize:     []float64{1920, 1080},
	}
	if got := Score(s, ""); got < 0.5 {
		t.Errorf("short-but-real trail should stay above threshold, got %f", got)
	}
}

// Perfectly straight trail = suspected bot (-0.3).  The timing here is human:
// the point is to isolate the geometry penalty from the motion checks below,
// which a fixed-interval fixture would also trip.
func TestScore_StraightLine(t *testing.T) {
	jitter := []float64{0, 17, 41, 58, 84, 96, 121, 149, 160, 188, 213, 226}
	dist := []float64{0, 8, 21, 33, 52, 74, 99, 126, 148, 163, 172, 178}
	trail := make([][]float64, 0, len(jitter))
	for i := range jitter {
		trail = append(trail, []float64{dist[i], dist[i], jitter[i]})
	}
	s := &Signal{
		HasMouseEvents: true,
		ClickAt:        3000,
		MouseTrail:     trail,
		WindowSize:     []float64{1200, 800},
	}
	if got := Score(s, ""); got > 0.71 || got < 0.69 {
		t.Errorf("straight line should give ~0.7, got %f", got)
	}
}

// A path can be curved enough to satisfy the geometry check and still be
// drawn by a driver: fixed interval per step, constant speed.  Nothing read
// the trail's time axis before, so that shape scored a clean 1.0 -- which is
// what a production headless crawler was actually doing.
func TestScore_SyntheticMotionIsCaught(t *testing.T) {
	trail := make([][]float64, 0, 20)
	for i := 0; i < 20; i++ {
		// A curve (so the straightness test is satisfied), stepped every 16ms
		// at a constant rate.
		x := float64(i * 12)
		y := 200 + 90*math.Sin(float64(i)/6)
		trail = append(trail, []float64{x, y, float64(i * 16)})
	}
	s := &Signal{
		HasMouseEvents: true,
		ClickAt:        4200,
		MouseTrail:     trail,
		WindowSize:     []float64{1200, 800},
	}
	// One tell alone is deliberately survivable -- real hardware can produce a
	// regular interval -- so this fixture is penalised but still passes.  What
	// must not happen is it scoring clean.
	if got := Score(s, ""); got >= 1.0 {
		t.Errorf("driver-stepped motion must not score clean, got %f", got)
	}

	// Fixed interval AND constant speed: no hand does both, and together they
	// take it below the threshold.
	flat := make([][]float64, 0, 20)
	for i := 0; i < 20; i++ {
		flat = append(flat, []float64{float64(i * 12), float64(i * 9), float64(i * 16)})
	}
	s2 := &Signal{HasMouseEvents: true, ClickAt: 4200, MouseTrail: flat, WindowSize: []float64{1200, 800}}
	if got := Score(s2, ""); got >= 0.5 {
		t.Errorf("fixed-interval constant-speed motion should fail, got %f", got)
	}
}

// The same shape with a hand behind it -- gaps that scatter, speed that rises
// and falls -- must stay well clear of the threshold.
func TestScore_HumanMotionSurvivesTheMotionChecks(t *testing.T) {
	gaps := []float64{0, 9, 23, 31, 48, 55, 71, 88, 96, 119, 131, 152, 168, 174, 199, 221}
	// Accelerate, then slow into the target.
	step := []float64{0, 4, 13, 27, 46, 70, 99, 132, 160, 182, 197, 206, 212, 215, 217, 218}
	trail := make([][]float64, 0, len(gaps))
	for i := range gaps {
		trail = append(trail, []float64{step[i], 300 + 60*math.Sin(float64(i)/5), gaps[i]})
	}
	s := &Signal{
		HasMouseEvents: true,
		ClickAt:        2600,
		MouseTrail:     trail,
		WindowSize:     []float64{1440, 900},
	}
	if got := Score(s, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/151.0.0.0"); got < 0.9 {
		t.Errorf("human-shaped motion must not be penalised, got %f", got)
	}
}

// The step lengths a real CDP-driven Chrome produced, captured from a live
// run against the challenge page: 69 segments carrying 8 distinct lengths,
// because each leg of the movement was divided into equal steps.  Its timing
// jittered normally and its overall spread was wide, so this is the property
// that gave it away -- pinned here so a future rewrite of the scoring cannot
// quietly stop catching it.
func TestScore_RealDriverStepQuantisation(t *testing.T) {
	legs := [][2]float64{{6.40, 20}, {5.66, 8}, {6.32, 6}, {6.71, 10}, {7.62, 9}, {16.40, 15}, {15.81, 6}, {15.00, 5}}
	trail := [][]float64{{0, 0, 0}}
	x, ts := 0.0, 0.0
	jit := []float64{11, 16, 31, 5, 26, 15, 17, 16, 7, 25, 14, 15}
	i := 0
	for _, leg := range legs {
		for n := 0; n < int(leg[1]); n++ {
			x += leg[0]
			ts += jit[i%len(jit)]
			i++
			trail = append(trail, []float64{x, 200, ts})
		}
	}
	s := &Signal{HasMouseEvents: true, ClickAt: 4000, MouseTrail: trail, WindowSize: []float64{1200, 800}}
	if got := Score(s, ""); got >= 0.5 {
		t.Errorf("a driver's step quantisation should fail the check, got %f", got)
	}
}

// The same length of trail from a hand: every segment a different length,
// because the hand is accelerating between samples that land on a clock.
func TestScore_LongHumanTrailIsNotQuantised(t *testing.T) {
	trail := [][]float64{}
	x, y, ts := 40.0, 300.0, 0.0
	// Accelerate away, drift, then settle -- no two steps alike.
	for i := 0; i < 70; i++ {
		v := 3 + 26*math.Sin(float64(i)/22) + 2.5*math.Sin(float64(i)/2.3)
		x += v
		y += 0.9*math.Cos(float64(i)/7) + 0.35*math.Sin(float64(i)/1.7)
		ts += 7 + 11*math.Abs(math.Sin(float64(i)/3.1))
		trail = append(trail, []float64{math.Round(x), math.Round(y), math.Round(ts)})
	}
	s := &Signal{HasMouseEvents: true, ClickAt: 3400, MouseTrail: trail, WindowSize: []float64{1440, 900}}
	if got := Score(s, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"); got < 0.9 {
		t.Errorf("a long human trail must stay clean, got %f", got)
	}
}

// isTrusted is set by the browser and cannot be forged upward, so an input
// event the page dispatched to itself is decisive.
func TestScore_UntrustedEvents(t *testing.T) {
	s := &Signal{HasMouseEvents: true, ClickAt: 2000, Untrusted: true,
		MouseTrail: [][]float64{{10, 10, 0}, {40, 33, 21}, {90, 60, 44}, {130, 92, 77}, {180, 120, 105}, {210, 141, 138}},
		WindowSize: []float64{1200, 800}}
	if got := Score(s, ""); got >= 0.5 {
		t.Errorf("self-dispatched input should fail, got %f", got)
	}
}

// A phone that cannot touch, moving a mouse cursor, is a desktop wearing a
// phone's name.  The reverse (touch from a desktop UA) is ordinary hardware
// and must not be penalised.
func TestScore_MobileUAContradiction(t *testing.T) {
	trail := [][]float64{{5, 5, 0}, {31, 24, 18}, {66, 51, 39}, {102, 88, 63}, {141, 120, 92}, {166, 140, 121}}
	mobile := "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/151.0.0.0 Mobile Safari/537.36"

	fake := &Signal{HasMouseEvents: true, ClickAt: 3000, MouseTrail: trail,
		WindowSize: []float64{412, 915}, MaxTouchPoints: 0}
	if got := Score(fake, mobile); got >= 0.5 {
		t.Errorf("phone UA with no touch capability and a cursor trail should fail, got %f", got)
	}

	real := &Signal{HasTouchEvents: true, ClickAt: 3000, WindowSize: []float64{412, 915}, MaxTouchPoints: 5}
	if got := Score(real, mobile); got < 0.9 {
		t.Errorf("an actual phone must be unaffected, got %f", got)
	}

	touchLaptop := &Signal{HasTouchEvents: true, HasMouseEvents: true, ClickAt: 3000, MouseTrail: trail,
		WindowSize: []float64{1440, 900}, MaxTouchPoints: 10}
	if got := Score(touchLaptop, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/151.0.0.0"); got < 0.9 {
		t.Errorf("a touch-capable desktop must be unaffected, got %f", got)
	}
}

func TestVerifyMath(t *testing.T) {
	const base = "test-base-secret"
	const ip = "203.0.113.7"
	a, b, token := MathChallenge(base, ip)
	correct := []byte{'0' + byte((a+b)/10), '0' + byte((a+b)%10)}
	correctStr := string(correct)
	if a+b < 10 {
		correctStr = correctStr[1:]
	}
	if !VerifyMath(correctStr, token, base, ip, 900) {
		t.Errorf("correct answer should verify (a=%d b=%d ans=%s)", a, b, correctStr)
	}
	if VerifyMath("0", token, base, ip, 900) && a+b != 0 {
		t.Error("zero answer should not verify (unless a+b==0)")
	}
	if VerifyMath("not a number", token, base, ip, 900) {
		t.Error("non-numeric answer should fail")
	}
	// IP binding: a solved token must not verify from a different IP.
	if VerifyMath(correctStr, token, base, "198.51.100.9", 900) {
		t.Error("token bound to one IP should not verify from another")
	}
	// Freshness: validSecs=-1 forces the stale branch (now-issued >= 0 > -1).
	if VerifyMath(correctStr, token, base, ip, -1) {
		t.Error("token outside the freshness window should not verify")
	}
}
