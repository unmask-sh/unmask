package captcha

import "testing"

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
	if got := Score(s); got < 0.9 {
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
	if got := Score(s); got >= 0.5 {
		t.Errorf("bot-like score should be below threshold, got %f", got)
	}
}

// Perfectly straight trail = suspected bot (-0.3).
func TestScore_StraightLine(t *testing.T) {
	trail := make([][]float64, 0, 12)
	for i := 0; i < 12; i++ {
		trail = append(trail, []float64{float64(i * 10), float64(i * 10), float64(i * 30)})
	}
	s := &Signal{
		HasMouseEvents: true,
		ClickAt:        3000,
		MouseTrail:     trail,
		WindowSize:     []float64{1200, 800},
	}
	if got := Score(s); got > 0.71 || got < 0.69 {
		t.Errorf("straight line should give ~0.7, got %f", got)
	}
}

func TestVerifyMath(t *testing.T) {
	const base = "test-base-secret"
	a, b, token := MathChallenge(base)
	correct := []byte{'0' + byte((a+b)/10), '0' + byte((a+b)%10)}
	correctStr := string(correct)
	if a+b < 10 {
		correctStr = correctStr[1:]
	}
	if !VerifyMath(correctStr, token, base) {
		t.Errorf("correct answer should verify (a=%d b=%d ans=%s)", a, b, correctStr)
	}
	if VerifyMath("0", token, base) && a+b != 0 {
		t.Error("zero answer should not verify (unless a+b==0)")
	}
	if VerifyMath("not a number", token, base) {
		t.Error("non-numeric answer should fail")
	}
}
