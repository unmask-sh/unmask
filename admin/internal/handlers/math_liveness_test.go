package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/captcha"
)

// mathAnswerFor mints a real question for this IP and returns the pieces the
// client would post back.
func mathAnswerFor(t *testing.T, h *Handler, ip string) (answer int, token, ct string) {
	t.Helper()
	a, b, tok := captcha.MathChallenge(h.cfg().Secret.CaptchaSecretBase, ip)
	return a + b, tok, captcha.IssueToken(h.cfg().Secret.CaptchaSecretBase, ip)
}

func postMath(t *testing.T, h *Handler, ip string, body map[string]any) (*http.Response, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/unmask/api/verify", strings.NewReader(string(raw)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Real-IP", ip)
	r.RemoteAddr = ip + ":40000"
	w := httptest.NewRecorder()
	h.VerifyJSON(w, r)
	res := w.Result()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

func bvKindFrom(t *testing.T, res *http.Response) string {
	t.Helper()
	for _, c := range res.Cookies() {
		if c.Name == "_bv" {
			// value is "<issued>.<sig>.<kind>"; the kind is the last segment.
			parts := strings.Split(c.Value, ".")
			return parts[len(parts)-1]
		}
	}
	return ""
}

// TestMathAnswerWithoutInputEventsIsDowngraded: a correct sum that arrived with
// no input events was typed by nobody.  It still passes -- dead-ending a
// visitor over a heuristic is not on the table -- but at proof-of-work grade,
// so it no longer satisfies the CAPTCHA-grade gates (protected paths, geo/ASN
// rules) the fallback was being used to walk past.
func TestMathAnswerWithoutInputEventsIsDowngraded(t *testing.T) {
	h := newTestHandler(t)
	const ip = "203.0.113.9"

	ans, token, ct := mathAnswerFor(t, h, ip)
	res, out := postMath(t, h, ip, map[string]any{
		"answer": ans, "token": token, "ct": ct, "iv": 0, "dt": 120,
	})
	if fmt.Sprint(out["ok"]) != "1" {
		t.Fatalf("a correct answer must still pass, got %v", out)
	}
	if fmt.Sprint(out["downgraded"]) != "1" {
		t.Errorf("the response must say the pass was downgraded, got %v", out)
	}
	if k := bvKindFrom(t, res); k != "pow" {
		t.Errorf("cookie kind = %q, want pow (CAPTCHA grade must not be earned without evidence)", k)
	}
}

// A typed answer keeps the full grade, and so does a client too old to report
// evidence at all -- an upgrade must not strand anyone mid-answer.
func TestMathAnswerWithEvidenceKeepsCaptchaGrade(t *testing.T) {
	h := newTestHandler(t)

	const typedIP = "203.0.113.10"
	ans, token, ct := mathAnswerFor(t, h, typedIP)
	res, out := postMath(t, h, typedIP, map[string]any{
		"answer": ans, "token": token, "ct": ct, "iv": 2, "dt": 3400,
	})
	if fmt.Sprint(out["ok"]) != "1" || out["downgraded"] != nil {
		t.Fatalf("typed answer must pass undowngraded, got %v", out)
	}
	if k := bvKindFrom(t, res); k != "captcha" {
		t.Errorf("typed answer cookie kind = %q, want captcha", k)
	}

	const legacyIP = "203.0.113.11"
	ans2, token2, ct2 := mathAnswerFor(t, h, legacyIP)
	res2, out2 := postMath(t, h, legacyIP, map[string]any{
		"answer": ans2, "token": token2, "ct": ct2, // no iv/dt: a page cached from before this shipped
	})
	if fmt.Sprint(out2["ok"]) != "1" || out2["downgraded"] != nil {
		t.Fatalf("a client that reports no evidence field must keep the old behavior, got %v", out2)
	}
	if k := bvKindFrom(t, res2); k != "captcha" {
		t.Errorf("legacy client cookie kind = %q, want captcha", k)
	}
}

// A wrong answer is still wrong, evidence or not.
func TestMathWrongAnswerStillFails(t *testing.T) {
	h := newTestHandler(t)
	const ip = "203.0.113.12"
	ans, token, ct := mathAnswerFor(t, h, ip)
	_, out := postMath(t, h, ip, map[string]any{
		"answer": ans + 1, "token": token, "ct": ct, "iv": 3, "dt": 5000,
	})
	if fmt.Sprint(out["ok"]) == "1" {
		t.Fatalf("a wrong answer must not pass, got %v", out)
	}
}
