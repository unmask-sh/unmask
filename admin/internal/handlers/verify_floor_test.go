package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/captcha"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The behavioral signal the page posts is the client's to make up, and the
// proof-of-load token was the one thing standing between a script and a
// CAPTCHA-grade cookie: fetch the page, post a plausible signal, done, in two
// requests.  Three bounds now sit on that path, none of which a person
// notices: an answer under a token issued in the same breath is refused
// (too_fast); each address gets the question budget's number of answers in
// five minutes; and the answer no longer says how the signal scored.
func TestVerifyRefusesAnAnswerInTheSameBreathAsTheServe(t *testing.T) {
	h := newTestHandler(t)
	post := func(ct string) (*httptest.ResponseRecorder, map[string]any) {
		body := `{"token":"x","ct":"` + ct + `","sig":{"hasMouseEvents":true,"clickAt":3000,"mouseTrail":[[10,10,1],[40,33,80],[70,55,160],[100,77,240],[130,99,320]],"windowSize":[1280,800]}}`
		req := httptest.NewRequest(http.MethodPost, "/unmask/api/verify", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Real-IP", "203.0.113.40")
		rr := httptest.NewRecorder()
		h.VerifyJSON(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr, out
	}
	// A token issued now: the page was served this very second.
	rr, out := post(captcha.IssueToken("test-base", time.Now(), captcha.Binding{Key: "203.0.113.40", Host: "example.com", Chain: settings.RateChallengeCaptchaOnly}))
	if rr.Code != http.StatusForbidden || fmt.Sprint(out["error"]) != "too_fast" {
		t.Fatalf("an answer in the same second as the serve: want 403 too_fast, got %d %v", rr.Code, out)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_bv" {
			t.Fatal("a _bv was issued on a refused answer")
		}
	}
	// The same signal under a token old enough passes, and the answer says
	// nothing about the score.
	rr, out = post(agedCT("test-base", "203.0.113.40"))
	if rr.Code != http.StatusOK || fmt.Sprint(out["ok"]) != "1" {
		t.Fatalf("the same signal under an older token: want 200, got %d %v", rr.Code, out)
	}
	if _, has := out["score"]; has {
		t.Errorf("the answer carries the score: %v", out)
	}
	// The math path is held to the same floor.
	ct := captcha.IssueToken("test-base", time.Now(), captcha.Binding{Key: "203.0.113.40", Host: "example.com", Chain: settings.RateChallengeCaptchaOnly})
	a, b, tok := captcha.MathChallenge("test-base", ct)
	res, mout := postMath(t, h, "203.0.113.40", map[string]any{"answer": a + b, "token": tok, "ct": ct, "iv": 3, "dt": 2000})
	if res.StatusCode != http.StatusForbidden || fmt.Sprint(mout["error"]) != "too_fast" {
		t.Fatalf("a sum answered in the same second as the serve: want 403 too_fast, got %d %v", res.StatusCode, mout)
	}
}

// A question is bound to the page it was drawn for: the right sum under
// another page's token is a wrong answer.
func TestMathQuestionIsBoundToItsPage(t *testing.T) {
	h := newTestHandler(t)
	ans, token, _ := mathAnswerFor(t, h, "203.0.113.41")
	other := agedCT(h.cfg().Secret.CaptchaSecretBase, "203.0.113.41")
	res, out := postMath(t, h, "203.0.113.41", map[string]any{"answer": ans, "token": token, "ct": other, "iv": 3, "dt": 2000})
	if res.StatusCode != http.StatusForbidden || fmt.Sprint(out["error"]) != "wrong" {
		t.Fatalf("a question answered under another page's token: want 403 wrong, got %d %v", res.StatusCode, out)
	}
	if k := bvKindFrom(t, res); k != "" {
		t.Fatalf("a _bv was issued: %q", k)
	}
}

// An address answers the question budget's number of times in five minutes;
// after that the verify says so, whatever the answer would have been.
func TestVerifyHasAPerAddressBudget(t *testing.T) {
	h := newTestHandler(t)
	limit := h.cfg().Challenge.Resolve("").DebugRateLimitPer5Min
	if limit <= 0 {
		limit = passTraceDefaultLimit
	}
	var last *httptest.ResponseRecorder
	for i := 0; i <= limit; i++ {
		body := `{"token":"x","ct":"` + agedCT("test-base", "203.0.113.42") + `","sig":{"hasMouseEvents":false,"clickAt":50,"windowSize":[0,0]}}`
		req := httptest.NewRequest(http.MethodPost, "/unmask/api/verify", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Real-IP", "203.0.113.42")
		last = httptest.NewRecorder()
		h.VerifyJSON(last, req)
		if i < limit && last.Code != http.StatusForbidden {
			t.Fatalf("answer %d: want 403 (a low score), got %d %s", i+1, last.Code, last.Body.String())
		}
	}
	if last.Code != http.StatusTooManyRequests || !strings.Contains(last.Body.String(), "rate_limit") {
		t.Fatalf("answer %d from one address: want 429 rate_limit, got %d %s", limit+1, last.Code, last.Body.String())
	}
	// Another address is untouched.
	body := `{"token":"x","ct":"` + agedCT("test-base", "203.0.113.43") + `","sig":{"hasMouseEvents":false,"clickAt":50,"windowSize":[0,0]}}`
	req := httptest.NewRequest(http.MethodPost, "/unmask/api/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "203.0.113.43")
	rr := httptest.NewRecorder()
	h.VerifyJSON(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("another address: want 403 (a low score), got %d %s", rr.Code, rr.Body.String())
	}
}

// The score the verify computed reaches the hunt on the beacon that reports
// the outcome, written by the daemon from what it computed for that page --
// not echoed by the page from an answer that no longer carries it.
func TestVerifyScoreRidesTheOutcomeBeacon(t *testing.T) {
	h := newTestHandler(t)
	bt := issueBeaconToken(h.cfg().Secret.CaptchaSecretBase)
	body := `{"token":"x","ct":"` + agedCT("test-base", "203.0.113.44") + `","bt":"` + bt + `","sig":{"hasMouseEvents":false,"clickAt":50,"windowSize":[0,0]}}`
	req := httptest.NewRequest(http.MethodPost, "/unmask/api/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "203.0.113.44")
	rr := httptest.NewRecorder()
	h.VerifyJSON(rr, req)
	if rr.Code != http.StatusForbidden || strings.Contains(rr.Body.String(), `"score":`) {
		t.Fatalf("want a 403 without a score, got %d %s", rr.Code, rr.Body.String())
	}
	// The page's own claim on the beacon is replaced by the daemon's number.
	beacon := `{"phase":"verify_ng","flags":0,"reload_count":0,"ua":"score-probe","score":0.99,"bt":"` + bt + `"}`
	breq := httptest.NewRequest(http.MethodPost, "/unmask/api/debug", strings.NewReader(beacon))
	breq.Header.Set("Content-Type", "application/json")
	breq.Header.Set("X-Real-IP", "203.0.113.44")
	brr := httptest.NewRecorder()
	h.DebugBeacon(brr, breq)
	if brr.Code != http.StatusOK {
		t.Fatalf("beacon: %d %s", brr.Code, brr.Body.String())
	}
	var payload string
	for i := 0; i < 150 && !strings.Contains(payload, `"ua":"score-probe"`); i++ {
		time.Sleep(20 * time.Millisecond)
		_ = h.DB.QueryRow(`SELECT COALESCE(payload_json, '') FROM unmask_event WHERE phase = 'verify_ng' ORDER BY id DESC LIMIT 1`).Scan(&payload)
	}
	if !strings.Contains(payload, `"score":0`) || strings.Contains(payload, `"score":0.99`) {
		t.Errorf("the beacon row must carry the daemon's score, not the page's: %s", payload)
	}
}
