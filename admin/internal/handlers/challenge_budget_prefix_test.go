package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestLimitAddr(t *testing.T) {
	for in, want := range map[string]string{
		"198.51.100.7":               "198.51.100.7",
		"2001:db8:1:2::1":            "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff::99": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":            "2001:db8:1:3::/64",
		"fe80::1%eth0":               "fe80::/64",
		"::ffff:198.51.100.7":        "::ffff:198.51.100.7",
		"not-an-address":             "not-an-address",
	} {
		if got := limitAddr(in); got != want {
			t.Errorf("limitAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// The beacon's budget counted per address, and an IPv6 client is given a
// /64 at the least: one machine sent its twenty beacons from each address of
// its prefix, without limit.  The budget counts the /64 now; the beacons it
// refuses are still counted for the address that sent them.
func TestBeaconBudgetCountsTheIPv6Prefix(t *testing.T) {
	h := passTraceHandler(t)
	const host = "example.com"
	for i := 1; i <= 20; i++ {
		ip := "2001:db8:1:2::" + strconv.FormatInt(int64(i), 16)
		if rr := passBeacon(h, ip, host, "load", ""); rr.Code != http.StatusOK {
			t.Fatalf("beacon %d from %s answered %d", i, ip, rr.Code)
		}
	}
	const next = "2001:db8:1:2:abcd::1"
	if rr := passBeacon(h, next, host, "load", ""); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("a 21st beacon from the same /64 (another address) answered %d, want 429", rr.Code)
	}
	if n, _ := h.passTrace.droppedFor(string(events.PackIP(next)), time.Now()); n != 1 {
		t.Errorf("the refused beacon is counted as %d dropped for the address that sent it, want 1", n)
	}
	if n, _ := h.passTrace.droppedFor(string(events.PackIP("2001:db8:1:2::1")), time.Now()); n != 0 {
		t.Errorf("an address of the prefix that sent nothing refused shows %d dropped", n)
	}
	// Another /64, and IPv4, have budgets of their own.
	if rr := passBeacon(h, "2001:db8:1:3::1", host, "load", ""); rr.Code != http.StatusOK {
		t.Errorf("a beacon from the next /64 answered %d", rr.Code)
	}
	if rr := passBeacon(h, "198.51.100.30", host, "load", ""); rr.Code != http.StatusOK {
		t.Errorf("an IPv4 beacon answered %d", rr.Code)
	}
}

// The answer's budget (VerifyJSON) and the question's (CaptchaNew) are the
// same kind of per-address budget, and fold the same way.
func TestVerifyBudgetCountsTheIPv6Prefix(t *testing.T) {
	h := passTraceHandler(t)
	verify := func(ip string) int {
		r := httptest.NewRequest(http.MethodPost, "https://example.com/unmask/api/verify",
			strings.NewReader(`{"ct":"x","answer":"1"}`))
		r.Host = "example.com"
		r.Header.Set("X-Real-IP", ip)
		r.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.VerifyJSON(rr, r)
		return rr.Code
	}
	for i := 1; i <= 20; i++ {
		ip := "2001:db8:9:9::" + strconv.FormatInt(int64(i), 16)
		if code := verify(ip); code == http.StatusTooManyRequests {
			t.Fatalf("answer %d from %s was refused by the budget", i, ip)
		}
	}
	if code := verify("2001:db8:9:9:1234::5"); code != http.StatusTooManyRequests {
		t.Fatalf("a 21st answer from the same /64 (another address) answered %d, want 429", code)
	}
	if code := verify("2001:db8:9:a::1"); code == http.StatusTooManyRequests {
		t.Error("an answer from the next /64 was refused by the first one's budget")
	}

	// The question: each request carries a page's token bound to its own
	// address, so the budget is what refuses the 21st.
	question := func(ip string) int {
		ct := agedCTFor(h.cfg().Secret.CaptchaSecretBase, ip, "example.com", settings.RateChallengeCaptchaOnly)
		r := httptest.NewRequest(http.MethodGet, "https://example.com/unmask/api/captcha/new?ct="+ct, nil)
		r.Host = "example.com"
		r.Header.Set("X-Real-IP", ip)
		rr := httptest.NewRecorder()
		h.CaptchaNew(rr, r)
		return rr.Code
	}
	for i := 1; i <= 20; i++ {
		ip := "2001:db8:7:7::" + strconv.FormatInt(int64(i), 16)
		if code := question(ip); code != http.StatusOK {
			t.Fatalf("question %d from %s answered %d", i, ip, code)
		}
	}
	if code := question("2001:db8:7:7:ffff::1"); code != http.StatusTooManyRequests {
		t.Fatalf("a 21st question from the same /64 (another address) answered %d, want 429", code)
	}
	if code := question("198.51.100.40"); code != http.StatusOK {
		t.Errorf("an IPv4 question answered %d", code)
	}
}
