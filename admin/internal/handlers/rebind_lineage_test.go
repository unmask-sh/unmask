package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// lineageOf reads the lineage out of a _bvj value ("<issued>.<ja4 set>.<ua>.
// <lineage>...").
func lineageOf(t *testing.T, bvj string) string {
	t.Helper()
	parts := strings.Split(bvj, ".")
	if len(parts) < 4 {
		t.Fatalf("not a _bvj: %q", bvj)
	}
	return parts[3]
}

// TestOneSolveHasOneLineage: asked for a _bvj again and again for one solve,
// without the _bvj being sent back, /api/bvj hands out the same lineage --
// one rebind budget -- and the addresses that solve can be carried to stay
// within it.
//
// The lineage used to be drawn at random at each mint, so every such POST
// came back with a budget of its own (16 re-binds, 10 an hour): five POSTs,
// and one proof-of-work held a pass on fifty addresses within the hour.  The
// cap counted the requests, not the solve.
func TestOneSolveHasOneLineage(t *testing.T) {
	h := newRebindTestHandler(t) // rebind on, 16 per lineage, 10 an hour, no ASN database
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Challenge.Default.PowDifficulty = bvjTestDifficulty })
	const (
		host = "example.com"
		ua   = "Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0"
		ja4  = "t13d1717h2_5b57614c22b0_3cbfd9057e0d"
		home = "203.0.113.10"
	)
	sec := h.cfg().Secret.BVSecret
	post := func(bv, agent string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "https://"+host+"/unmask/api/bvj", nil)
		req.Header.Set("X-Real-IP", home)
		req.Header.Set("User-Agent", agent)
		req.Header.Set("X-Client-JA4", ja4)
		req.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
		rr := httptest.NewRecorder()
		h.IssueBVJ(rr, req)
		v := setCookie(rr, "_bvj")
		if v == "" {
			t.Fatalf("no _bvj (%d %s)", rr.Code, rr.Body.String())
		}
		return v
	}

	bv := powPass(t, sec, home, host) // one proof-of-work, solved at home
	credentials := map[string]bool{}
	lineages := map[string]bool{}
	for i := 0; i < 5; i++ {
		// A User-Agent of its own each time, as a solver handing the
		// credentials out to clients of several kinds would send.
		v := post(bv, fmt.Sprintf("%s client/%d", ua, i))
		credentials[v] = true
		lineages[lineageOf(t, v)] = true
	}
	if len(lineages) != 1 {
		t.Fatalf("5 POSTs of one solve were handed %d lineages, want 1", len(lineages))
	}

	// Every credential spent from addresses that never solved anything: what
	// passes is what one lineage allows in the hour, whichever credential
	// asks.
	rebound, n := 0, 0
	for i := 0; i < 5; i++ {
		agent := fmt.Sprintf("%s client/%d", ua, i)
		bvj := post(bv, agent)
		for k := 0; k < 10; k++ {
			n++
			ip := fmt.Sprintf("198.51.%d.%d", 100+n/200, 1+n%200)
			req := httptest.NewRequest(http.MethodGet, "https://"+host+"/unmask/challenge/", nil)
			req.Header.Set("X-Real-IP", ip)
			req.Header.Set("User-Agent", agent)
			req.Header.Set("X-Client-JA4", ja4)
			req.AddCookie(&http.Cookie{Name: "_bvj", Value: bvj})
			rr := httptest.NewRecorder()
			h.ServeChallenge(rr, req)
			if nb := setCookie(rr, "_bv"); nb != "" && cookies.Verify(nb, sec, ip, host, 604800, 1209600, bvjTestDifficulty) {
				rebound++
			}
		}
	}
	if perHour := h.cfg().Rebind.MaxRebindsPerHourResolved(); rebound != perHour {
		t.Errorf("one solve was carried to %d of %d other addresses within the hour; one lineage allows %d", rebound, n, perHour)
	}

	// Another solve is another lineage: the budget is the solve's, not the
	// address's or the host's.
	other := powPassAt(t, sec, home, host, timeOfPass(t, bv)-60)
	if l := lineageOf(t, post(other, ua)); lineages[l] {
		t.Errorf("a second solve was handed the first one's lineage %q", l)
	}
}

// timeOfPass reads the issue time off a pass ("<issued>....").
func timeOfPass(t *testing.T, bv string) int64 {
	t.Helper()
	var at int64
	if _, err := fmt.Sscanf(strings.SplitN(bv, ".", 2)[0], "%d", &at); err != nil {
		t.Fatalf("no issue time in %q: %v", bv, err)
	}
	return at
}

// TestVerifyAndBVJNameOneLineage: the credential /api/verify mints with a
// pass and the one /api/bvj mints for the same pass name the same lineage.
// A CAPTCHA's solver that dropped the first and asked /api/bvj for another
// used to hold two budgets, and as many more as it asked for.
func TestVerifyAndBVJNameOneLineage(t *testing.T) {
	h := newTestHandler(t)
	const ip = "203.0.113.12"
	ans, token, ct := mathAnswerFor(t, h, ip)
	res, out := postMath(t, h, ip, map[string]any{"answer": ans, "token": token, "ct": ct, "iv": 2, "dt": 3400})
	if fmt.Sprint(out["ok"]) != "1" {
		t.Fatalf("the answer did not pass: %v", out)
	}
	var bv, minted string
	for _, c := range res.Cookies() {
		switch c.Name {
		case "_bv":
			bv = c.Value
		case "_bvj":
			minted = c.Value
		}
	}
	if bv == "" || minted == "" {
		t.Fatalf("the answer set _bv %q and _bvj %q; want both", bv, minted)
	}

	req := httptest.NewRequest(http.MethodPost, "/unmask/api/bvj", nil)
	req.Header.Set("X-Real-IP", ip)
	req.RemoteAddr = ip + ":40000"
	req.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
	rr := httptest.NewRecorder()
	h.IssueBVJ(rr, req)
	again := setCookie(rr, "_bvj")
	if again == "" {
		t.Fatalf("/api/bvj minted nothing for the pass (%d %s)", rr.Code, rr.Body.String())
	}
	if a, b := lineageOf(t, minted), lineageOf(t, again); a != b {
		t.Errorf("/api/verify named lineage %q and /api/bvj %q for one pass", a, b)
	}
}
