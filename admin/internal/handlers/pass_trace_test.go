package handlers

import (
	"crypto/sha256"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// passTraceHandler is a handler with the secrets and the difficulty the pass
// tests solve at, the beacon limit at its default, and the flusher running
// for the rows the /bvj issue writes.
func passTraceHandler(t *testing.T) *Handler {
	t.Helper()
	h := installedHandler(t)
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	s.Secret.CaptchaSecretBase = "test-base"
	s.Challenge.Default.PowDifficulty = bvjTestDifficulty
	s.Challenge.Default.DebugRateLimitPer5Min = 20
	h.SetSettings(s)
	events.StartFlusher(h.DB, 10, 50)
	t.Cleanup(events.StopFlusher)
	return h
}

func passBeacon(h *Handler, ip, host, phase, bv string) *httptest.ResponseRecorder {
	bt := issueBeaconToken(h.cfg().Secret.CaptchaSecretBase)
	r := httptest.NewRequest(http.MethodPost, "https://"+host+"/unmask/api/debug",
		strings.NewReader(`{"phase":"`+phase+`","flags":0,"reload_count":0,"ua":"x","trace":"forged","pass_verified":1,"bt":"`+bt+`"}`))
	r.Host = host
	r.Header.Set("X-Real-IP", ip)
	r.Header.Set("Content-Type", "application/json")
	if bv != "" {
		r.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
	}
	rr := httptest.NewRecorder()
	h.DebugBeacon(rr, r)
	return rr
}

func countPassRows(t *testing.T, h *Handler, phase, payloadLike string) int {
	t.Helper()
	var n int
	q := `SELECT COUNT(*) FROM unmask_event WHERE phase = ?`
	args := []any{phase}
	if payloadLike != "" {
		q += ` AND payload_json LIKE ?`
		args = append(args, payloadLike)
	}
	if err := h.DB.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestPassBeaconOutsideTheLimit: the beacon limit counts beacons, and a pass
// beacon the request's own fresh cookie vouches for is outside it and kept
// once.  The page's word for the daemon's marks is dropped from the payload,
// and the beacons the limit refused are counted for the address.
func TestPassBeaconOutsideTheLimit(t *testing.T) {
	h := passTraceHandler(t)
	const ip, host = "198.51.100.21", "example.com"
	for i := 0; i < 20; i++ {
		if rr := passBeacon(h, ip, host, "load", ""); rr.Code != http.StatusOK {
			t.Fatalf("load beacon %d answered %d", i, rr.Code)
		}
	}
	for i := 0; i < 3; i++ {
		if rr := passBeacon(h, ip, host, "load", ""); rr.Code != http.StatusTooManyRequests {
			t.Fatalf("load beacon past the limit answered %d, want 429", rr.Code)
		}
	}
	// An unvouched pass beacon is within the limit like any other.
	if rr := passBeacon(h, ip, host, "bv_pow_only", ""); rr.Code != http.StatusTooManyRequests {
		t.Errorf("pass beacon without a cookie answered %d, want 429", rr.Code)
	}
	// Vouched: kept, outside the limit, once.
	bv := powPass(t, h.cfg().Secret.BVSecret, ip, host)
	if rr := passBeacon(h, ip, host, "bv_pow_only", bv); rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "dup") {
		t.Fatalf("vouched pass beacon answered %d %s, want 200 and kept", rr.Code, rr.Body.String())
	}
	if rr := passBeacon(h, ip, host, "bv_pow_only", bv); rr.Code != http.StatusTooManyRequests {
		// The repeat is within the limit (exhausted here), so it is refused
		// before the duplicate check: a replay cannot spend what a pass may.
		t.Errorf("repeated pass beacon answered %d, want 429 with the limit exhausted", rr.Code)
	}
	if n := countPassRows(t, h, "bv_pow_only", ""); n != 1 {
		t.Errorf("%d bv_pow_only rows, want 1", n)
	}
	if n := countPassRows(t, h, "bv_pow_only", `%"pass_verified":1%`); n != 1 {
		t.Errorf("%d rows marked pass_verified, want 1", n)
	}
	if n := countPassRows(t, h, "bv_pow_only", `%forged%`); n != 0 {
		t.Errorf("the page's own trace mark was kept")
	}
	if n := countPassRows(t, h, "load", `%pass_verified%`); n != 0 {
		t.Errorf("a load beacon was marked pass_verified")
	}
	dropped, last := h.passTrace.droppedFor(string(events.PackIP(ip)), time.Now())
	if dropped != 5 || last.IsZero() {
		t.Errorf("dropped = %d (last %v), want 5", dropped, last)
	}
	if n, _ := h.passTrace.droppedFor(string(events.PackIP("198.51.100.22")), time.Now()); n != 0 {
		t.Errorf("another address shows %d dropped", n)
	}
	// Within the limit, the repeat is answered as a duplicate and not written.
	h2 := passTraceHandler(t)
	bv2 := powPass(t, h2.cfg().Secret.BVSecret, ip, host)
	passBeacon(h2, ip, host, "bv_pow_only", bv2)
	if rr := passBeacon(h2, ip, host, "bv_pow_only", bv2); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"dup":1`) {
		t.Errorf("repeated pass beacon answered %d %s, want 200 dup", rr.Code, rr.Body.String())
	}
	if n := countPassRows(t, h2, "bv_pow_only", ""); n != 1 {
		t.Errorf("%d bv_pow_only rows after the repeat, want 1", n)
	}
}

// powPassAt is powPass for a pass issued at a given time.
func powPassAt(t *testing.T, secret, key, host string, issued int64) string {
	t.Helper()
	seed := cookies.PowSeed(secret, key, host, issued)
	for nonce := int64(0); nonce < 1<<24; nonce++ {
		sum := sha256.Sum256([]byte(seed + ":" + strconv.FormatInt(nonce, 10)))
		n := 0
		for _, b := range sum {
			if b != 0 {
				n += bits.LeadingZeros8(b)
				break
			}
			n += 8
		}
		if n >= bvjTestDifficulty {
			return strconv.FormatInt(issued, 10) + ".pow2." + strconv.FormatInt(nonce, 36) + ".0"
		}
	}
	t.Fatal("no nonce clears the difficulty")
	return ""
}

// graceTrigger stands in for the /bvj issue's grace timer (passTraceAfter):
// it keeps the records the issue schedules and runs them when the test says
// the grace is over.  Whether a beacon lands inside the grace is then the
// test's choice, not a race against the clock that a loaded runner loses.
type graceTrigger struct {
	mu      sync.Mutex
	pending []func()
}

func (g *graceTrigger) after(_ time.Duration, f func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pending = append(g.pending, f)
}

// fire ends the grace of every scheduled record and says how many there were.
func (g *graceTrigger) fire() int {
	g.mu.Lock()
	fs := g.pending
	g.pending = nil
	g.mu.Unlock()
	for _, f := range fs {
		f()
	}
	return len(fs)
}

// TestBVJIssueRecordsAPassTheBeaconMissed: the /bvj issue writes the pass
// when the page's beacon does not arrive within the grace, and nothing when
// it does, whichever of the two is first.  A pass too old to be this page's
// earns the credential as before and no record.  The grace ends when the
// test ends it (graceTrigger), so the order of beacon and grace is exact.
func TestBVJIssueRecordsAPassTheBeaconMissed(t *testing.T) {
	grace := &graceTrigger{}
	saved := passTraceAfter
	passTraceAfter = grace.after
	t.Cleanup(func() { passTraceAfter = saved })
	h := passTraceHandler(t)
	const ip, host = "198.51.100.31", "example.com"
	post := func(bv string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://"+host+"/unmask/api/bvj", nil)
		r.Host = host
		r.Header.Set("X-Real-IP", ip)
		r.Header.Set("User-Agent", "Mozilla/5.0 test")
		r.Header.Set("X-Client-JA4", "t13d1516h2_8daaf6152771_d8a2da3f94cd")
		r.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
		rr := httptest.NewRecorder()
		h.IssueBVJ(rr, r)
		return rr
	}
	secret := h.cfg().Secret.BVSecret
	bvjRows := func() int { return countPassRows(t, h, "bv_pow_only", `%"trace":"bvj"%`) }
	allRows := func() int { return countPassRows(t, h, "bv_pow_only", "") }
	// settle gives a write that should not happen the time to show up: a few
	// of the flusher's intervals.  It can only make a check stricter.
	settle := func() { time.Sleep(250 * time.Millisecond) }
	// Three solves, each its own pass: a proof-of-work cookie is determined by
	// its issue second, so two minted in the same second are one cookie, and
	// the second would read as the first seen again.
	now := time.Now().Unix()
	bv1 := powPassAt(t, secret, ip, host, now)
	bv2 := powPassAt(t, secret, ip, host, now-1)
	bv3 := powPassAt(t, secret, ip, host, now-2)

	// The beacon never comes: the grace runs out and the issue writes the pass.
	if rr := post(bv1); rr.Code != http.StatusOK {
		t.Fatalf("bvj answered %d %s", rr.Code, rr.Body.String())
	}
	if n := grace.fire(); n != 1 {
		t.Fatalf("the issue scheduled %d records, want 1", n)
	}
	waitFor(t, "the bvj-side pass row", 5*time.Second, func() bool { return bvjRows() == 1 })
	// The beacon arriving after that is the same pass again.
	if rr := passBeacon(h, ip, host, "bv_pow_only", bv1); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"dup":1`) {
		t.Errorf("a beacon after the issue's record answered %d %s, want dup", rr.Code, rr.Body.String())
	}
	// Posting the same pass again schedules nothing.
	post(bv1)
	if n := grace.fire(); n != 0 {
		t.Errorf("a repeated bvj post scheduled %d records, want none", n)
	}
	settle()
	if n := allRows(); n != 1 {
		t.Errorf("%d pass rows after a repeated bvj post and a late beacon, want 1", n)
	}

	// The beacon arrives first: the issue schedules nothing.
	if rr := passBeacon(h, ip, host, "bv_pow_only", bv2); rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "dup") {
		t.Fatalf("pass beacon answered %d %s, want kept", rr.Code, rr.Body.String())
	}
	waitFor(t, "the beacon's row", 5*time.Second, func() bool { return allRows() == 2 })
	post(bv2)
	if n := grace.fire(); n != 0 {
		t.Errorf("the issue scheduled %d records for a pass the beacon reported, want none", n)
	}
	settle()
	if n := bvjRows(); n != 1 {
		t.Errorf("%d bvj-side rows after a pass the beacon reported, want still 1", n)
	}

	// The issue arrives first and the beacon inside the grace: the beacon is
	// kept, and when the grace ends the issue's record is not written.
	post(bv3)
	if rr := passBeacon(h, ip, host, "bv_pow_only", bv3); rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "dup") {
		t.Fatalf("pass beacon inside the grace answered %d %s, want kept", rr.Code, rr.Body.String())
	}
	waitFor(t, "the third solve's row", 5*time.Second, func() bool { return allRows() == 3 })
	if n := grace.fire(); n != 1 {
		t.Fatalf("the issue scheduled %d records, want 1 (overtaken by the beacon)", n)
	}
	settle()
	if n := bvjRows(); n != 1 {
		t.Errorf("%d bvj-side rows, want still 1", n)
	}
	if n := allRows(); n != 3 {
		t.Errorf("%d pass rows in all, want 3 (one per solve)", n)
	}

	// A pass from twenty minutes ago is valid for the credential, and no
	// solve of this page: nothing scheduled, no record.
	old := powPassAt(t, secret, ip, host, time.Now().Add(-20*time.Minute).Unix())
	if rr := post(old); rr.Code != http.StatusOK {
		t.Errorf("bvj for an older pass answered %d %s, want 200", rr.Code, rr.Body.String())
	}
	if n := grace.fire(); n != 0 {
		t.Errorf("the issue scheduled %d records for an older pass, want none", n)
	}
	settle()
	if n := bvjRows(); n != 1 {
		t.Errorf("%d bvj-side rows after an older pass, want still 1", n)
	}
}
