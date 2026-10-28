package handlers

import (
	"crypto/sha256"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

// TestBVJIssueRecordsAPassTheBeaconMissed: the /bvj issue writes the pass
// when the page's beacon does not arrive within the grace, and nothing when
// it does, whichever of the two is first.  A pass too old to be this page's
// earns the credential as before and no record.
func TestBVJIssueRecordsAPassTheBeaconMissed(t *testing.T) {
	saved := passTraceGrace
	passTraceGrace = 300 * time.Millisecond
	t.Cleanup(func() { passTraceGrace = saved })
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
	settle := func() { time.Sleep(3 * passTraceGrace) }

	// The beacon never comes: the issue's record is written after the grace.
	bv1 := powPass(t, secret, ip, host)
	if rr := post(bv1); rr.Code != http.StatusOK {
		t.Fatalf("bvj answered %d %s", rr.Code, rr.Body.String())
	}
	waitFor(t, "the bvj-side pass row", 5*time.Second, func() bool { return bvjRows() == 1 })
	// Posting the same pass again adds nothing.
	post(bv1)
	settle()
	if n := allRows(); n != 1 {
		t.Errorf("%d pass rows after a repeated bvj post, want 1", n)
	}

	// The beacon arrives first: the issue writes nothing.
	bv2 := powPass(t, secret, ip, host)
	if rr := passBeacon(h, ip, host, "bv_pow_only", bv2); rr.Code != http.StatusOK {
		t.Fatalf("pass beacon answered %d", rr.Code)
	}
	waitFor(t, "the beacon's row", 5*time.Second, func() bool { return allRows() == 2 })
	post(bv2)
	settle()
	if n := bvjRows(); n != 1 {
		t.Errorf("%d bvj-side rows after a pass the beacon reported, want still 1", n)
	}

	// The issue arrives first and the beacon within the grace: the beacon is
	// kept, the issue's record is not written.  This step runs on a grace of
	// two seconds: the beacon has to land inside it, and on a loaded CI
	// runner 300 ms has not always covered the gap between two requests.
	// settle() then waits out the issue's timer at the same length.
	passTraceGrace = 2 * time.Second
	bv3 := powPass(t, secret, ip, host)
	post(bv3)
	if rr := passBeacon(h, ip, host, "bv_pow_only", bv3); rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "dup") {
		t.Fatalf("pass beacon inside the grace answered %d %s, want kept", rr.Code, rr.Body.String())
	}
	waitFor(t, "the third solve's row", 5*time.Second, func() bool { return allRows() == 3 })
	settle()
	if n := bvjRows(); n != 1 {
		t.Errorf("%d bvj-side rows, want still 1", n)
	}
	if n := allRows(); n != 3 {
		t.Errorf("%d pass rows in all, want 3 (one per solve)", n)
	}
	passTraceGrace = 300 * time.Millisecond

	// A pass from twenty minutes ago is valid for the credential, and no
	// solve of this page: no record.
	old := powPassAt(t, secret, ip, host, time.Now().Add(-20*time.Minute).Unix())
	if rr := post(old); rr.Code != http.StatusOK {
		t.Errorf("bvj for an older pass answered %d %s, want 200", rr.Code, rr.Body.String())
	}
	settle()
	if n := bvjRows(); n != 1 {
		t.Errorf("%d bvj-side rows after an older pass, want still 1", n)
	}
}
