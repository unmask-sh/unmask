package advisor

import (
	"context"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func newTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/advisor.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	return d
}

func insertEvent(t *testing.T, d *db.DB, ip, ja4, phase, ua, payload string) {
	t.Helper()
	if payload == "" {
		payload = "{}"
	}
	if _, err := d.Exec(`INSERT INTO unmask_event
		(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		VALUES ('','','',0,?,?,?, '',0,?,0,0,'','',?,datetime('now'))`,
		events.PackIP(ip), ua, ja4, phase, payload); err != nil {
		t.Fatal(err)
	}
}

func TestCandidatesSignals(t *testing.T) {
	d := newTestDB(t)
	opt := Options{MinServes: 5, MinScanner: 3, HerdMinIPs: 3, Limit: 50}

	// A: hammers challenges, never runs the JS -> challenge_hammering.
	for i := 0; i < 6; i++ {
		insertEvent(t, d, "203.0.113.10", "t13d_bot", "serve", "curl/8", "")
	}
	// B: as many serves but it PASSES -> a real browser, no candidate.
	for i := 0; i < 6; i++ {
		insertEvent(t, d, "203.0.113.20", "t13d_ok", "serve", "Mozilla/5.0", "")
	}
	insertEvent(t, d, "203.0.113.20", "t13d_ok", "bv_pow_only", "Mozilla/5.0", "")
	// C: scanner paths -> scanner_paths (below the serve threshold on purpose).
	for _, p := range []string{"/.env", "/wp-config.php.save", "/.git/config"} {
		insertEvent(t, d, "203.0.113.30", "t13d_scan", "serve", "Mozilla/5.0", `{"path":"`+p+`"}`)
	}
	// D: private address must never surface, however loud.
	for i := 0; i < 10; i++ {
		insertEvent(t, d, "10.0.0.5", "t13d_priv", "serve", "curl/8", "")
	}
	// E: herd -- one JA4 across 4 addresses, serves only.
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
		for i := 0; i < 2; i++ {
			insertEvent(t, d, ip, "q13d_herd", "serve", "Mozilla/5.0", "")
		}
	}

	cands, err := Candidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	byTarget := map[string]Candidate{}
	for _, c := range cands {
		byTarget[c.Target] = c
	}

	a, ok := byTarget["203.0.113.10"]
	if !ok || !hasSignal(a, "challenge_hammering") {
		t.Errorf("hammering IP not flagged: %+v", a)
	}
	if a.Scope != "ip_only" || a.Passes != 0 || a.Serves != 6 {
		t.Errorf("hammering evidence off: %+v", a)
	}
	if _, ok := byTarget["203.0.113.20"]; ok {
		t.Error("a passing visitor must not be a candidate")
	}
	cSc, ok := byTarget["203.0.113.30"]
	if !ok || !hasSignal(cSc, "scanner_paths") {
		t.Errorf("scanner IP not flagged: %+v", cSc)
	}
	if len(cSc.SamplePaths) == 0 || !strings.HasPrefix(cSc.SamplePaths[0], "/") {
		t.Errorf("sample paths missing: %+v", cSc.SamplePaths)
	}
	if _, ok := byTarget["10.0.0.5"]; ok {
		t.Error("private IP must never be a candidate")
	}
	herd, ok := byTarget["q13d_herd"]
	if !ok || herd.Type != "ja4" || !hasSignal(herd, "ja4_herd") {
		t.Errorf("ja4 herd not flagged: %+v", herd)
	}
	if herd.DistinctIPs != 4 || herd.Scope != "ja4_only" {
		t.Errorf("herd evidence off: %+v", herd)
	}
}

// The herd rule must NOT flag a shared fingerprint that real visitors pass
// with (a popular browser JA4 fans out over many addresses by nature).
func TestCandidatesHerdPassingFingerprintExempt(t *testing.T) {
	d := newTestDB(t)
	opt := Options{MinServes: 5, HerdMinIPs: 3, Limit: 50}
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		insertEvent(t, d, ip, "t13d_browser", "serve", "Mozilla/5.0", "")
		insertEvent(t, d, ip, "t13d_browser", "serve", "Mozilla/5.0", "")
		if i >= 0 { // every address completes the challenge
			insertEvent(t, d, ip, "t13d_browser", "bv_pow_only", "Mozilla/5.0", "")
		}
	}
	cands, err := Candidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if c.Target == "t13d_browser" {
			t.Fatalf("passing browser fingerprint flagged as herd: %+v", c)
		}
	}
}

func TestCandidatesExclusions(t *testing.T) {
	d := newTestDB(t)
	opt := Options{MinServes: 5, Limit: 50}
	for i := 0; i < 6; i++ {
		insertEvent(t, d, "203.0.113.40", "t13d_x", "serve", "curl/8", "")
		insertEvent(t, d, "203.0.113.50", "t13d_y", "serve", "curl/8", "")
		insertEvent(t, d, "203.0.113.60", "t13d_z", "serve", "curl/8", "")
	}
	excl := Exclusions{
		BannedIPs:   map[string]bool{"203.0.113.40": true},
		DismissedIP: map[string]bool{"203.0.113.50": true},
		ExcludeIPs:  map[string]bool{"203.0.113.60": true},
	}
	cands, err := Candidates(context.Background(), d, nil, excl, opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 0 {
		t.Fatalf("banned/dismissed/excluded targets surfaced: %+v", cands)
	}
}

func hasSignal(c Candidate, id string) bool {
	for _, s := range c.Signals {
		if s.ID == id {
			return true
		}
	}
	return false
}
