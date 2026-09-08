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

// insertEvents writes n identical rows in one transaction: the cost floor for
// a contained client is thousands of serves, which row-by-row autocommit
// would make the slowest thing in the package.
func insertEvents(t *testing.T, d *db.DB, ip, ja4, phase, ua, payload string, n int) {
	t.Helper()
	if payload == "" {
		payload = "{}"
	}
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := tx.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,?,?, '',0,?,0,0,'','',?,datetime('now'))`,
			events.PackIP(ip), ua, ja4, phase, payload); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
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

// A group whose every row has NULL user_agent / ja4 / payload_json (a
// forward-auth check writes none) must not break the extraction: MAX over an
// all-NULL group is NULL, and the first cut scanned that into a string.
func TestCandidatesTolerateNullColumns(t *testing.T) {
	d := newTestDB(t)
	for i := 0; i < 6; i++ {
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,NULL,NULL,'',0,'serve',0,0,'','',NULL,datetime('now'))`,
			events.PackIP("203.0.113.90")); err != nil {
			t.Fatal(err)
		}
	}
	cands, err := Candidates(context.Background(), d, nil, Exclusions{}, Options{MinServes: 5, Limit: 50})
	if err != nil {
		t.Fatalf("NULL columns broke the extraction: %v", err)
	}
	var found bool
	for _, c := range cands {
		if c.Target == "203.0.113.90" {
			found = true
			if c.UA != "" || c.JA4 != "" {
				t.Errorf("NULL columns should read as empty, got ua=%q ja4=%q", c.UA, c.JA4)
			}
		}
	}
	if !found {
		t.Fatal("the NULL-column hammering address was not extracted")
	}
}

// Passes are pass cookies, not JS-side phases: one challenge flow writes
// load, pow_pass and captcha rows on its way, and a client that solves the
// proof-of-work but never clears the CAPTCHA is contained, not passing.
func TestCandidatesPassSemantics(t *testing.T) {
	d := newTestDB(t)
	opt := Options{MinServes: 5, Limit: 50}
	// Solves PoW, stopped at the CAPTCHA -- six full attempts, three of them
	// on scanner paths (the informational captcha_held alone does not make a
	// candidate; the score floor is 3).
	scan := []string{"/.env", "/wp-config.php.save", "/.git/config"}
	for i := 0; i < 6; i++ {
		payload := ""
		if i < len(scan) {
			payload = `{"path":"` + scan[i] + `"}`
		}
		insertEvent(t, d, "203.0.113.70", "t13d_held", "serve", "Mozilla/5.0", payload)
		for _, ph := range []string{"load", "pow_pass", "captcha"} {
			insertEvent(t, d, "203.0.113.70", "t13d_held", ph, "Mozilla/5.0", "")
		}
	}
	// Completes the challenge -- a real pass each time.
	for i := 0; i < 6; i++ {
		for _, ph := range []string{"serve", "load", "pow_pass", "captcha", "bv_pow_then_captcha"} {
			insertEvent(t, d, "203.0.113.71", "t13d_through", ph, "Mozilla/5.0", "")
		}
	}
	cands, err := Candidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Candidate{}
	for _, c := range cands {
		by[c.Target] = c
	}
	held, ok := by["203.0.113.70"]
	if !ok {
		t.Fatalf("the CAPTCHA-held client should be a candidate (6 serves): %+v", cands)
	}
	if !held.Contained || held.Passes != 0 || held.PowPassed != 6 || held.Loads != 6 || held.CaptchaShown != 6 {
		t.Errorf("stage counts wrong for the held client: %+v", held)
	}
	if hasSignal(held, "challenge_hammering") {
		t.Error("a client that ran the JS must not be called hammering")
	}
	if !hasSignal(held, "captcha_held") {
		t.Error("expected the captcha_held signal")
	}
	if !held.HeldAtCaptcha() {
		t.Error("HeldAtCaptcha must be true for the held client")
	}
	if _, ok := by["203.0.113.71"]; ok {
		t.Error("a client that completes the challenge (no other signal) must not be a candidate")
	}
	// The pool carries the same stage counts; the completing client shows
	// passes == serves there, never more.
	orig := LookupPTR
	LookupPTR = func(ctx context.Context, ip string) []string { return nil }
	t.Cleanup(func() { LookupPTR = orig })
	pool, err := BuildPool(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	var through *PoolIP
	for i := range pool.IPs {
		if pool.IPs[i].IP == "203.0.113.71" {
			through = &pool.IPs[i]
		}
	}
	if through == nil {
		t.Fatalf("the completing client is missing from the pool: %+v", pool.IPs)
	}
	if through.Serves != 6 || through.JSLoaded != 6 || through.PowPassed != 6 || through.CaptchaShown != 6 || through.Passes != 6 {
		t.Errorf("pool stage counts wrong: %+v", *through)
	}
}

// Volume is a signal of its own, and where it starts depends on whether the
// challenge is already handling the client.  A passing client is load at a
// few hundred serves, and the volume lifts its lone signal to attention; a
// contained one -- answered for the price of a small page -- is load only at
// thousands (the operator's calibration, 2026-09-09: short of that there is
// nothing to notice), and until then stays at the candidate floor whatever
// else it carries.  Thirty serves is not volume by any measure.
func TestCandidatesHighVolume(t *testing.T) {
	d := newTestDB(t)
	opt := Options{MinServes: 5, Limit: 50}
	insertEvents(t, d, "203.0.113.80", "t13d_heavy", "serve", "curl/8", "", VolumeServes)
	insertEvents(t, d, "203.0.113.82", "t13d_flood", "serve", "curl/8", "", ContainedVolumeServes)
	insertEvents(t, d, "203.0.113.81", "t13d_light", "serve", "curl/8", "", 30)
	// Passing (one pass), scanner paths, a few hundred serves.
	insertEvents(t, d, "203.0.113.83", "t13d_through", "serve", "Mozilla/5.0", `{"path":"/.env"}`, VolumeServes)
	insertEvent(t, d, "203.0.113.83", "t13d_through", "bv_pow_then_captcha", "Mozilla/5.0", "")
	cands, err := Candidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Candidate{}
	for _, c := range cands {
		by[c.Target] = c
	}
	heavy, flood, light, through := by["203.0.113.80"], by["203.0.113.82"], by["203.0.113.81"], by["203.0.113.83"]
	if hasSignal(heavy, "high_volume") || heavy.Score != candidateFloor || heavy.Attention() {
		t.Errorf("a contained hammerer at %d serves is not volume: %+v", VolumeServes, heavy)
	}
	if !hasSignal(flood, "high_volume") || flood.Score != containedCostScore || !flood.Attention() {
		t.Errorf("a contained hammerer at %d serves is the volume itself: %+v", ContainedVolumeServes, flood)
	}
	if hasSignal(light, "high_volume") || light.Score >= AttentionScore {
		t.Errorf("thirty serves is not volume: %+v", light)
	}
	if through.Contained || !hasSignal(through, "high_volume") || !hasSignal(through, "scanner_paths") || through.Score != AttentionScore {
		t.Errorf("a passing scanner at %d serves carries the volume and clears the floor: %+v", VolumeServes, through)
	}
}

// A contained client's shape stops at the candidate floor however many
// signals it carries, the volume past the cost floor is what lifts it, and
// passing clients sort ahead of contained ones whatever the scores say --
// the operator's "0 passes is effectively blocked: lower its priority"
// (2026-09-09).
func TestContainedRanksUnderPassing(t *testing.T) {
	d := newTestDB(t)
	opt := Options{MinServes: 5, Limit: 50}
	// Hammering + scanner paths, 35 serves, never passed: two shapes, no volume.
	insertEvents(t, d, "203.0.113.90", "t13d_shape", "serve", "curl/8", `{"path":"/.env"}`, 35)
	// The same shapes past the cost floor.
	insertEvents(t, d, "203.0.113.91", "t13d_flood", "serve", "curl/8", `{"path":"/.env"}`, ContainedVolumeServes)
	// Passing: scanner paths at a few hundred serves and one pass -- a lower
	// score than the flood, and still first.
	insertEvents(t, d, "203.0.113.92", "t13d_through", "serve", "Mozilla/5.0", `{"path":"/.env"}`, VolumeServes)
	insertEvent(t, d, "203.0.113.92", "t13d_through", "bv_pow_then_captcha", "Mozilla/5.0", "")
	cands, err := Candidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	by := map[string]Candidate{}
	for _, c := range cands {
		order = append(order, c.Target)
		by[c.Target] = c
	}
	if want := []string{"203.0.113.92", "203.0.113.91", "203.0.113.90"}; strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want passing first, then the flood, then the shape-only client", order)
	}
	shape := by["203.0.113.90"]
	if !hasSignal(shape, "challenge_hammering") || !hasSignal(shape, "scanner_paths") || shape.Score != candidateFloor || shape.Attention() {
		t.Errorf("two contained shapes without the volume stop at the candidate floor: %+v", shape)
	}
	flood := by["203.0.113.91"]
	if !flood.Contained || flood.Score != containedCostScore || !flood.Attention() {
		t.Errorf("the same shapes past the cost floor score %d: %+v", containedCostScore, flood)
	}
	if through := by["203.0.113.92"]; through.Contained || through.Score != AttentionScore {
		t.Errorf("the passing scanner: %+v", through)
	}
}

// A contained fingerprint herd follows the same rule: the herd is the shape,
// and a few hundred serves across it is not the volume that lifts it.
func TestContainedHerdNeedsTheVolume(t *testing.T) {
	d := newTestDB(t)
	opt := Options{MinServes: 5, Limit: 50}
	for i := 1; i <= 12; i++ {
		insertEvents(t, d, "198.51.100."+itoa(i), "t13d_herd", "serve", "curl/8", "", 30)
	}
	cands, err := Candidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	var herd *Candidate
	for i := range cands {
		if cands[i].Type == "ja4" && cands[i].Target == "t13d_herd" {
			herd = &cands[i]
		}
	}
	if herd == nil {
		t.Fatalf("the herd is missing: %+v", cands)
	}
	if !herd.Contained || herd.Serves < VolumeServes || hasSignal(*herd, "high_volume") || herd.Score != candidateFloor || herd.Attention() {
		t.Errorf("a contained herd at a few hundred serves stays at the candidate floor: %+v", *herd)
	}
}

// Sample paths come from the payload the module actually writes: the
// requested path sits in orig_path on real events (path is the older / test
// shape).  The page showed an empty column on every install until this read
// both.
func TestSamplePathsReadOrigPath(t *testing.T) {
	d := newTestDB(t)
	opt := Options{MinServes: 5, Limit: 50}
	for i, path := range []string{"/wp-login.php", "/.env", "/xmlrpc.php", "/wp-login.php", "/.git/config", "/cgi-bin/luci"} {
		payload := `{"bt":"x","ch_mode":"pow_then_captcha","force_reason":"header","orig_path":"` + path + `","rl":0}`
		if i == 5 {
			payload = `{"path":"` + path + `"}` // the older shape still reads
		}
		insertEvent(t, d, "203.0.113.90", "t13d_scan", "serve", "Mozilla/5.0", payload)
	}
	cands, err := Candidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	var c *Candidate
	for i := range cands {
		if cands[i].Target == "203.0.113.90" {
			c = &cands[i]
		}
	}
	if c == nil {
		t.Fatalf("scanner not a candidate: %+v", cands)
	}
	if len(c.SamplePaths) != 3 {
		t.Fatalf("want 3 distinct sample paths from orig_path, got %v", c.SamplePaths)
	}
	for _, p := range c.SamplePaths {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("sample path is not a path: %q", p)
		}
	}
}

// In a proof-of-work-only chain the solve is the pass: it counts as PoW
// solved and shows up in the pass breakdown as pass_pow.
func TestPowOnlyChainCountsAsPowSolved(t *testing.T) {
	d := newTestDB(t)
	opt := Options{MinServes: 5, Limit: 50}
	for i := 0; i < 6; i++ {
		payload := ""
		if i < 3 {
			payload = `{"orig_path":"/.env"}` // scanner paths: makes it a candidate despite passing
		}
		insertEvent(t, d, "203.0.113.95", "t13d_powonly", "serve", "Mozilla/5.0", payload)
		insertEvent(t, d, "203.0.113.95", "t13d_powonly", "load", "Mozilla/5.0", "")
		insertEvent(t, d, "203.0.113.95", "t13d_powonly", "bv_pow_only", "Mozilla/5.0", "")
	}
	cands, err := Candidates(context.Background(), d, nil, Exclusions{}, opt)
	if err != nil {
		t.Fatal(err)
	}
	var c *Candidate
	for i := range cands {
		if cands[i].Target == "203.0.113.95" {
			c = &cands[i]
		}
	}
	if c == nil {
		t.Fatalf("not a candidate: %+v", cands)
	}
	if c.PowPassed != 6 || c.Passes != 6 || c.PassPow != 6 || c.PassCaptcha != 0 || c.PassBoth != 0 || c.Contained {
		t.Errorf("pow_only chain: want PoW solved 6 = passes 6 = pass_pow 6, got %+v", c)
	}
}
