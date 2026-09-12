package advisor

import (
	"context"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/events"
)

// Every row has its most requested paths with their hits: a hammerer's
// hundreds of rows no longer crowd a quiet address or a fingerprint herd
// out of one shared sample, the origin rides along for the full address,
// and a row that has its paths keeps them (operator, 2026-09-13: "要求パス
// 例が空欄のものが多いのはなぜ？" / "パスもヒット数があるといいかも").
func TestPathsByHits(t *testing.T) {
	d := newTestDB(t)
	for i := 0; i < 600; i++ {
		insertEvent(t, d, "198.51.100.70", "t13d_busy", "serve", "curl/8", `{"orig_path":"/hammer"}`)
	}
	for i := 0; i < 4; i++ {
		insertEvent(t, d, "198.51.100.70", "t13d_busy", "serve", "curl/8", `{"orig_path":"/hammer-b"}`)
	}
	insertEvent(t, d, "198.51.100.70", "t13d_busy", "serve", "curl/8", `{"orig_path":"/c"}`)
	insertEvent(t, d, "198.51.100.70", "t13d_busy", "serve", "curl/8", `{"orig_path":"/d"}`)
	insertEvent(t, d, "198.51.100.70", "t13d_busy", "load", "curl/8", `{"orig_path":"/not-a-serve"}`)
	// A quiet address, served once with the site the module records.
	if _, err := d.Exec(`INSERT INTO unmask_event
		(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		VALUES ('example.test','','https',443,?,'curl/8','t13d_quiet','',0,'serve',0,0,'','','{"orig_path":"/quiet"}',datetime('now'))`,
		events.PackIP("198.51.100.71")); err != nil {
		t.Fatal(err)
	}
	insertEvent(t, d, "198.51.100.72", "t13d_herd", "serve", "curl/8", `{"orig_path":"/herd-a"}`)
	insertEvent(t, d, "198.51.100.73", "t13d_herd", "serve", "curl/8", `{"path":"/herd-b"}`) // the older shape
	insertEvent(t, d, "198.51.100.73", "t13d_herd", "serve", "curl/8", `{"orig_path":""}`)   // no path: skipped
	cands := []Candidate{
		{Type: "ip", Target: "198.51.100.70"},
		{Type: "ip", Target: "198.51.100.71"},
		{Type: "ja4", Target: "t13d_herd"},
		{Type: "ip", Target: "198.51.100.74", Paths: []PathCount{{Path: "/kept", Hits: 1}}},
	}
	if err := FillPaths(context.Background(), d, cands, Options{}); err != nil {
		t.Fatal(err)
	}
	busy := cands[0]
	if len(busy.Paths) != topPaths || busy.Paths[0] != (PathCount{Path: "/hammer", Hits: 600}) || busy.Paths[1] != (PathCount{Path: "/hammer-b", Hits: 4}) || busy.Paths[2] != (PathCount{Path: "/c", Hits: 1}) || busy.DistinctPaths != 4 || busy.MorePaths() != 1 {
		t.Errorf("the hammerer's paths: %+v distinct=%d", busy.Paths, busy.DistinctPaths)
	}
	if len(busy.SamplePaths) != 3 || busy.SamplePaths[0] != "/hammer" {
		t.Errorf("the model's sample paths follow: %v", busy.SamplePaths)
	}
	quiet := cands[1]
	if len(quiet.Paths) != 1 || quiet.Paths[0] != (PathCount{Path: "/quiet", Hits: 1, Site: "example.test", Scheme: "https", Port: 443}) {
		t.Errorf("the quiet address has its own path, with its origin: %+v", quiet.Paths)
	}
	herd := cands[2]
	if len(herd.Paths) != 2 || herd.DistinctPaths != 2 || herd.Paths[0].Path != "/herd-a" || herd.Paths[1].Path != "/herd-b" {
		t.Errorf("a fingerprint row has paths too, the older shape included: %+v", herd.Paths)
	}
	if len(cands[3].Paths) != 1 || cands[3].Paths[0].Path != "/kept" {
		t.Errorf("a row with paths keeps them: %+v", cands[3].Paths)
	}
}
