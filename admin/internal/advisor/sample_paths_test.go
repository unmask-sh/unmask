package advisor

import (
	"context"
	"testing"
)

// Every row samples its own newest events for its paths: a hammerer's
// hundreds of rows no longer crowd a quiet address or a fingerprint herd
// out of one shared sample, and a row that has its paths keeps them
// (operator, 2026-09-13: "要求パス例が空欄のものが多いのはなぜ？").
func TestSamplePathsPerRow(t *testing.T) {
	d := newTestDB(t)
	for i := 0; i < 600; i++ {
		insertEvent(t, d, "198.51.100.70", "t13d_busy", "serve", "curl/8", `{"orig_path":"/hammer"}`)
	}
	insertEvent(t, d, "198.51.100.71", "t13d_quiet", "serve", "curl/8", `{"orig_path":"/quiet"}`)
	insertEvent(t, d, "198.51.100.72", "t13d_herd", "serve", "curl/8", `{"orig_path":"/herd-a"}`)
	insertEvent(t, d, "198.51.100.73", "t13d_herd", "load", "curl/8", `{"orig_path":"/herd-b"}`)
	insertEvent(t, d, "198.51.100.73", "t13d_herd", "serve", "curl/8", `{"orig_path":""}`) // no path: skipped, not a blank
	cands := []Candidate{
		{Type: "ip", Target: "198.51.100.70"},
		{Type: "ip", Target: "198.51.100.71"},
		{Type: "ja4", Target: "t13d_herd"},
		{Type: "ip", Target: "198.51.100.74", SamplePaths: []string{"/kept"}},
	}
	if err := FillSamplePaths(context.Background(), d, cands, Options{}); err != nil {
		t.Fatal(err)
	}
	if len(cands[0].SamplePaths) != 1 || cands[0].SamplePaths[0] != "/hammer" {
		t.Errorf("the hammerer's paths: %v", cands[0].SamplePaths)
	}
	if len(cands[1].SamplePaths) != 1 || cands[1].SamplePaths[0] != "/quiet" {
		t.Errorf("the quiet address must have its own path beside the hammerer: %v", cands[1].SamplePaths)
	}
	herd := cands[2].SamplePaths
	if len(herd) != 2 || !contains(herd, "/herd-a") || !contains(herd, "/herd-b") {
		t.Errorf("a fingerprint row has paths too: %v", herd)
	}
	if len(cands[3].SamplePaths) != 1 || cands[3].SamplePaths[0] != "/kept" {
		t.Errorf("a row with paths keeps them: %v", cands[3].SamplePaths)
	}
}
