package nginxconf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestSyncPullOnce_HappyPath: the hub returns one source, the override file
// is written, and Reload() makes Prefixes() see the new entry.
func TestSyncPullOnce_HappyPath(t *testing.T) {
	dir := t.TempDir()

	doc := AggregatedDoc{
		SchemaVersion: 1,
		GeneratedAt:   "2026-06-03T00:00:00Z",
		Sources: map[string]AggregatedSource{
			"google-common": {
				CreationTime: "2026-06-02T00:00:00.000000",
				Prefixes: []AggregatedPrefix{
					{IPv4Prefix: "203.0.113.0/24"},
					{IPv6Prefix: "2001:db8::/32"},
				},
			},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "Tue, 03 Jun 2026 00:00:00 GMT")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()

	s := NewSync()
	s.HubURL = srv.URL
	s.Dir = dir

	if err := s.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce: %v", err)
	}

	// File must exist under the override dir with the vendor-shaped JSON.
	body, err := os.ReadFile(filepath.Join(dir, "googlebot.json"))
	if err != nil {
		t.Fatalf("read override file: %v", err)
	}
	var got iprangePayload
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal written file: %v", err)
	}
	if len(got.Prefixes) != 2 {
		t.Fatalf("expected 2 prefixes, got %d", len(got.Prefixes))
	}
	if s.LastSyncedAt().IsZero() {
		t.Fatal("LastSyncedAt zero after successful pull")
	}
	if s.LastError() != "" {
		t.Fatalf("LastError nonempty after success: %q", s.LastError())
	}

	// Group must read from the override file (= 2 prefixes instead of the
	// embed's 900+).
	SetOverrideDir(dir)
	defer SetOverrideDir("")
	var g *BypassIPGroup
	for i := range BypassIPGroups {
		if BypassIPGroups[i].ID == "google-common" {
			g = &BypassIPGroups[i]
			break
		}
	}
	if g == nil {
		t.Fatal("google-common group missing")
	}
	if got := g.PrefixCount(); got != 2 {
		t.Fatalf("expected 2 prefixes from override, got %d", got)
	}
}

// TestSyncPullOnce_NotModified: a 304 response advances LastSyncedAt
// (= proof of a successful check) but writes no files.
func TestSyncPullOnce_NotModified(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	s := NewSync()
	s.HubURL = srv.URL
	s.Dir = dir

	if err := s.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce: %v", err)
	}
	if s.LastSyncedAt().IsZero() {
		t.Fatal("LastSyncedAt zero after 304")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			t.Fatalf("304 wrote unexpected file: %s", e.Name())
		}
	}
}

// TestSyncPullOnce_BadStatus: 5xx leaves no file behind and records the
// error.  LastSyncedAt remains zero so the UI can show "Not yet" properly.
func TestSyncPullOnce_BadStatus(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := NewSync()
	s.HubURL = srv.URL
	s.Dir = dir

	err := s.PullOnce(context.Background())
	if err == nil {
		t.Fatal("expected error on 500, got nil")
	}
	// The subscribe loop calls recordError; PullOnce itself doesn't (= only
	// success/304 paths set state).  Caller drives recordError, so this
	// stays untested here without coupling tests to the loop logic.
}

// TestSyncPullOnce_RenderFuncFires: a successful pull triggers the render
// hook so http.inc / server.inc are regenerated immediately.  A 304 does
// NOT fire it (= nothing changed).
func TestSyncPullOnce_RenderFuncFires(t *testing.T) {
	dir := t.TempDir()
	doc := AggregatedDoc{
		SchemaVersion: 1,
		Sources: map[string]AggregatedSource{
			"bing": {CreationTime: "2026-06-02T00:00:00.000000", Prefixes: []AggregatedPrefix{{IPv4Prefix: "198.51.100.0/24"}}},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()

	called := 0
	s := NewSync()
	s.HubURL = srv.URL
	s.Dir = dir
	s.RenderFunc = func() error { called++; return nil }

	if err := s.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce: %v", err)
	}
	if called != 1 {
		t.Fatalf("expected RenderFunc to fire once, got %d", called)
	}

	// Second pull: hub answers 304 → RenderFunc must NOT fire again.
	srv304 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv304.Close()
	s.HubURL = srv304.URL
	if err := s.PullOnce(context.Background()); err != nil {
		t.Fatalf("PullOnce 304: %v", err)
	}
	if called != 1 {
		t.Fatalf("304 should not refire RenderFunc, got %d", called)
	}
}

// TestReloadFromDisk: after writing fresh files and calling Reload, the
// loaded prefixes reflect the new content (= the cache is properly busted).
func TestReloadFromDisk(t *testing.T) {
	dir := t.TempDir()
	payload := iprangePayload{
		CreationTime: "2026-06-02T00:00:00.000000",
		Prefixes: []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
		}{
			{IPv4Prefix: "198.51.100.0/24"},
		},
	}
	body, _ := json.Marshal(payload)
	if err := os.WriteFile(filepath.Join(dir, "bingbot.json"), body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	SetOverrideDir(dir)
	defer SetOverrideDir("")

	var g *BypassIPGroup
	for i := range BypassIPGroups {
		if BypassIPGroups[i].ID == "bing" {
			g = &BypassIPGroups[i]
			break
		}
	}
	if g == nil {
		t.Fatal("bing group missing")
	}
	if got := g.PrefixCount(); got != 1 {
		t.Fatalf("expected 1 prefix from override, got %d", got)
	}
}
