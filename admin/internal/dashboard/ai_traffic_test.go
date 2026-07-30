package dashboard

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestAITrafficBreakdown_InstallWide: install-wide agg path returns the
// expected per-crawler-tag counts + uniq IP shape.  Tags that didn't see
// a UA in the window appear with Count==0 (= the zero-row policy).
func TestAITrafficBreakdown_InstallWide(t *testing.T) {
	d := openTestDB(t)

	// 7 crawler UAs across distinct tags + 1 human Chrome that must not
	// match any crawler tag.  Site column intentionally empty so the
	// install-wide path is exercised.
	seedAITrafficEvents(t, d, "", []seedEvent{
		{"1.1.1.1", "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"},
		{"2.2.2.2", "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"},
		{"3.3.3.3", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
		{"4.4.4.4", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
		{"5.5.5.5", "ClaudeBot/1.0; +claudebot@anthropic.com"},
		{"6.6.6.6", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"},
		{"7.7.7.7", "PerplexityBot/1.0; +https://perplexity.ai/perplexitybot"},
		{"8.8.8.8", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"},
	})

	ctx := context.Background()
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	defer hourlyReady.Store(false)

	rows, err := AITrafficBreakdown(ctx, d, "", nil, 36)
	if err != nil {
		t.Fatalf("breakdown: %v", err)
	}

	// Every ordered tag must appear, zero-row policy guarantees that.
	if len(rows) != len(classify.CrawlerTagOrder) {
		t.Fatalf("expected %d rows (one per tag), got %d", len(classify.CrawlerTagOrder), len(rows))
	}
	// At least one row with Count > 0 — the test would be pointless otherwise.
	var hits int
	for _, r := range rows {
		if r.Count > 0 {
			hits++
		}
	}
	if hits == 0 {
		t.Fatal("no crawler UA matched — fixture vs embedded JSON drift")
	}
	// Tag set boundary: every Tag we returned must be one of the ordered
	// known values (= the Chrome UA can't have leaked an "unknown" row).
	known := map[string]bool{}
	for _, t := range classify.CrawlerTagOrder {
		known[t] = true
	}
	for _, r := range rows {
		if !known[r.Tag] {
			t.Errorf("unexpected tag %q", r.Tag)
		}
	}
}

// TestAITrafficBreakdown_PerSite: site-filtered agg path reads
// hkAITagSite, and an event seeded against site "alice" must not show up
// in a site="bob" query.  Plus the install-wide path must see both sites
// combined.
func TestAITrafficBreakdown_PerSite(t *testing.T) {
	d := openTestDB(t)

	// 4 events on "alice": 2 distinct GPTBot IPs (= ai-training × 2) +
	//                      1 Googlebot      (= search-engine × 1) +
	//                      1 facebookexternalhit (= social-preview × 1)
	// 2 events on "bob"  : 1 ClaudeBot      (= ai-training × 1) +
	//                      1 PerplexityBot  (= ai-user      × 1)
	seedAITrafficEvents(t, d, "alice", []seedEvent{
		{"1.1.1.1", "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"},
		{"2.2.2.2", "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"},
		{"3.3.3.3", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
		{"4.4.4.4", "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"},
	})
	seedAITrafficEvents(t, d, "bob", []seedEvent{
		{"5.5.5.5", "ClaudeBot/1.0; +claudebot@anthropic.com"},
		{"6.6.6.6", "PerplexityBot/1.0; +https://perplexity.ai/perplexitybot"},
	})

	ctx := context.Background()
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	defer hourlyReady.Store(false)

	// alice path: only alice's events count.
	aliceRows, err := AITrafficBreakdown(ctx, d, "alice", nil, 36)
	if err != nil {
		t.Fatalf("alice breakdown: %v", err)
	}
	aliceByTag := indexByTag(aliceRows)
	if got := aliceByTag["ai-training"]; got != 2 {
		t.Errorf("alice ai-training count = %d, want 2", got)
	}
	if got := aliceByTag["search-engine"]; got != 1 {
		t.Errorf("alice search-engine count = %d, want 1", got)
	}
	if got := aliceByTag["social-preview"]; got != 1 {
		t.Errorf("alice social-preview count = %d, want 1", got)
	}
	if got := aliceByTag["ai-user"]; got != 0 {
		t.Errorf("alice must not see bob's ai-user (got %d)", got)
	}

	// bob path: only bob's events count.
	bobRows, err := AITrafficBreakdown(ctx, d, "bob", nil, 36)
	if err != nil {
		t.Fatalf("bob breakdown: %v", err)
	}
	bobByTag := indexByTag(bobRows)
	if got := bobByTag["ai-training"]; got != 1 {
		t.Errorf("bob ai-training count = %d, want 1", got)
	}
	if got := bobByTag["ai-user"]; got != 1 {
		t.Errorf("bob ai-user count = %d, want 1", got)
	}
	if got := bobByTag["search-engine"]; got != 0 {
		t.Errorf("bob must not see alice's search-engine (got %d)", got)
	}

	// Install-wide path: alice + bob combined.
	allRows, err := AITrafficBreakdown(ctx, d, "", nil, 36)
	if err != nil {
		t.Fatalf("install-wide breakdown: %v", err)
	}
	allByTag := indexByTag(allRows)
	if got := allByTag["ai-training"]; got != 3 {
		t.Errorf("install-wide ai-training count = %d, want 3 (= alice 2 + bob 1)", got)
	}
}

// TestAITrafficBreakdown_HostFilterAndUnready: host filter or an
// un-bootstrapped aggregate must yield zero rows rather than fall back
// to a raw scan that times out the dashboard.  Mirrors the contract in
// AITrafficBreakdown's docstring.
func TestAITrafficBreakdown_HostFilterAndUnready(t *testing.T) {
	d := openTestDB(t)
	seedAITrafficEvents(t, d, "alice", []seedEvent{
		{"1.1.1.1", "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"},
	})

	ctx := context.Background()

	// agg not ready yet → all-zero rows even though events exist.
	rows, err := AITrafficBreakdown(ctx, d, "", nil, 36)
	if err != nil {
		t.Fatalf("unready breakdown: %v", err)
	}
	for _, r := range rows {
		if r.Count != 0 || r.UniqIP != 0 {
			t.Errorf("unready path must return zeros, got %+v", r)
		}
	}

	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	defer hourlyReady.Store(false)

	// host filter → zeros (= no host dimension on the aggregate).
	rows, err = AITrafficBreakdown(ctx, d, "", []string{"someHost"}, 36)
	if err != nil {
		t.Fatalf("host-filtered breakdown: %v", err)
	}
	for _, r := range rows {
		if r.Count != 0 || r.UniqIP != 0 {
			t.Errorf("host-filter path must return zeros, got %+v", r)
		}
	}
}

// ---- shared fixtures ----

type seedEvent struct {
	ip string
	ua string
}

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	tmp, _ := os.MkdirTemp("", "aitest-*")
	t.Cleanup(func() { os.RemoveAll(tmp) })
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}

// seedAITrafficEvents inserts phase=serve, rl-clean rows planted 30 minutes
// in the past so both the 24h scan window and the hour-bucket aggregate
// catch them.  site goes straight into the event's `site` column so the
// per-site rollup branch in aggregate_hourly fires.
func seedAITrafficEvents(t *testing.T, d *db.DB, site string, events []seedEvent) {
	t.Helper()
	for i, ev := range events {
		if _, err := d.Exec(
			`INSERT INTO unmask_event
				(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
				 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			 VALUES (?,'','','','`+ev.ip+`',?, 't13d','',0,'serve',0,0,'','','{}',datetime('now','-30 minutes'))`,
			site, ev.ua); err != nil {
			t.Fatalf("seed[%d] site=%q: %v", i, site, err)
		}
	}
}

func indexByTag(rows []AITrafficRow) map[string]int {
	by := map[string]int{}
	for _, r := range rows {
		by[r.Tag] = r.Count
	}
	return by
}
