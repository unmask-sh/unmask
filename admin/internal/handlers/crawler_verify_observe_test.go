package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/crawlerverify"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// banTableDDL mirrors the SQLite unmask_ban schema (db/migrate.go); newTestHandler's
// hand-written schema omits it, and db.Migrate can't run on top (its ALTERs
// collide with the partial schema), so create just this table.
const banTableDDL = `CREATE TABLE IF NOT EXISTS unmask_ban (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip VARCHAR(64) NOT NULL, ja4 VARCHAR(40) NOT NULL, source VARCHAR(32) NOT NULL,
    reason VARCHAR(255), banned_at INTEGER NOT NULL, expires_at INTEGER NOT NULL DEFAULT 0,
    banned_by VARCHAR(64), action VARCHAR(32) NOT NULL DEFAULT '',
    scope VARCHAR(16) NOT NULL DEFAULT 'ip_ja4', UNIQUE (ip, ja4, scope));`

type fakeRes struct {
	ptr map[string][]string
	fwd map[string][]string
}

func (f fakeRes) LookupAddr(_ context.Context, ip string) ([]string, error) { return f.ptr[ip], nil }
func (f fakeRes) LookupHost(_ context.Context, host string) ([]string, error) {
	return f.fwd[host], nil
}

// seedForged/seedVerified populate the verifier cache synchronously so the
// observer's Cached() lookup hits deterministically (no async wait).
func seedVerifier(res crawlerverify.Resolver, ip string) *crawlerverify.Verifier {
	v := crawlerverify.New(res)
	v.Verify(context.Background(), ip, "Googlebot")
	return v
}

// TestObserveCrawlerForBan: a forged crawler is auto-banned, a genuine one is
// not, and a disabled axis is a no-op.
func TestObserveCrawlerForBan(t *testing.T) {
	ctx := context.Background()
	h := newTestHandler(t)
	if _, err := h.DB.Exec(banTableDDL); err != nil {
		t.Fatalf("create unmask_ban: %v", err)
	}
	h.BanMgr = ban.New(h.DB, "", time.Hour)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Nginx.CrawlerVerify = settings.CrawlerVerifyConfig{Enabled: true, ForgedAction: settings.GeoActionDeny}
	})

	// Forged: PTR is not a google domain -> ban.
	h.CrawlerVerify = seedVerifier(fakeRes{ptr: map[string][]string{"1.2.3.4": {"host.cheap-vps.example"}}}, "1.2.3.4")
	h.ObserveCrawlerForBan("1.2.3.4", "Googlebot")
	if !h.BanMgr.IsBanned(ctx, "1.2.3.4", "") {
		t.Error("forged crawler should be auto-banned")
	}
	if src, ok := h.BanMgr.IsBannedSource(ctx, "1.2.3.4", ""); !ok || src != ban.SourceCrawlerForged {
		t.Errorf("ban source = %q ok=%v, want %q", src, ok, ban.SourceCrawlerForged)
	}

	// Verified: real Googlebot rDNS -> must NOT ban.
	h.CrawlerVerify = seedVerifier(fakeRes{
		ptr: map[string][]string{"66.249.66.1": {"crawl.googlebot.com"}},
		fwd: map[string][]string{"crawl.googlebot.com": {"66.249.66.1"}},
	}, "66.249.66.1")
	h.ObserveCrawlerForBan("66.249.66.1", "Googlebot")
	if h.BanMgr.IsBanned(ctx, "66.249.66.1", "") {
		t.Error("verified crawler must not be banned")
	}

	// Disabled: even a forgery is a no-op.
	h.updateSettingsInMemory(func(s *settings.Settings) { s.Nginx.CrawlerVerify.Enabled = false })
	h.CrawlerVerify = seedVerifier(fakeRes{ptr: map[string][]string{"5.6.7.8": {"x.evil.example"}}}, "5.6.7.8")
	h.ObserveCrawlerForBan("5.6.7.8", "Googlebot")
	if h.BanMgr.IsBanned(ctx, "5.6.7.8", "") {
		t.Error("disabled rDNS must not ban")
	}
}
