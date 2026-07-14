package ban

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Start() flushes the ban file immediately, and flush() resolves every row
// whose action column is empty (= "inherit the source default") through
// EffectiveAction.  With no resolver installed EffectiveAction falls back to
// "deny", so a daemon that called Start() before wiring the resolver rewrote
// every inherit-action ban as a hard deny -- silently over-blocking, on every
// restart, regardless of the operator's configured captcha_only.  main.go now
// seeds the resolver from the boot settings before Start(); this pins that.
func TestStartFlushHonorsResolverNotDenyFallback(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	banFile := filepath.Join(dir, "ban.list")

	// A honeypot ban with an EMPTY action column (= inherit the source default),
	// which is what the auto-ban path writes when no per-preset override applies.
	seed := New(d, banFile, 0)
	seed.SetActionResolver(func(string) string { return settings.RateChallengeCaptchaOnly })
	seed.AddWithSourceAction(context.Background(), "203.0.113.9", "", SourceHoneypot, "trap", "", "")

	// Simulate a daemon restart: a brand-new Manager over the same DB + file.
	// The resolver must already be installed when Start() does its initial flush.
	restarted := New(d, banFile, 0)
	restarted.SetActionResolver(func(source string) string {
		if source == SourceHoneypot {
			return settings.RateChallengeCaptchaOnly
		}
		return ""
	})
	restarted.Start()
	defer restarted.Close()

	buf, err := os.ReadFile(banFile)
	if err != nil {
		t.Fatalf("read ban file: %v", err)
	}
	got := string(buf)
	if strings.Contains(got, "|honeypot|deny") {
		t.Errorf("restart flush wrote a hard deny for an inherit-action honeypot ban "+
			"(operator configured captcha_only) -- over-block regression:\n%s", got)
	}
	if !strings.Contains(got, "|honeypot|"+settings.RateChallengeCaptchaOnly) {
		t.Errorf("restart flush did not apply the resolver's captcha_only:\n%s", got)
	}
}

// EffectiveAction keeps its "deny" fallback when NO resolver is installed --
// that is the safe hard-ban default and the reason the ordering above matters.
// Pinned so a future refactor doesn't quietly change the fallback instead of
// fixing the ordering.
func TestEffectiveActionFallsBackToDenyWithoutResolver(t *testing.T) {
	m := New(nil, "", 0)
	if got := m.EffectiveAction("", SourceHoneypot); got != "deny" {
		t.Errorf("EffectiveAction with no resolver = %q, want deny", got)
	}
	if got := m.EffectiveAction("captcha_only", SourceHoneypot); got != "captcha_only" {
		t.Errorf("an explicit per-row action must win: got %q", got)
	}
}
