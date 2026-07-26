package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestForgedCrawlerDecision pins how a proven-forged crawler maps to a decision:
// the default is a challenge with a chMode, an explicit deny is a hard block,
// and the reason always names the crawler.
func TestForgedCrawlerDecision(t *testing.T) {
	// Default (unset) -> challenge, not deny.
	d := forgedCrawlerDecision(settings.CrawlerVerifyConfig{}, "Googlebot")
	if d.sev == sevDeny {
		t.Error("default forged action must not be deny")
	}
	if d.reason != "crawler:forged:Googlebot" {
		t.Errorf("reason = %q", d.reason)
	}
	if d.chMode == "" {
		t.Error("a challenge decision must carry a chMode for the challenge HTML")
	}

	// Explicit deny -> hard block, no chMode needed.
	d = forgedCrawlerDecision(settings.CrawlerVerifyConfig{ForgedAction: settings.GeoActionDeny}, "Bingbot")
	if d.sev != sevDeny {
		t.Errorf("explicit deny: sev = %v, want sevDeny", d.sev)
	}
	if d.reason != "crawler:forged:Bingbot" {
		t.Errorf("reason = %q", d.reason)
	}

	// Explicit captcha_only -> challenge with a chMode.
	d = forgedCrawlerDecision(settings.CrawlerVerifyConfig{ForgedAction: settings.GeoActionCaptchaOnly}, "YandexBot")
	if d.sev == sevDeny {
		t.Error("captcha_only must not be deny")
	}
	if d.chMode == "" {
		t.Error("captcha_only must carry a chMode")
	}
}
