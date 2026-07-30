package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The notification-preview group's rescue is a composite: the UA must be
// backed by Apple's TLS stack (JA4_b cipher hash against $effective_ja4).
// These fetchers run on subscribers' own devices -- residential IPs, no
// vendor ranges -- so putting the pattern in the plain $is_search_bot UA
// whitelist would make the rescue one copied header line.
func TestNotificationPreviewRenderGuarded(t *testing.T) {
	conf := renderHTTPInc(t, nil)

	for _, want := range []string{
		`map $http_user_agent $unmask_notif_preview_ua {`,
		`"~*Notification(Service)?Extension/.*CFNetwork" 1;`,
		`map $effective_ja4 $unmask_apple_tls {`,
		`"~` + classify.AppleCFNetworkJA4B + `" 1;`,
		`map "$unmask_search_bot_ua$unmask_notif_preview_ua$unmask_apple_tls" $is_search_bot {`,
		`"~^011$" 1;`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("default render must carry the guarded composite; missing %q", want)
		}
	}

	// The pattern must appear ONLY in the guarded map -- inside the plain UA
	// whitelist it would rescue on the UA string alone.
	uaMap := conf[strings.Index(conf, "$unmask_search_bot_ua {"):]
	uaMap = uaMap[:strings.Index(uaMap, "}")]
	if strings.Contains(uaMap, "NotificationExtension") {
		t.Error("notification-preview pattern leaked into the plain UA whitelist")
	}

	// Downstream consumers keep the $is_search_bot name: the composite swap
	// must be invisible to $final_challenge and the axis exemption keys.
	if !strings.Contains(conf, `:$is_search_bot:`) {
		t.Error("downstream maps no longer reference $is_search_bot")
	}
}

// Turning the group off ("none") removes the guarded maps entirely and falls
// back to the single plain map, so existing deployments render byte-stable.
func TestNotificationPreviewRenderOff(t *testing.T) {
	conf := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.SearchBots.UpstreamGroupMode = map[string]string{
			classify.NotificationPreviewTag: classify.GroupModeNone,
		}
	})
	for _, absent := range []string{"$unmask_notif_preview_ua", "$unmask_apple_tls", "$unmask_search_bot_ua"} {
		if strings.Contains(conf, absent) {
			t.Errorf("group off: %q must not render", absent)
		}
	}
	if !strings.Contains(conf, `map $http_user_agent $is_search_bot {`) {
		t.Error("group off: the plain $is_search_bot map must come back")
	}
}

// Per-pattern disable behaves like every other upstream pattern: the guarded
// maps disappear with their last enabled pattern.
func TestNotificationPreviewRenderPatternDisabled(t *testing.T) {
	conf := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.SearchBots.UpstreamDisabled = []string{
			"Notification(Service)?Extension/.*CFNetwork",
		}
	})
	if strings.Contains(conf, "$unmask_notif_preview_ua") {
		t.Error("disabling the only pattern must drop the guarded maps")
	}
}
