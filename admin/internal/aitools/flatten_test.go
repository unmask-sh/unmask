package aitools

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// config.yml's keys, flattened with their values, secrets only said to be
// set; and the search that picks the ones a few words name.
func TestFlattenConfig(t *testing.T) {
	var s settings.Settings
	s.Nginx.TrustedLBPresets = []string{"gcp"}
	s.Secret.BVSecret = "hunter2"
	s.AIAdvisor.APIKey = "sk-1"
	s.EventsRetentionDays = 30
	keys := flattenConfig(s)
	byKey := map[string]string{}
	for _, k := range keys {
		byKey[k.Key] = k.Value
	}
	if byKey["nginx.trusted_lb_presets"] != "gcp" {
		t.Errorf("trusted_lb_presets = %q", byKey["nginx.trusted_lb_presets"])
	}
	if byKey["secret.bv_secret"] != "(set; not shown)" || byKey["ai_advisor.api_key"] != "(set; not shown)" {
		t.Errorf("secrets: bv=%q api=%q", byKey["secret.bv_secret"], byKey["ai_advisor.api_key"])
	}
	for _, k := range keys {
		if strings.Contains(k.Value, "hunter2") || strings.Contains(k.Value, "sk-1") {
			t.Errorf("a secret leaked: %+v", k)
		}
	}
	hits := configKeysMatching(keys, queryWords("GCP load balancer"))
	found := false
	for _, k := range hits {
		if k.Key == "nginx.trusted_lb_presets" {
			found = true
		}
	}
	if !found {
		t.Errorf("\"GCP\" did not find nginx.trusted_lb_presets: %+v", hits)
	}
	if hits := configKeysMatching(keys, queryWords("retention")); len(hits) == 0 || !strings.HasPrefix(hits[0].Key, "events_retention") && !strings.Contains(hits[0].Key, "retention") {
		t.Errorf("\"retention\": %+v", hits)
	}
}

func TestSettingsToolsListed(t *testing.T) {
	var d Deps
	names := map[string]bool{}
	for _, tl := range d.List() {
		names[tl.Name] = true
	}
	if !names["settings_find"] || !names["settings_tab"] {
		t.Errorf("tools: %v", names)
	}
	// Without the admin the search still answers from config.yml, and says
	// the pages are not available.
	d.Settings = func() settings.Settings {
		var s settings.Settings
		s.Nginx.TrustedLBPresets = []string{"gcp"}
		return s
	}
	out, err := d.Run(t.Context(), "settings_find", map[string]any{"query": "gcp"})
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if _, ok := m["admin"].(string); !ok {
		t.Errorf("admin: %v", m["admin"])
	}
	if ks, _ := m["config_keys"].([]configKey); len(ks) == 0 {
		t.Errorf("config_keys: %v", m["config_keys"])
	}
	if _, err := d.Run(t.Context(), "settings_find", map[string]any{}); err == nil {
		t.Error("an empty query must be an error")
	}
	if _, err := d.Run(t.Context(), "settings_tab", map[string]any{"tab": "network"}); err == nil {
		t.Error("settings_tab without the admin must be an error")
	}
}

// A webhook URL is a credential (its token is the path), and so is any
// value that carries one -- a password in a URL, a token in a query string
// -- whatever its key is called.  None of them reaches the model: not in
// the flattened keys, and not through a search that names the service.
func TestFlattenConfigRedactsWebhookURLsAndCredentialValues(t *testing.T) {
	var s settings.Settings
	s.Notifications.URL = "https://hooks.slack.com/services/T000/B000/SECRETTOKEN"
	s.Notifications.CriticalURL = "https://discord.com/api/webhooks/1234/DISCORDTOKEN"
	s.SMTP.Host = "mail.example"
	s.CommunityBans.SubmitURL = "https://user:HUBPASS@hub.example/submit"
	s.VersionCheckURL = "https://updates.example/check?token=QUERYTOKEN"
	s.IPGeo.MMDBPath = "/var/lib/unmask/ipgeo/dbip-country.mmdb"
	keys := flattenConfig(s)
	byKey := map[string]string{}
	for _, k := range keys {
		byKey[k.Key] = k.Value
	}
	for _, key := range []string{"notifications.url", "notifications.critical_url", "community_bans.submit_url", "version_check_url"} {
		if byKey[key] != "(set; not shown)" {
			t.Errorf("%s = %q, want it redacted", key, byKey[key])
		}
	}
	if byKey["smtp.host"] != "mail.example" || byKey["ipgeo.mmdb_path"] != s.IPGeo.MMDBPath {
		t.Errorf("plain values were hidden: host=%q mmdb=%q", byKey["smtp.host"], byKey["ipgeo.mmdb_path"])
	}
	for _, leak := range []string{"SECRETTOKEN", "DISCORDTOKEN", "HUBPASS", "QUERYTOKEN"} {
		for _, k := range keys {
			if strings.Contains(k.Value, leak) {
				t.Errorf("%s leaked through %s = %q", leak, k.Key, k.Value)
			}
		}
		for _, q := range []string{"slack", "webhook", "url", "discord", "token"} {
			for _, k := range configKeysMatching(keys, queryWords(q)) {
				if strings.Contains(k.Value, leak) {
					t.Errorf("query %q returned %s = %q", q, k.Key, k.Value)
				}
			}
		}
	}
	// The key is still found by the words that name it, with its value
	// said to be set.
	found := false
	for _, k := range configKeysMatching(keys, queryWords("webhook url")) {
		found = found || k.Key == "notifications.url"
	}
	if !found {
		t.Error("\"webhook url\" did not find notifications.url")
	}
}
