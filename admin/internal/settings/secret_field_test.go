package settings

import "testing"

// IsSecretField answers from the same table WithSecretsRedacted blanks, by
// the yaml path or by the field's name alone.
func TestIsSecretField(t *testing.T) {
	for _, p := range []string{
		"notifications.url", "url", "URL",
		"secret.bv_secret", "bv_secret",
		"smtp.password", "password",
		"community_bans.token", "token",
		"ai_advisor.api_key", "api_key",
		"challenge.default.captcha_provider.turnstile_secret_key", "turnstile_secret_key",
		"challenge.sites.shop.public_test_pages_password", "public_test_pages_password",
	} {
		if !IsSecretField(p) {
			t.Errorf("%q is not a secret", p)
		}
	}
	for _, p := range []string{"", "notifications.format", "format", "sites", "turnstile_site_key", "base_path", "mmdb_path"} {
		if IsSecretField(p) {
			t.Errorf("%q is a secret", p)
		}
	}
}
