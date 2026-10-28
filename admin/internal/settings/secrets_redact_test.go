package settings

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// secretSettings: a Settings with every credential set to a value no other
// field produces, a public key beside each secret one, and a site record
// carrying its own.
func secretSettings() Settings {
	var s Settings
	s.Secret.BVSecret = "LEAK-bv"
	s.Secret.CaptchaSecretBase = "LEAK-captcha-base"
	s.DB.MariaDB.Password = "LEAK-db"
	s.SMTP.Password = "LEAK-smtp"
	s.CommunityBans.Token = "LEAK-hub"
	s.AIAdvisor.APIKey = "LEAK-ai"
	s.Notifications.URL = "https://hooks.example/services/LEAK-webhook"
	s.Notifications.CriticalURL = "https://hooks.example/services/LEAK-critical-webhook"
	s.Challenge.Default.PublicTestPagesPassword = "LEAK-testpages"
	s.Challenge.Default.CaptchaProvider = Captcha{
		Provider:           "turnstile",
		TurnstileSiteKey:   "public-turnstile",
		TurnstileSecretKey: "LEAK-turnstile",
		HCaptchaSecretKey:  "LEAK-hcaptcha",
		RecaptchaSecretKey: "LEAK-recaptcha",
	}
	s.Challenge.Sites = map[string]ChallengeValues{
		"shop": {
			PublicTestPagesPassword: "LEAK-shop-testpages",
			CaptchaProvider: Captcha{
				Provider:          "hcaptcha",
				HCaptchaSiteKey:   "public-shop",
				HCaptchaSecretKey: "LEAK-shop-hcaptcha",
			},
		},
	}
	return s
}

func mustYAML(t *testing.T, s Settings) string {
	t.Helper()
	body, err := MarshalYAML(s)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Every credential, the per-site ones included, is replaced in the copy and
// nothing else is: the public keys stay, and the original -- its site map
// above all, the one part a value copy shares -- is untouched.
func TestWithSecretsRedactedCoversEveryCredential(t *testing.T) {
	s := secretSettings()
	body := mustYAML(t, s.WithSecretsRedacted())
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "LEAK-") {
			t.Errorf("a secret survived redaction: %s", line)
		}
	}
	for _, public := range []string{"public-turnstile", "public-shop"} {
		if !strings.Contains(body, public) {
			t.Errorf("the public key %s was redacted along with the secrets", public)
		}
	}
	if !strings.Contains(body, redactedSecret) {
		t.Fatalf("the redacted copy carries no marker:\n%s", body)
	}
	if s.SMTP.Password != "LEAK-smtp" || s.Challenge.Default.CaptchaProvider.TurnstileSecretKey != "LEAK-turnstile" {
		t.Error("the original's scalar secrets were written through")
	}
	if got := s.Challenge.Sites["shop"].CaptchaProvider.HCaptchaSecretKey; got != "LEAK-shop-hcaptcha" {
		t.Errorf("the original's site record was written through: %q", got)
	}
}

// A credential that is not set stays empty rather than becoming the marker,
// so the redacted copy still says which ones are configured; and an install
// without site records keeps a nil map, so its yaml does not change.
func TestWithSecretsRedactedLeavesEmptyAlone(t *testing.T) {
	var s Settings
	r := s.WithSecretsRedacted()
	if body := mustYAML(t, r); strings.Contains(body, redactedSecret) {
		t.Errorf("an unset credential became the marker:\n%s", body)
	}
	if r.Challenge.Sites != nil {
		t.Error("a nil site map came back non-nil")
	}
}

// The restore path: a redacted snapshot, parsed back, takes every live
// secret where it holds the marker -- and only there.  A value the snapshot
// holds in the clear (a row from before the redaction) or empty is applied as
// written, and a site that no longer exists in live gets an empty value, not
// the marker.
func TestWithSecretsFromRestoresLiveValues(t *testing.T) {
	live := secretSettings()
	snap, err := LoadFromYAML(mustYAML(t, live.WithSecretsRedacted()))
	if err != nil {
		t.Fatal(err)
	}
	if snap.SMTP.Password != redactedSecret {
		t.Fatalf("the marker did not survive the yaml round trip: %q", snap.SMTP.Password)
	}

	got := snap.WithSecretsFrom(live)
	want := secretFields(&live)
	for i, p := range secretFields(&got) {
		if *p != *want[i] {
			t.Errorf("secret %d: restored %q, live %q", i, *p, *want[i])
		}
	}
	gotShop, liveShop := got.Challenge.Sites["shop"], live.Challenge.Sites["shop"]
	wantShop := challengeSecretFields(&liveShop)
	for i, p := range challengeSecretFields(&gotShop) {
		if *p != *wantShop[i] {
			t.Errorf("site secret %d: restored %q, live %q", i, *p, *wantShop[i])
		}
	}
	if strings.Contains(mustYAML(t, got), redactedSecret) {
		t.Error("a marker survived the refill")
	}
	if snap.Challenge.Sites["shop"].CaptchaProvider.HCaptchaSecretKey != redactedSecret {
		t.Error("the refill wrote through the snapshot's site map")
	}

	clear := snap
	clear.SMTP.Password = "old-in-the-clear"
	clear.AIAdvisor.APIKey = ""
	got = clear.WithSecretsFrom(live)
	if got.SMTP.Password != "old-in-the-clear" {
		t.Errorf("a value held in the clear was replaced: %q", got.SMTP.Password)
	}
	if got.AIAdvisor.APIKey != "" {
		t.Errorf("an empty value was filled in: %q", got.AIAdvisor.APIKey)
	}

	gone := live
	gone.Challenge.Sites = nil
	got = snap.WithSecretsFrom(gone)
	if v := got.Challenge.Sites["shop"].CaptchaProvider.HCaptchaSecretKey; v != "" {
		t.Errorf("a site missing from live kept %q, want empty", v)
	}
	if got.Secret.BVSecret != "LEAK-bv" {
		t.Errorf("the install-wide secrets were not refilled beside a missing site: %q", got.Secret.BVSecret)
	}
}

// credentialField matches the names a credential is given in this package.
// A string field named like one that redaction does not reach is the bug
// this test is for: the list in secretFields is maintained by hand.
var credentialField = regexp.MustCompile(`(Password|Secret|Key|Token|APIKey)$`)

// notASecret names, by the tail of their path in the walk, the fields whose
// name says key and that are no credential: the CAPTCHA site keys, which the
// challenge page sends to every visitor; a Privacy Pass issuer's key, which
// is its published verification key; and a rate zone's key, which names
// what the zone counts by (ip, ip+ja4).  A field added here is a decision
// that it may leave in an export.
var notASecret = []string{
	".CaptchaProvider.TurnstileSiteKey",
	".CaptchaProvider.HCaptchaSiteKey",
	".CaptchaProvider.RecaptchaSiteKey",
	".PrivacyPass.Issuers[0].Key",
	".RateLimit.Key",
	".RateLimit.Zones[0].Key",
}

func isNotASecret(path string) bool {
	for _, tail := range notASecret {
		if strings.HasSuffix(path, tail) {
			return true
		}
	}
	return false
}

// fillCredentials sets every credential-named string field reachable through
// v -- structs, pointers to them, and one element put into each slice and
// map of structs -- to a value that names its path.
func fillCredentials(v reflect.Value, path string, depth int) {
	if depth > 10 {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			if v.Type().Elem().Kind() != reflect.Struct || !v.CanSet() {
				return
			}
			v.Set(reflect.New(v.Type().Elem()))
		}
		fillCredentials(v.Elem(), path, depth+1)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if !f.CanSet() {
				continue
			}
			name := v.Type().Field(i).Name
			if f.Kind() == reflect.String {
				if credentialField.MatchString(name) && !isNotASecret(path+"."+name) {
					f.SetString("LEAK-" + path + "." + name)
				}
				continue
			}
			fillCredentials(f, path+"."+name, depth+1)
		}
	case reflect.Slice:
		// A list of values ([]string) has no fields; a list of records gets
		// one record, filled, so a credential on a row is checked too.
		if !v.CanSet() || !holdsStruct(v.Type().Elem()) {
			return
		}
		elem := reflect.New(v.Type().Elem()).Elem()
		fillCredentials(elem, path+"[0]", depth+1)
		v.Set(reflect.Append(v, elem))
	case reflect.Map:
		// The per-site records live in a map; one site, filled.
		if !v.CanSet() || v.Type().Key().Kind() != reflect.String || !holdsStruct(v.Type().Elem()) {
			return
		}
		elem := reflect.New(v.Type().Elem()).Elem()
		fillCredentials(elem, path+"[probe]", depth+1)
		m := reflect.MakeMap(v.Type())
		m.SetMapIndex(reflect.ValueOf("probe"), elem)
		v.Set(m)
	}
}

// holdsStruct: is t a struct, or a pointer to one?
func holdsStruct(t reflect.Type) bool {
	return t.Kind() == reflect.Struct || (t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Struct)
}

// Every string field whose name says credential -- Password, Secret, Key,
// Token, APIKey -- anywhere in the Settings tree, the per-site records and
// the rule lists included, is covered by the redaction, or is named in
// notASecret as deliberately public.  Adding one to a struct without adding
// it to secretFields fails here, with its path.
func TestEveryCredentialNamedFieldIsRedacted(t *testing.T) {
	var s Settings
	fillCredentials(reflect.ValueOf(&s).Elem(), "settings", 0)
	if s.SMTP.Password == "" || s.Challenge.Default.CaptchaProvider.RecaptchaSecretKey == "" {
		t.Fatal("the walk did not reach the known credentials")
	}
	if site, ok := s.Challenge.Sites["probe"]; !ok || site.CaptchaProvider.HCaptchaSecretKey == "" {
		t.Fatal("the walk did not reach the per-site records")
	}
	if s.Challenge.Default.CaptchaProvider.TurnstileSiteKey != "" {
		t.Fatal("a public site key was filled as a credential")
	}
	body := mustYAML(t, s.WithSecretsRedacted())
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "LEAK-") {
			t.Errorf("a credential-named field is not redacted: %s", strings.TrimSpace(line))
		}
	}
}
