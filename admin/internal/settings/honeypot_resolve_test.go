package settings

import (
	"reflect"
	"testing"
)

// HoneypotConfig.Resolve: a site's overrides combine with the default's
// parallel Extra arrays via append + remove, plus scalar DefaultAction /
// BanDuration / DisabledPresets overrides.  Undeclared site / empty override
// entry fall through to the default.  The returned value never carries the
// Overrides map (= callers must not re-resolve).
func TestHoneypotResolve(t *testing.T) {
	emptyPresets := []string{}
	customPresets := []string{"shell"}
	base := HoneypotConfig{
		DisabledPresets: []string{"wordpress", "secrets", "cms-admin"},
		Extra:           []string{"/wp-login.php", "/xmlrpc.php"},
		ExtraTitle:      []string{"wp-login", "xmlrpc"},
		ExtraDisabled:   []bool{false, false},
		ExtraUpdatedAt:  []int64{1000, 1001},
		ExtraAction:     []string{"", "deny"},
		BanDuration:     86400,
		BanFilePath:     "/etc/unmask/banned.txt",
		DefaultAction:   "pow_then_captcha",
		PresetAction:    map[string]string{"wordpress": "captcha_only"},
		Overrides: map[string]HoneypotOverride{
			"shop.example.com": {
				AppendExtra:          []string{"/shop-trap"},
				AppendExtraTitle:     []string{"shop-only honeypot"},
				AppendExtraDisabled:  []bool{false},
				AppendExtraUpdatedAt: []int64{2000},
				AppendExtraAction:    []string{"deny"},
				Remove:               []string{"/xmlrpc.php"},
				DefaultAction:        "captcha_only",
			},
			"blog.example.com": {
				DefaultAction:  "deny",
				BanDuration:    3600,
				BanDurationSet: true,
			},
			"strict.example.com": {
				DisabledPresets: &emptyPresets, // every preset ON
				DefaultAction:   "deny",
			},
			"custom.example.com": {
				DisabledPresets: &customPresets,
			},
			"empty.example.com": {},
			"removeonly.example.com": {
				Remove: []string{"/wp-login.php"},
			},
			"banperm.example.com": {
				BanDuration:    0,
				BanDurationSet: true, // explicit "permanent" overrides default 86400
			},
		},
	}

	cases := []struct {
		name             string
		site             string
		wantDisabled     []string
		wantExtra        []string
		wantExtraTitle   []string
		wantExtraAction  []string
		wantDefAction    string
		wantBanDuration  int
	}{
		{
			name:            "no site -> default verbatim",
			site:            "",
			wantDisabled:    []string{"wordpress", "secrets", "cms-admin"},
			wantExtra:       []string{"/wp-login.php", "/xmlrpc.php"},
			wantExtraTitle:  []string{"wp-login", "xmlrpc"},
			wantExtraAction: []string{"", "deny"},
			wantDefAction:   "pow_then_captcha",
			wantBanDuration: 86400,
		},
		{
			name:            "undeclared -> default",
			site:            "api.example.com",
			wantDisabled:    []string{"wordpress", "secrets", "cms-admin"},
			wantExtra:       []string{"/wp-login.php", "/xmlrpc.php"},
			wantExtraTitle:  []string{"wp-login", "xmlrpc"},
			wantExtraAction: []string{"", "deny"},
			wantDefAction:   "pow_then_captcha",
			wantBanDuration: 86400,
		},
		{
			name:            "shop: append + remove + action override",
			site:            "shop.example.com",
			wantDisabled:    []string{"wordpress", "secrets", "cms-admin"},
			wantExtra:       []string{"/wp-login.php", "/shop-trap"},
			wantExtraTitle:  []string{"wp-login", "shop-only honeypot"},
			wantExtraAction: []string{"", "deny"},
			wantDefAction:   "captcha_only",
			wantBanDuration: 86400,
		},
		{
			name:            "blog: scalar-only override",
			site:            "blog.example.com",
			wantDisabled:    []string{"wordpress", "secrets", "cms-admin"},
			wantExtra:       []string{"/wp-login.php", "/xmlrpc.php"},
			wantExtraTitle:  []string{"wp-login", "xmlrpc"},
			wantExtraAction: []string{"", "deny"},
			wantDefAction:   "deny",
			wantBanDuration: 3600,
		},
		{
			name:            "strict: DisabledPresets explicit empty",
			site:            "strict.example.com",
			wantDisabled:    []string{},
			wantExtra:       []string{"/wp-login.php", "/xmlrpc.php"},
			wantExtraTitle:  []string{"wp-login", "xmlrpc"},
			wantExtraAction: []string{"", "deny"},
			wantDefAction:   "deny",
			wantBanDuration: 86400,
		},
		{
			name:            "custom: DisabledPresets replacement",
			site:            "custom.example.com",
			wantDisabled:    []string{"shell"},
			wantExtra:       []string{"/wp-login.php", "/xmlrpc.php"},
			wantExtraTitle:  []string{"wp-login", "xmlrpc"},
			wantExtraAction: []string{"", "deny"},
			wantDefAction:   "pow_then_captcha",
			wantBanDuration: 86400,
		},
		{
			name:            "empty entry -> default verbatim",
			site:            "empty.example.com",
			wantDisabled:    []string{"wordpress", "secrets", "cms-admin"},
			wantExtra:       []string{"/wp-login.php", "/xmlrpc.php"},
			wantExtraTitle:  []string{"wp-login", "xmlrpc"},
			wantExtraAction: []string{"", "deny"},
			wantDefAction:   "pow_then_captcha",
			wantBanDuration: 86400,
		},
		{
			name:            "remove only -> default minus removed",
			site:            "removeonly.example.com",
			wantDisabled:    []string{"wordpress", "secrets", "cms-admin"},
			wantExtra:       []string{"/xmlrpc.php"},
			wantExtraTitle:  []string{"xmlrpc"},
			wantExtraAction: []string{"deny"},
			wantDefAction:   "pow_then_captcha",
			wantBanDuration: 86400,
		},
		{
			name:            "permanent ban via explicit 0 + Set",
			site:            "banperm.example.com",
			wantDisabled:    []string{"wordpress", "secrets", "cms-admin"},
			wantExtra:       []string{"/wp-login.php", "/xmlrpc.php"},
			wantExtraTitle:  []string{"wp-login", "xmlrpc"},
			wantExtraAction: []string{"", "deny"},
			wantDefAction:   "pow_then_captcha",
			wantBanDuration: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := base.Resolve(tc.site)
			if !reflect.DeepEqual(got.DisabledPresets, tc.wantDisabled) {
				t.Errorf("DisabledPresets = %v, want %v", got.DisabledPresets, tc.wantDisabled)
			}
			if !reflect.DeepEqual(got.Extra, tc.wantExtra) {
				t.Errorf("Extra = %v, want %v", got.Extra, tc.wantExtra)
			}
			if !reflect.DeepEqual(got.ExtraTitle, tc.wantExtraTitle) {
				t.Errorf("ExtraTitle = %v, want %v", got.ExtraTitle, tc.wantExtraTitle)
			}
			if !reflect.DeepEqual(got.ExtraAction, tc.wantExtraAction) {
				t.Errorf("ExtraAction = %v, want %v", got.ExtraAction, tc.wantExtraAction)
			}
			if got.DefaultAction != tc.wantDefAction {
				t.Errorf("DefaultAction = %q, want %q", got.DefaultAction, tc.wantDefAction)
			}
			if got.BanDuration != tc.wantBanDuration {
				t.Errorf("BanDuration = %d, want %d", got.BanDuration, tc.wantBanDuration)
			}
			if got.Overrides != nil {
				t.Errorf("Overrides leaked into resolved value")
			}
			// Install-wide fields must survive resolution unchanged.
			if got.BanFilePath != base.BanFilePath {
				t.Errorf("BanFilePath should be inherited verbatim")
			}
			if !reflect.DeepEqual(got.PresetAction, base.PresetAction) {
				t.Errorf("PresetAction should be inherited verbatim")
			}
		})
	}
}

// DisabledPresets nil vs empty: same pointer distinction as BypassPaths so
// the yaml round-trips both shapes.
func TestHoneypotResolveDisabledPresetsPointer(t *testing.T) {
	emptySlice := []string{}
	base := HoneypotConfig{
		DisabledPresets: []string{"wordpress", "secrets"},
		Overrides: map[string]HoneypotOverride{
			"explicit-empty.example.com": {DisabledPresets: &emptySlice},
			"inherit.example.com":        {},
		},
	}
	if got := base.Resolve("explicit-empty.example.com").DisabledPresets; !reflect.DeepEqual(got, []string{}) {
		t.Errorf("explicit empty: got %v want []", got)
	}
	if got := base.Resolve("inherit.example.com").DisabledPresets; !reflect.DeepEqual(got, []string{"wordpress", "secrets"}) {
		t.Errorf("inherit: got %v want default", got)
	}
}
