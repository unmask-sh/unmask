package settings

import "testing"

// Branding.Resolve: per-site override merges field-by-field on top of the
// default; sites without an override entry get the default unchanged; an
// empty string in an override slot inherits the default; the returned value
// never carries the Overrides map (= callers shouldn't accidentally
// re-resolve a resolved value).
func TestBrandingResolve(t *testing.T) {
	base := Branding{
		LogoPath:   "/etc/unmask/logo.svg",
		SiteName:   "MyCo",
		FooterText: "Operated by MyCo",
		CopyPreset: "friendly",
		Overrides: map[string]Branding{
			"shop.example.com": {
				SiteName: "MyCo Shop",
				LogoPath: "/etc/unmask/shop.svg",
			},
			"blog.example.com": {
				CopyPreset: "minimal",
				FooterText: "", // explicit empty must inherit default
			},
			"empty.example.com": {}, // no fields -> all default
		},
	}

	cases := []struct {
		name string
		site string
		want Branding
	}{
		{
			name: "no site -> default",
			site: "",
			want: Branding{
				LogoPath: "/etc/unmask/logo.svg", SiteName: "MyCo",
				FooterText: "Operated by MyCo", CopyPreset: "friendly",
			},
		},
		{
			name: "undeclared site -> default",
			site: "api.example.com",
			want: Branding{
				LogoPath: "/etc/unmask/logo.svg", SiteName: "MyCo",
				FooterText: "Operated by MyCo", CopyPreset: "friendly",
			},
		},
		{
			name: "shop override -> per-field merge",
			site: "shop.example.com",
			want: Branding{
				LogoPath: "/etc/unmask/shop.svg", SiteName: "MyCo Shop",
				FooterText: "Operated by MyCo", CopyPreset: "friendly",
			},
		},
		{
			name: "blog override -> empty string inherits, set field wins",
			site: "blog.example.com",
			want: Branding{
				LogoPath: "/etc/unmask/logo.svg", SiteName: "MyCo",
				FooterText: "Operated by MyCo", CopyPreset: "minimal",
			},
		},
		{
			name: "empty override entry -> default",
			site: "empty.example.com",
			want: Branding{
				LogoPath: "/etc/unmask/logo.svg", SiteName: "MyCo",
				FooterText: "Operated by MyCo", CopyPreset: "friendly",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := base.Resolve(tc.site)
			if got.LogoPath != tc.want.LogoPath ||
				got.SiteName != tc.want.SiteName ||
				got.FooterText != tc.want.FooterText ||
				got.CopyPreset != tc.want.CopyPreset {
				t.Errorf("Resolve(%q) = %+v, want %+v", tc.site, got, tc.want)
			}
			if got.Overrides != nil {
				t.Errorf("Resolve(%q) returned non-nil Overrides; caller must not re-resolve", tc.site)
			}
		})
	}
}
