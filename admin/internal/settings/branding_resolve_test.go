package settings

import (
	"reflect"
	"testing"
)

// TestBrandingResolveUndeclared: a site without an entry in Sites returns the
// Default record verbatim.  No field-level merge happens.
func TestBrandingResolveUndeclared(t *testing.T) {
	b := Branding{
		Default: BrandingValues{
			SiteName:   "MyCo",
			LogoPath:   "/etc/unmask/logo.svg",
			FooterText: "Operated by MyCo",
			CopyPreset: BrandingPresetFriendly,
		},
	}
	got := b.Resolve("blog.example.com")
	if !reflect.DeepEqual(got, b.Default) {
		t.Fatalf("undeclared site: want default %+v, got %+v", b.Default, got)
	}
}

// TestBrandingResolveDeclared: a site with an entry in Sites returns the
// entry verbatim regardless of what Default holds.  Every field is taken
// from the entry, including ones whose value matches Default.
func TestBrandingResolveDeclared(t *testing.T) {
	shop := BrandingValues{
		SiteName:   "Shop Co",
		LogoPath:   "/etc/unmask/shop.png",
		FooterText: "Operated by MyCo",
		CopyPreset: BrandingPresetFriendly,
	}
	b := Branding{
		Default: BrandingValues{
			SiteName:   "MyCo",
			LogoPath:   "/etc/unmask/logo.svg",
			FooterText: "Operated by MyCo",
			CopyPreset: BrandingPresetFriendly,
		},
		Sites: map[string]BrandingValues{
			"shop.example.com": shop,
		},
	}
	got := b.Resolve("shop.example.com")
	if !reflect.DeepEqual(got, shop) {
		t.Fatalf("declared site: want %+v, got %+v", shop, got)
	}
}

// TestBrandingResolveEmptyEntry: an empty BrandingValues entry returns the
// zero-value record (= it does NOT fall back to Default).  This is the v2
// contract: an entry exists or it does not; there is no field-level merge.
func TestBrandingResolveEmptyEntryInherits(t *testing.T) {
	b := Branding{
		Default: BrandingValues{
			SiteName:   "MyCo",
			LogoPath:   "/etc/unmask/logo.svg",
			FooterText: "Operated by MyCo",
			CopyPreset: BrandingPresetFriendly,
		},
		Sites: map[string]BrandingValues{
			"empty.example.com": {},
		},
	}
	if got := b.Resolve("empty.example.com"); !reflect.DeepEqual(got, b.Default) {
		t.Fatalf("empty entry: want Default %+v, got %+v", b.Default, got)
	}
	// Setting one field leaves the others inheriting -- a site that wants its
	// own logo does not thereby lose the operator's copy preset.
	b.Sites["empty.example.com"] = BrandingValues{LogoPath: "/etc/unmask/site.svg"}
	got := b.Resolve("empty.example.com")
	if got.LogoPath != "/etc/unmask/site.svg" {
		t.Errorf("own logo not applied: %q", got.LogoPath)
	}
	if got.SiteName != "MyCo" || got.CopyPreset != BrandingPresetFriendly {
		t.Errorf("overriding the logo dropped the inherited identity: %+v", got)
	}
}

// TestBrandingResolveAfterDelete: dropping a site from Sites returns the
// site to Default verbatim.
func TestBrandingResolveAfterDelete(t *testing.T) {
	b := Branding{
		Default: BrandingValues{
			SiteName:   "MyCo",
			CopyPreset: BrandingPresetFriendly,
		},
		Sites: map[string]BrandingValues{
			"shop.example.com": {SiteName: "Shop Co", CopyPreset: BrandingPresetMinimal},
		},
	}
	if got := b.Resolve("shop.example.com"); got.SiteName != "Shop Co" {
		t.Fatalf("pre-delete: want SiteName=Shop Co, got %q", got.SiteName)
	}
	delete(b.Sites, "shop.example.com")
	got := b.Resolve("shop.example.com")
	if !reflect.DeepEqual(got, b.Default) {
		t.Fatalf("post-delete: want default %+v, got %+v", b.Default, got)
	}
}

// TestBrandingResolveEmptyConfig: an empty Branding (= zero value) returns
// the zero BrandingValues for every site.  Sentinel for "fresh install with
// no branding configured".
func TestBrandingResolveEmptyConfig(t *testing.T) {
	var b Branding
	if got := b.Resolve(""); !reflect.DeepEqual(got, BrandingValues{}) {
		t.Fatalf("empty branding, empty site: want zero, got %+v", got)
	}
	if got := b.Resolve("some.example.com"); !reflect.DeepEqual(got, BrandingValues{}) {
		t.Fatalf("empty branding, real site: want zero, got %+v", got)
	}
}
