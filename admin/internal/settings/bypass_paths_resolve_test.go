package settings

import (
	"reflect"
	"testing"
)

// TestBypassPathsResolveEmpty: no Paths -> empty slice for every site.
func TestBypassPathsResolveEmpty(t *testing.T) {
	var b BypassPathsConfig
	if got := b.ResolvePaths(""); len(got) != 0 {
		t.Fatalf("empty config, empty site: want [], got %+v", got)
	}
	if got := b.ResolvePaths("shop.example.com"); len(got) != 0 {
		t.Fatalf("empty config, real site: want [], got %+v", got)
	}
}

// TestBypassPathsResolveAllSites: a row with Site == "" applies to every site.
func TestBypassPathsResolveAllSites(t *testing.T) {
	b := BypassPathsConfig{
		Paths: []BypassPath{
			{Path: "/robots.txt", Site: ""},
		},
	}
	for _, site := range []string{"", "shop.example.com", "blog.example.com"} {
		got := b.ResolvePaths(site)
		if !reflect.DeepEqual(got, b.Paths) {
			t.Fatalf("site=%q: want %+v, got %+v", site, b.Paths, got)
		}
	}
}

// TestBypassPathsResolveSiteSpecific: a row with a non-empty Site matches
// only that site (= other sites get an empty slice when no all-sites row
// is present).
func TestBypassPathsResolveSiteSpecific(t *testing.T) {
	shopOnly := BypassPath{Path: "/api/v2/health", Site: "shop.example.com"}
	b := BypassPathsConfig{Paths: []BypassPath{shopOnly}}
	if got := b.ResolvePaths("shop.example.com"); !reflect.DeepEqual(got, []BypassPath{shopOnly}) {
		t.Fatalf("shop: want [%+v], got %+v", shopOnly, got)
	}
	if got := b.ResolvePaths("blog.example.com"); len(got) != 0 {
		t.Fatalf("blog: want [], got %+v", got)
	}
}

// TestBypassPathsResolveMixed: the all-sites row appears for every site;
// the shop-only row only appears for shop.  Order is preserved.
func TestBypassPathsResolveMixed(t *testing.T) {
	all := BypassPath{Path: "/robots.txt", Site: ""}
	shop := BypassPath{Path: "/api/v2/health", Site: "shop.example.com"}
	b := BypassPathsConfig{Paths: []BypassPath{all, shop}}
	if got := b.ResolvePaths("shop.example.com"); !reflect.DeepEqual(got, []BypassPath{all, shop}) {
		t.Fatalf("shop: want [all, shop], got %+v", got)
	}
	if got := b.ResolvePaths("blog.example.com"); !reflect.DeepEqual(got, []BypassPath{all}) {
		t.Fatalf("blog: want [all], got %+v", got)
	}
}
