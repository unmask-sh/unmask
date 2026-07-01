package settings

import (
	"reflect"
	"testing"
)

// TestProtectedPathsResolveEmpty: empty config -> empty slice for every site.
func TestProtectedPathsResolveEmpty(t *testing.T) {
	var p ProtectedPathsConfig
	if got := p.ResolvePaths(""); len(got) != 0 {
		t.Fatalf("empty: want [], got %+v", got)
	}
	if got := p.ResolvePaths("shop.example.com"); len(got) != 0 {
		t.Fatalf("empty real site: want [], got %+v", got)
	}
}

// TestProtectedPathsResolveAllSites: Site == "" applies to every site.
func TestProtectedPathsResolveAllSites(t *testing.T) {
	row := ProtectedPath{Path: "/admin/", Mode: "captcha"}
	p := ProtectedPathsConfig{Paths: []ProtectedPath{row}}
	for _, site := range []string{"", "shop.example.com"} {
		got := p.ResolvePaths(site)
		if !reflect.DeepEqual(got, []ProtectedPath{row}) {
			t.Fatalf("site=%q: want [%+v], got %+v", site, row, got)
		}
	}
}

// TestProtectedPathsResolveSiteSpecific: non-empty Site filters to exact match.
func TestProtectedPathsResolveSiteSpecific(t *testing.T) {
	shop := ProtectedPath{Path: "/checkout/", Mode: "pow", Site: "shop.example.com"}
	p := ProtectedPathsConfig{Paths: []ProtectedPath{shop}}
	if got := p.ResolvePaths("shop.example.com"); !reflect.DeepEqual(got, []ProtectedPath{shop}) {
		t.Fatalf("shop: want [shop], got %+v", got)
	}
	if got := p.ResolvePaths("blog.example.com"); len(got) != 0 {
		t.Fatalf("blog: want [], got %+v", got)
	}
}

// TestProtectedPathsResolveMixed: ensure ordering + filtering across two
// rows with different Site values.
func TestProtectedPathsResolveMixed(t *testing.T) {
	all := ProtectedPath{Path: "/admin/", Mode: "captcha"}
	shop := ProtectedPath{Path: "/checkout/", Mode: "pow", Site: "shop.example.com"}
	p := ProtectedPathsConfig{Paths: []ProtectedPath{all, shop}}
	if got := p.ResolvePaths("shop.example.com"); !reflect.DeepEqual(got, []ProtectedPath{all, shop}) {
		t.Fatalf("shop: want [all, shop], got %+v", got)
	}
	if got := p.ResolvePaths("blog.example.com"); !reflect.DeepEqual(got, []ProtectedPath{all}) {
		t.Fatalf("blog: want [all], got %+v", got)
	}
}
