package settings

import (
	"reflect"
	"testing"
)

// TestHoneypotResolveURLsEmpty: empty config -> empty slice.
func TestHoneypotResolveURLsEmpty(t *testing.T) {
	var h HoneypotConfig
	if got := h.ResolveURLs("shop.example.com"); len(got) != 0 {
		t.Fatalf("empty: want [], got %+v", got)
	}
}

// TestHoneypotResolveURLsAllSites: empty Site applies everywhere.
func TestHoneypotResolveURLsAllSites(t *testing.T) {
	row := HoneypotURL{Path: "/__hp__"}
	h := HoneypotConfig{URLs: []HoneypotURL{row}}
	for _, site := range []string{"", "shop.example.com"} {
		got := h.ResolveURLs(site)
		if !reflect.DeepEqual(got, []HoneypotURL{row}) {
			t.Fatalf("site=%q: want [row], got %+v", site, got)
		}
	}
}

// TestHoneypotResolveURLsSiteSpecific: non-empty Site filters exact match.
func TestHoneypotResolveURLsSiteSpecific(t *testing.T) {
	shop := HoneypotURL{Path: "/__decoy__", Site: "shop.example.com"}
	h := HoneypotConfig{URLs: []HoneypotURL{shop}}
	if got := h.ResolveURLs("shop.example.com"); !reflect.DeepEqual(got, []HoneypotURL{shop}) {
		t.Fatalf("shop: want [shop], got %+v", got)
	}
	if got := h.ResolveURLs("blog.example.com"); len(got) != 0 {
		t.Fatalf("blog: want [], got %+v", got)
	}
}

// TestHoneypotResolveURLsMixed: combine all-sites + per-site rows.
func TestHoneypotResolveURLsMixed(t *testing.T) {
	all := HoneypotURL{Path: "/__hp__"}
	shop := HoneypotURL{Path: "/__decoy__", Site: "shop.example.com"}
	h := HoneypotConfig{URLs: []HoneypotURL{all, shop}}
	if got := h.ResolveURLs("shop.example.com"); !reflect.DeepEqual(got, []HoneypotURL{all, shop}) {
		t.Fatalf("shop: want [all, shop], got %+v", got)
	}
	if got := h.ResolveURLs("blog.example.com"); !reflect.DeepEqual(got, []HoneypotURL{all}) {
		t.Fatalf("blog: want [all], got %+v", got)
	}
}

// TestHoneypotResolveParamsUndeclared: undeclared site -> Default verbatim.
func TestHoneypotResolveParamsUndeclared(t *testing.T) {
	h := HoneypotConfig{
		Default: HoneypotValues{BanDurationSec: 86400},
	}
	if got := h.ResolveParams("blog.example.com"); got != h.Default {
		t.Fatalf("undeclared: want %+v, got %+v", h.Default, got)
	}
}

// TestHoneypotResolveParamsDeclared: declared site -> Sites[site] verbatim.
func TestHoneypotResolveParamsDeclared(t *testing.T) {
	shop := HoneypotValues{BanDurationSec: 604800}
	h := HoneypotConfig{
		Default: HoneypotValues{BanDurationSec: 86400},
		Sites:   map[string]HoneypotValues{"shop.example.com": shop},
	}
	if got := h.ResolveParams("shop.example.com"); got != shop {
		t.Fatalf("declared: want %+v, got %+v", shop, got)
	}
}

// TestHoneypotResolveParamsEmptyEntry: empty entry -> zero value (no merge).
func TestHoneypotResolveParamsEmptyEntry(t *testing.T) {
	h := HoneypotConfig{
		Default: HoneypotValues{BanDurationSec: 86400},
		Sites:   map[string]HoneypotValues{"empty.example.com": {}},
	}
	if got := h.ResolveParams("empty.example.com"); got != (HoneypotValues{}) {
		t.Fatalf("empty entry: want zero, got %+v", got)
	}
}

// TestHoneypotResolvedBanDurationSecFallback: 0 -> 86400 default.
func TestHoneypotResolvedBanDurationSecFallback(t *testing.T) {
	v := HoneypotValues{}
	if got := v.ResolvedBanDurationSec(); got != 86400 {
		t.Fatalf("zero: want 86400, got %d", got)
	}
	v = HoneypotValues{BanDurationSec: 60}
	if got := v.ResolvedBanDurationSec(); got != 60 {
		t.Fatalf("nonzero: want 60, got %d", got)
	}
}
