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

// TestHoneypotResolvedBanDurationSecFallback: 0 -> 86400 default.
// BanDurationSec is install-wide (= per-site override was dropped because the
// BAN list is keyed on IP+JA4, not on the visited host).
func TestHoneypotResolvedBanDurationSecFallback(t *testing.T) {
	h := HoneypotConfig{}
	if got := h.ResolvedBanDurationSec(); got != 86400 {
		t.Fatalf("zero: want 86400, got %d", got)
	}
	h = HoneypotConfig{BanDurationSec: 60}
	if got := h.ResolvedBanDurationSec(); got != 60 {
		t.Fatalf("nonzero: want 60, got %d", got)
	}
}
