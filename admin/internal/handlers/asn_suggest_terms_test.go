package handlers

import (
	"reflect"
	"testing"
)

// TestResolveSuggestTokens pins query tokenization + the brand bridge that feeds
// the AND search (no mmdb needed -- it only touches the static catalog).
func TestResolveSuggestTokens(t *testing.T) {
	cases := []struct {
		q    string
		want []string
	}{
		// single brand token -> its primary pattern (junk raw form not searched)
		{"microsoft", []string{"Microsoft"}},
		{"azure", []string{"Microsoft"}},
		// AND: a brand token is bridged, a plain qualifier stays literal
		{"azure china", []string{"Microsoft", "china"}},
		{"amazon data", []string{"Amazon", "data"}},
		// a catalog-provider token bridges to canonical case
		{"ovh", []string{"OVH"}},
		// numbers name no provider -> literal
		{"16509", []string{"16509"}},
		{"16509 13335", []string{"16509", "13335"}},
		// a non-catalog org name stays literal
		{"comcast", []string{"comcast"}},
		// an AMBIGUOUS token (matches many provider labels: "Google Cloud",
		// "Alibaba Cloud"...) is kept literal rather than bridged to one.
		{"cloud", []string{"cloud"}},
		// 1-char tokens dropped
		{"a ovh", []string{"OVH"}},
		{"  amazon   data ", []string{"Amazon", "data"}},
	}
	for _, c := range cases {
		got := resolveSuggestTokens(c.q)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("resolveSuggestTokens(%q) = %v, want %v", c.q, got, c.want)
		}
	}
}

// TestResolveSuggestTokensCap: a pathological query is capped.
func TestResolveSuggestTokensCap(t *testing.T) {
	q := "aa bb cc dd ee ff gg hh ii jj kk" // 11 tokens
	if got := resolveSuggestTokens(q); len(got) > maxSuggestTokens {
		t.Errorf("tokens = %d, want <= %d (%v)", len(got), maxSuggestTokens, got)
	}
}
