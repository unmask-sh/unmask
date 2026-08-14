package ipgeo

import (
	"strings"
	"testing"
)

// nginxGeoParams counts the parameters nginx's geo parser would see on one
// entry line: whitespace-separated tokens, except that a double-quoted span is
// one token.  A geo entry must have exactly two.
func nginxGeoParams(line string) int {
	line = strings.TrimSuffix(strings.TrimSpace(line), ";")
	n := 0
	inQuote := false
	inTok := false
	for _, r := range line {
		switch r {
		case '"':
			inQuote = !inQuote
			if !inTok {
				n++
				inTok = true
			}
		case ' ', '\t':
			if !inQuote {
				inTok = false
			}
		default:
			if !inTok {
				n++
				inTok = true
			}
		}
	}
	return n
}

// TestGeoLineSurvivesSpaceyValues: an org rule's map value is "org:<pattern>"
// and patterns contain spaces.  Unquoted, nginx read the space as a third geo
// parameter and rejected the whole rendered config -- render succeeded,
// nginx -t failed afterwards, and a restart in that window would have kept
// nginx down.  Hit live on tool1-gb applying "china unicom".
func TestGeoLineSurvivesSpaceyValues(t *testing.T) {
	for _, val := range []string{"org:china unicom", "AS4837", "org:t-mobile"} {
		line := geoLine("1.2.3.0/24", val)
		if got := nginxGeoParams(line); got != 2 {
			t.Errorf("geoLine(%q) = %q parses as %d geo parameters, want 2", val, line, got)
		}
		if !strings.HasSuffix(strings.TrimSpace(line), ";") {
			t.Errorf("geoLine(%q) = %q lacks the terminating semicolon", val, line)
		}
	}
}

// TestGeoLineShape pins the exact emitted form so the rendered file stays
// diffable across releases.
func TestGeoLineShape(t *testing.T) {
	got := geoLine("112.80.0.0/13", "org:china unicom")
	want := "    112.80.0.0/13 \"org:china unicom\";\n"
	if got != want {
		t.Errorf("geoLine = %q, want %q", got, want)
	}
}
