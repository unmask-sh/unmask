package settings

import (
	"bytes"
	"log"
	"testing"
)

// A leftover upstream_disabled names crawlers the operator took off the rescue
// list; the log has to say they pass again and name them.
func TestWarnRemovedUpstreamLists(t *testing.T) {
	capture := func(raw string) string {
		var buf bytes.Buffer
		old := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(old)
		warnRemovedUpstreamLists("/etc/unmask/config.yml", []byte(raw))
		return buf.String()
	}

	got := capture("nginx:\n  search_bots:\n    upstream_disabled:\n      - Sogou\n      - DataForSeoBot\n")
	for _, want := range []string{"REMOVED in 0.1.52", "rescued again", "Sogou, DataForSeoBot", "upstream_pattern_mode", "render-nginx"} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Fatalf("upstream_disabled warning must mention %q, got: %s", want, got)
		}
	}

	if got := capture("nginx:\n  search_bots:\n    upstream_ua_enabled:\n      - Googlebot\\/\n"); got == "" {
		t.Fatal("an upstream_ua_enabled leftover should still say it is ignored")
	} else if bytes.Contains([]byte(got), []byte("rescued again")) {
		t.Fatalf("upstream_ua_enabled changes nothing; the strong wording is for upstream_disabled only, got: %s", got)
	}

	if got := capture("nginx:\n  search_bots:\n    upstream_pattern_mode:\n      Sogou: none\n"); got != "" {
		t.Fatalf("the current key -> no warning, got: %s", got)
	}
	if got := capture(":: not yaml ::"); got != "" {
		t.Fatalf("unparsable yaml must stay silent here (Load already errors), got: %s", got)
	}
}
