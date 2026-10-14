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
	for _, want := range []string{"REMOVED in 0.1.51", "rescued again", "Sogou, DataForSeoBot", "upstream_pattern_mode", "render-nginx"} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Fatalf("upstream_disabled warning must mention %q, got: %s", want, got)
		}
	}

	// The new key already sets every crawler the old list names: nothing is
	// rescued again, and the log must not say so -- only that the list is
	// left over.
	got = capture("nginx:\n  search_bots:\n    upstream_pattern_mode:\n      DataForSeoBot: none\n      Sogou: none\n" +
		"    upstream_disabled:\n      - Sogou\n      - DataForSeoBot\n")
	if bytes.Contains([]byte(got), []byte("rescued again")) || !bytes.Contains([]byte(got), []byte("upstream_pattern_mode sets each crawler")) {
		t.Fatalf("a list the new key covers is only left over, got: %s", got)
	}
	// Covered in part: the warning names only the crawler the new key leaves out.
	got = capture("nginx:\n  search_bots:\n    upstream_pattern_mode:\n      Sogou: none\n" +
		"    upstream_disabled:\n      - Sogou\n      - DataForSeoBot\n")
	if !bytes.Contains([]byte(got), []byte("rescued again")) || !bytes.Contains([]byte(got), []byte("upstream_disabled (DataForSeoBot)")) {
		t.Fatalf("the crawler the new key leaves out must be named on its own, got: %s", got)
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
