package events

import (
	"encoding/json"
	"strings"
	"testing"
)

// A payload past the column's size keeps the keys the hunt groups and
// attributes by -- the beacon token above all -- under the truncation mark.
// It used to be replaced by the mark alone, so the row belonged to no
// session and the reason to no rule.
func TestTruncatedPayloadKeepsTheGroupingKeys(t *testing.T) {
	p := map[string]any{
		"bt": "tok.en.abc", "force_reason": "asn", "force_rule": "AS64496", "seq": 3,
		"elapsed_ms": 1200, "orig_path": "/search", "kind": "js_exception",
		"ua": strings.Repeat("u", 3000), "error_msg": strings.Repeat("e", 3000),
	}
	raw, _ := json.Marshal(p)
	if len(raw) <= payloadMax {
		t.Fatalf("the fixture must exceed payloadMax, has %d bytes", len(raw))
	}
	got := truncatedPayload(p)
	if len(got) > payloadMax {
		t.Fatalf("the kept payload is %d bytes, past payloadMax", len(got))
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(got), &back); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	for _, k := range []string{"bt", "force_reason", "force_rule", "seq", "elapsed_ms", "orig_path", "kind", "_truncated"} {
		if _, ok := back[k]; !ok {
			t.Errorf("%s is missing from %s", k, got)
		}
	}
	for _, k := range []string{"ua", "error_msg"} {
		if _, ok := back[k]; ok {
			t.Errorf("%s was kept", k)
		}
	}
	// A kept set that is itself too big falls back to the mark alone.
	huge := map[string]any{"bt": strings.Repeat("b", 5000)}
	if got := truncatedPayload(huge); got != `{"_truncated":true}` {
		t.Errorf("a kept set past the size: %q", got[:40])
	}
}
