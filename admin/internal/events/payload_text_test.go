package events

import (
	"encoding/json"
	"testing"
)

// The path and the referer are read by a person, so they have to come back as
// the text the visitor's browser sent.  Serialized the way the writer does it:
// the escapes under test are the serializer's, not something a fixture made up.
func TestRowTextIsUnescaped(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		path    string
		referer string
	}{
		{
			name:    "two query parameters and a search referer",
			payload: map[string]any{"bt": "abc", "orig_path": "/zipcode/?sort=zipcode&order=asc&p=5", "referer": "https://www.example.com/url?q=https://example.org/&sa=U"},
			path:    "/zipcode/?sort=zipcode&order=asc&p=5",
			referer: "https://www.example.com/url?q=https://example.org/&sa=U",
		},
		{
			name:    "angle brackets and a quote",
			payload: map[string]any{"uri": `/a?x=<b>&y="z"`},
			path:    `/a?x=<b>&y="z"`,
		},
		{
			name:    "the client-sent url loses its origin, not its query",
			payload: map[string]any{"url": "https://example.org/list?a=1&b=2"},
			path:    "/list?a=1&b=2",
		},
		{
			name:    "nothing to unescape",
			payload: map[string]any{"orig_path": "/plain/path", "referer": "https://example.org/"},
			path:    "/plain/path",
			referer: "https://example.org/",
		},
		{
			name:    "non-ASCII stays as written",
			payload: map[string]any{"orig_path": "/検索?q=あ&p=2"},
			path:    "/検索?q=あ&p=2",
		},
	}
	for _, c := range cases {
		buf, err := json.Marshal(c.payload)
		if err != nil {
			t.Fatal(err)
		}
		var row Row
		decorateRowFromPayload(&row, string(buf))
		if row.Path != c.path {
			t.Errorf("%s: Path = %q, want %q (stored: %s)", c.name, row.Path, c.path, buf)
		}
		if row.Referer != c.referer {
			t.Errorf("%s: Referer = %q, want %q (stored: %s)", c.name, row.Referer, c.referer, buf)
		}
	}
}

// A value the extractor cut short, or one that is simply not valid inside a
// JSON string, is handed back as it was rather than dropped.
func TestUnescapeJSONTextKeepsWhatItCannotDecode(t *testing.T) {
	for _, v := range []string{`/a\u00`, `/a\`, `/a\x`, "/plain"} {
		if got := unescapeJSONText(v); got != v {
			t.Errorf("unescapeJSONText(%q) = %q, want it unchanged", v, got)
		}
	}
	if got := unescapeJSONText(`/a?x=1\u0026y=2`); got != "/a?x=1&y=2" {
		t.Errorf("unescapeJSONText = %q", got)
	}
}
