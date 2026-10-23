package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A pattern may carry `\"` -- a literal quote in RE2, which the form's regex
// check accepts.  Escaping only the quote rendered `\\"`, which nginx read as
// one backslash and a CLOSING quote, and the rest of the pattern became
// directives in a file nginx loads as root.  The backslash is doubled first.
func TestNginxQuoteKeepsTheKeyClosed(t *testing.T) {
	in := `a\"; include /etc/evil.conf; #`
	got := nginxQuote(in)
	want := `a\\\"; include /etc/evil.conf; #`
	if got != want {
		t.Fatalf("nginxQuote(%q)\n got %q\nwant %q", in, got, want)
	}
	// Walk it the way nginx's reader does: a backslash escapes the next
	// character, and the key ends at the first unescaped quote.  The whole
	// pattern must still be inside.
	closedAt := -1
	for i := 0; i < len(got); i++ {
		if got[i] == '\\' {
			i++
			continue
		}
		if got[i] == '"' {
			closedAt = i
			break
		}
	}
	if closedAt >= 0 {
		t.Fatalf("an unescaped quote at %d closes the key early: %q", closedAt, got)
	}
	// A lone trailing backslash would escape the closing quote the template
	// adds; doubled, it cannot.
	if got := nginxQuote(`end\`); !strings.HasSuffix(got, `\\`) {
		t.Fatalf("trailing backslash not doubled: %q", got)
	}
	// Control characters never belong in a key.
	if got := nginxQuote("a\r\nb\x00c"); got != "abc" {
		t.Fatalf("control characters kept: %q", got)
	}
}

// A custom trusted-LB label is written on a comment line of the rendered
// config, where a newline would end the comment and start a directive.  The
// form strips it on the way in; the renderer strips it again so a hand-edited
// config gets the same treatment.
func TestLBLabelStaysOnItsCommentLine(t *testing.T) {
	lbs := effectiveLBs(nil, []settings.TrustedLBExtra{{
		ID:     "mylb",
		Label:  "my lb\ninclude /etc/evil.conf;",
		CIDRs:  []string{"203.0.113.0/24"},
		Header: "$http_x_client_ja4; include /etc/evil.conf",
	}})
	if len(lbs) != 1 {
		t.Fatalf("expected the one custom row, got %d", len(lbs))
	}
	if strings.ContainsAny(lbs[0].Label, "\r\n") {
		t.Fatalf("label still carries a line break: %q", lbs[0].Label)
	}
	if lbs[0].Header != "$http_x_client_ja4" {
		t.Fatalf("a header that is not a clean $http_ variable was kept: %q", lbs[0].Header)
	}
	if OneLine("a\tb\nc\r") != "a b c " {
		t.Fatalf("OneLine: %q", OneLine("a\tb\nc\r"))
	}
}
