package handlers

import (
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// A custom honeypot rule's title leads the reason of every ban the rule
// creates, and the reason keeps reasonRuleMax characters of it.  The save says
// so, on the row, instead of the ban cutting the title later: the operator
// gets to choose the short form.  Counted in characters, so a Japanese title
// has the same room as an English one.
func TestHoneypotTitleLimit(t *testing.T) {
	post := func(title string) error {
		t.Helper()
		form := url.Values{}
		form["honeypot_url_path"] = []string{"/trap"}
		form["honeypot_url_title"] = []string{title}
		form["honeypot_url_enabled"] = []string{"1"}
		r := httptest.NewRequest("POST", "/x?section=honeypot", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		var n settings.Nginx
		return applyHoneypotForm(&n, r, i18n.LangEN)
	}
	for _, tc := range []struct {
		name  string
		title string
		ok    bool
	}{
		{"at the limit", strings.Repeat("t", reasonRuleMax), true},
		{"one past it", strings.Repeat("t", reasonRuleMax+1), false},
		{"multi-byte, at the limit", strings.Repeat("罠", reasonRuleMax), true},
		{"multi-byte, one past it", strings.Repeat("罠", reasonRuleMax+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := post(tc.title)
			if tc.ok {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			fe, is := err.(*listFieldError)
			if !is {
				t.Fatalf("not rejected as a row error: %v", err)
			}
			if fe.Field != "honeypot_url_path" || fe.Value != "/trap" {
				t.Errorf("the error does not point at the row: %+v", fe)
			}
			if want := i18n.Tf(i18n.LangEN, "err.honeypot_title_long", reasonRuleMax); fe.Msg != want {
				t.Errorf("message %q, want %q", fe.Msg, want)
			}
		})
	}

	// The page carries the same limit and the same words on the field, for the
	// check that runs as the operator types (data-maxchars in settings.html):
	// on every stored row and on the template a new row is cloned from.
	h := vacuumHandler(t, 10)
	body := renderTab(t, h, "honeypot", user.RoleSuperadmin, "en")
	attr := `name="honeypot_url_title"`
	if n := strings.Count(body, attr); n < 1 {
		t.Fatal("no honeypot title field rendered")
	}
	for _, chunk := range strings.Split(body, attr)[1:] {
		field := chunk
		if i := strings.Index(field, ">"); i >= 0 {
			field = field[:i]
		}
		if !strings.Contains(field, `data-maxchars="`+strconv.Itoa(reasonRuleMax)+`"`) {
			t.Errorf("a title field has no limit on it: %s", field)
		}
		if !strings.Contains(field, `data-maxchars-msg="`+i18n.Tf(i18n.LangEN, "err.honeypot_title_long", reasonRuleMax)+`"`) {
			t.Errorf("a title field does not carry the message: %s", field)
		}
	}
}
