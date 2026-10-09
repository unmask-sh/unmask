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

// An ASN rule's label, and the organisation text an organisation rule matches
// on, used to be cut to 80 characters on save without a word -- for the
// organisation, that changed what the rule matched.  The save now says so on
// the row at labelMax, in characters, and the page carries the same limit on
// the fields for the check that runs as the operator types.
func TestAsnLabelLimit(t *testing.T) {
	post := func(value, label string) error {
		t.Helper()
		form := url.Values{}
		form["asn_number"] = []string{value}
		form["asn_label"] = []string{label}
		form["asn_action"] = []string{"captcha_only"}
		r := httptest.NewRequest("POST", "/x?section=asn", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		var c settings.AsnConfig
		return applyAsnForm(&c, r, i18n.LangEN)
	}
	want := i18n.Tf(i18n.LangEN, "err.value_long", labelMax)
	for _, tc := range []struct {
		name, value, label string
		ok                 bool
	}{
		{"label at the limit", "15169", strings.Repeat("ラ", labelMax), true},
		{"label one past it", "15169", strings.Repeat("ラ", labelMax+1), false},
		{"organisation at the limit", strings.Repeat("o", labelMax), "", true},
		{"organisation one past it", strings.Repeat("o", labelMax+1), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := post(tc.value, tc.label)
			if tc.ok {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			fe, is := err.(*listFieldError)
			if !is || fe.Field != "asn_number" || fe.Value != tc.value || fe.Msg != want {
				t.Fatalf("not rejected on the row with the limit: %v", err)
			}
		})
	}

	body := renderTab(t, vacuumHandler(t, 10), "asn", user.RoleSuperadmin, "en")
	// Only the <input> tags: the tab's script names the fields too.
	seen := map[string]int{}
	for _, tag := range strings.Split(body, "<input ")[1:] {
		if i := strings.Index(tag, ">"); i >= 0 {
			tag = tag[:i]
		}
		for _, attr := range []string{`name="asn_label"`, `name="asn_number"`} {
			if !strings.Contains(tag, attr) {
				continue
			}
			seen[attr]++
			if !strings.Contains(tag, `data-maxchars="`+strconv.Itoa(labelMax)+`"`) || !strings.Contains(tag, `data-maxchars-msg="`+want+`"`) {
				t.Errorf("a %s field has no limit or message on it: %s", attr, tag)
			}
		}
	}
	// At least the template a new row is cloned from (the test settings hold
	// no ASN rule); a stored row renders the same tag.
	if len(seen) != 2 {
		t.Fatalf("fields seen: %v", seen)
	}
}
