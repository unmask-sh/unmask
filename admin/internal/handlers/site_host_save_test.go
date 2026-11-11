package handlers

import (
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A per-site rule's Site keys nginx's host maps, so a value that is not a
// host name is refused with the row, not saved for nginx to reject (or, for
// a quoted name, to apply to every host).
func TestBypassPathSiteMustBeAHostName(t *testing.T) {
	post := func(site string) error {
		form := url.Values{"bp_path": {"^/feed/"}, "bp_site": {site}, "bp_enabled": {"1"}}
		r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		var n settings.Nginx
		return applyBypassPathsForm(&n, r, i18n.LangEN)
	}
	for _, bad := range []string{`"shop.example.com"`, `shop.example.com\`, "default", "shop example.com"} {
		err := post(bad)
		var lf *listFieldError
		if !errors.As(err, &lf) || lf.Field != "bp_site" || lf.Value != bad {
			t.Errorf("site %q: %v", bad, err)
		}
	}
	for _, ok := range []string{"", "shop.example.com"} {
		if err := post(ok); err != nil {
			t.Errorf("site %q refused: %v", ok, err)
		}
	}
}
