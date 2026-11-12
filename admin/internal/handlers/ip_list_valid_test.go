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

// An address list takes addresses and CIDRs.  The check was of the
// characters only: "192.168.1" or "10.0.0.0/33" was saved under a success
// banner, and then matched nothing -- the renderer leaves out what nginx
// would refuse.  The row is refused by name instead, like any other the
// form cannot use.
func TestAddressListsRefuseWhatIsNoAddress(t *testing.T) {
	post := func(form url.Values, apply func(*settings.Nginx, *httptest.ResponseRecorder, url.Values) error) error {
		var n settings.Nginx
		return apply(&n, nil, form)
	}
	bypass := func(n *settings.Nginx, _ *httptest.ResponseRecorder, form url.Values) error {
		r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		return applyBypassIPsForm(n, r, i18n.LangEN)
	}
	network := func(n *settings.Nginx, _ *httptest.ResponseRecorder, form url.Values) error {
		r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		return applyNetworkForm(n, r, i18n.LangEN, "198.51.100.7", "admin.example.com")
	}

	for _, bad := range []string{"192.168.1", "10.0.0.0/33", "203.0.113.300", "::::", "abc", "1.2.3.4/", "fe80::1/129"} {
		for field, c := range map[string]struct {
			form  url.Values
			apply func(*settings.Nginx, *httptest.ResponseRecorder, url.Values) error
		}{
			"bypass_ip":          {url.Values{"bypass_ip": {bad}, "bypass_enabled": {"1"}}, bypass},
			"stats_exclude_ips":  {url.Values{"stats_exclude_ips": {bad}}, bypass},
			"metrics_allow_from": {url.Values{"metrics_allow_from": {bad}, "metrics_allow_from_enabled": {"1"}}, network},
			"admin_allowed_ips":  {url.Values{"admin_allowed_ips": {bad}, "admin_allowed_ips_enabled": {"1"}}, network},
		} {
			err := post(c.form, c.apply)
			var lf *listFieldError
			if !errors.As(err, &lf) || lf.Field != field || lf.Value != bad {
				t.Errorf("%s = %q: %v, want the row refused by name", field, bad, err)
			}
		}
	}
	for _, ok := range []string{"198.51.100.7", "198.51.100.0/24", "2001:db8::1", "2001:db8::/32", "::ffff:192.0.2.1", "0.0.0.0/0"} {
		if err := post(url.Values{"bypass_ip": {ok}, "bypass_enabled": {"1"}}, bypass); err != nil {
			t.Errorf("bypass_ip = %q refused: %v", ok, err)
		}
		if err := post(url.Values{"metrics_allow_from": {ok}, "metrics_allow_from_enabled": {"1"}}, network); err != nil {
			t.Errorf("metrics_allow_from = %q refused: %v", ok, err)
		}
	}
}
