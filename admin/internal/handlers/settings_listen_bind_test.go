package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The listen form saves a bind the daemon is restarted on.  It took "::" and
// the daemon could not listen on it; it also took anything made of hex digits,
// dots, colons and slashes.  What it takes now is an IP address -- IPv6 with
// or without its brackets -- and nothing that is not one.
func TestListenFormTakesAnAddressAndNothingElse(t *testing.T) {
	post := func(bind string) (settings.Server, error) {
		form := url.Values{"listen_mode": {"tcp"}, "tcp_bind": {bind}, "tcp_port": {"9477"}}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		s := settings.Server{Bind: "127.0.0.1", Port: 9477}
		err := applyServerListenForm(&s, r, i18n.LangEN)
		return s, err
	}
	for bind, want := range map[string]string{
		"127.0.0.1":    "127.0.0.1",
		"0.0.0.0":      "0.0.0.0",
		"192.0.2.10":   "192.0.2.10",
		"::":           "::",
		"[::]":         "[::]",
		"::1":          "::1",
		"[::1]":        "[::1]",
		"2001:db8::10": "2001:db8::10",
		"":             "127.0.0.1", // left empty: the default
	} {
		s, err := post(bind)
		if err != nil {
			t.Errorf("bind %q refused: %v", bind, err)
			continue
		}
		if s.Bind != want || s.Port != 9477 {
			t.Errorf("bind %q saved as %q port %d, want %q port 9477", bind, s.Bind, s.Port, want)
		}
	}
	for _, bind := range []string{
		"0.0.0.0:9477",        // the port has its own field
		"[::]:9477",           //
		"10.0.0.0/8",          // a range is not an address
		"1.2.3",               //
		"cafe",                // hex digits are not an address either
		"localhost",           //
		"fe80::1%eth0",        // a zone is free text
		"::1;include /tmp/x",  // and so is this
		"127.0.0.1 127.0.0.2", //
		"[::1",                //
	} {
		if s, err := post(bind); err == nil {
			t.Errorf("bind %q was taken (saved as %q); it is not an address", bind, s.Bind)
		}
	}
}
