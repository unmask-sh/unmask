package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestCheckHTTPSRedirectHealthCheck covers the live health-check probe:
//  1. redirect off -> silent
//  2. probe 301'd (exemption missing) -> WARN
//  3. probe 200 (exemption working) -> OK
//  4. probe unreachable -> silent
func TestCheckHTTPSRedirectHealthCheck(t *testing.T) {
	t.Run("off is silent", func(t *testing.T) {
		var s settings.Settings // HTTPSRedirect false
		cap, addOK, addWarn, _ := newCaptures()
		checkHTTPSRedirectHealthCheck(s, addOK, addWarn)
		if len(cap.ok)+len(cap.warn) != 0 {
			t.Errorf("expected silence, got ok=%v warn=%v", cap.ok, cap.warn)
		}
	})

	t.Run("301 to GoogleHC -> WARN", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// simulate the redirect firing on the health-check probe
			http.Redirect(w, r, "https://example.com/", http.StatusMovedPermanently)
		}))
		defer srv.Close()
		old := httpsRedirectProbeURL
		httpsRedirectProbeURL = srv.URL + "/"
		defer func() { httpsRedirectProbeURL = old }()

		var s settings.Settings
		s.Nginx.HTTPSRedirect = true
		cap, addOK, addWarn, _ := newCaptures()
		checkHTTPSRedirectHealthCheck(s, addOK, addWarn)
		if len(cap.warn) != 1 || len(cap.ok) != 0 {
			t.Errorf("expected 1 WARN, got ok=%v warn=%v", cap.ok, cap.warn)
		}
	})

	t.Run("200 to GoogleHC -> OK", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("User-Agent") != "GoogleHC/1.0" {
				t.Errorf("probe should send GoogleHC user-agent, got %q", r.Header.Get("User-Agent"))
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		old := httpsRedirectProbeURL
		httpsRedirectProbeURL = srv.URL + "/"
		defer func() { httpsRedirectProbeURL = old }()

		var s settings.Settings
		s.Nginx.HTTPSRedirect = true
		cap, addOK, addWarn, _ := newCaptures()
		checkHTTPSRedirectHealthCheck(s, addOK, addWarn)
		if len(cap.ok) != 1 || len(cap.warn) != 0 {
			t.Errorf("expected 1 OK, got ok=%v warn=%v", cap.ok, cap.warn)
		}
	})

	t.Run("unreachable is silent", func(t *testing.T) {
		old := httpsRedirectProbeURL
		httpsRedirectProbeURL = "http://127.0.0.1:1/" // nothing listens on port 1
		defer func() { httpsRedirectProbeURL = old }()

		var s settings.Settings
		s.Nginx.HTTPSRedirect = true
		cap, addOK, addWarn, _ := newCaptures()
		checkHTTPSRedirectHealthCheck(s, addOK, addWarn)
		if len(cap.ok)+len(cap.warn) != 0 {
			t.Errorf("expected silence on unreachable probe, got ok=%v warn=%v", cap.ok, cap.warn)
		}
	})
}
