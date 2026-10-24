package handlers

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/cdn"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// An automatic ban that sits on a CDN's origin-facing address is marked on
// the bans page and counted in its note; an operator's own ban on the same
// address is not.
func TestBansPageMarksCDNEgress(t *testing.T) {
	cdn.Set(nil)
	h := installedHandler(t)
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	h.BanMgr = ban.New(h.DB, filepath.Join(t.TempDir(), "ban.list"), 0)
	// 130.176.88.7 is CloudFront origin-facing in the built-in snapshot; the
	// ban was placed before the manager knew (no lookup installed).
	const cfIP, ja4 = "130.176.88.7", "t13d230800_bfd000000000_000000000000"
	h.BanMgr.Add(cfIP, ja4)
	h.BanMgr.Add("203.0.113.9", ja4)
	if err := h.BanMgr.AddManual(t.Context(), "130.176.88.8", ja4, "by hand", "alice", "deny", 0); err != nil {
		t.Fatal(err)
	}

	body := renderAs(t, h.AdminBansIndex, "/unmask/admin/bans/", user.RoleSuperadmin, "en")
	if strings.Count(body, "CDN egress (Amazon CloudFront)") != 1 {
		t.Errorf("the CloudFront automatic ban is not marked once: %d marks", strings.Count(body, "CDN egress (Amazon CloudFront)"))
	}
	if !strings.Contains(body, "1 of these are automatic bans on a CDN") {
		t.Error("the note does not count the one CDN ban")
	}
	ja := renderAs(t, h.AdminBansIndex, "/unmask/admin/bans/", user.RoleSuperadmin, "ja")
	if !strings.Contains(ja, "CDN の出口 (Amazon CloudFront)") {
		t.Error("ja: the mark is not in Japanese")
	}

	// With the switch that bans CDN egress, nothing is marked.
	s = *h.cfg()
	s.Nginx.CDNEgressBan = true
	h.SetSettings(s)
	body = renderAs(t, h.AdminBansIndex, "/unmask/admin/bans/", user.RoleSuperadmin, "en")
	if strings.Contains(body, "CDN egress (") {
		t.Error("a ban is marked although CDN egress is banned by the switch")
	}
}

// The network tab's CDN card: the operator's own ranges are kept one per
// line and a line that is no range is refused by name; the switch and the
// real_ip switch round-trip.
func TestCDNEgressForm(t *testing.T) {
	var s settings.Settings
	form := url.Values{
		"cdn_egress_extra":  {"23.0.0.0/12\r\n\r\n2001:db8::1\n"},
		"cdn_egress_ban":    {"1"},
		"trusted_lb_realip": {"1"},
	}
	r, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	if err := applyCDNEgressForm(&s.Nginx, r, "en"); err != nil {
		t.Fatal(err)
	}
	applyTrustedLBForm(&s.Nginx, r)
	if len(s.Nginx.CDNEgressExtra) != 2 || s.Nginx.CDNEgressExtra[0] != "23.0.0.0/12" || s.Nginx.CDNEgressExtra[1] != "2001:db8::1" {
		t.Errorf("extra ranges: %v", s.Nginx.CDNEgressExtra)
	}
	if !s.Nginx.CDNEgressBan || !s.Nginx.TrustedLBRealIP {
		t.Error("the switches did not round-trip")
	}
	form.Set("cdn_egress_extra", "23.0.0.0/12\nnot a range\n")
	r, _ = http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	if err := applyCDNEgressForm(&s.Nginx, r, "en"); err == nil || !strings.Contains(err.Error(), "not a range") {
		t.Errorf("a line that is no range must be refused by name: %v", err)
	}
}
