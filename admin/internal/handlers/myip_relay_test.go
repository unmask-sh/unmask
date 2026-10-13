package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/relay"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestMyIPNamesTheRelay: the IP popover's lookup says when an address is a
// privacy relay's, gives the relay's country, and keeps the database's beside
// it -- the operator sees why the two disagree.
func TestMyIPNamesTheRelay(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "172.224.226.5:BN:36183,203.0.113.10:BR:16509")
	h := newTestHandler(t)
	h.IPGeo = ipgeo.Open("", "")
	tb, err := relay.Parse([]byte(`{"schemaVersion":1,"generatedAt":"2026-10-13T00:00:00Z","relays":{"apple-private-relay":{"countries":{"JP":["172.224.226.0/27"]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	relay.Set(tb)
	defer relay.Set(nil)

	get := func(ip string) myipResponse {
		t.Helper()
		rr := httptest.NewRecorder()
		h.AdminMyIP(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/api/myip?ip="+ip, nil))
		var resp myipResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: %v (%s)", ip, err, rr.Body.String())
		}
		return resp
	}
	if r := get("172.224.226.5"); r.Country != "JP" || r.Relay != "iCloud Private Relay" || r.CountryDB != "BN" || r.ASN != 36183 {
		t.Errorf("relay address: %+v", r)
	}
	if r := get("203.0.113.10"); r.Country != "BR" || r.Relay != "" || r.CountryDB != "" {
		t.Errorf("other address: %+v", r)
	}
}

// TestNetworkTabRelaySwitch: the network tab shows the relay list's switch
// and what was last pulled, and the save reads the box (absent = off).
func TestNetworkTabRelaySwitch(t *testing.T) {
	h := newTestHandler(t)
	tb, err := relay.Parse([]byte(`{"schemaVersion":1,"generatedAt":"2026-10-13T06:17:00Z","relays":{"apple-private-relay":{"countries":{"JP":["172.224.226.0/27"],"GB":["172.224.226.32/31"]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	relay.Set(tb)
	defer relay.Set(nil)

	render := func() string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/network/", nil)
		req.SetPathValue("tab", "network")
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		return rr.Body.String()
	}
	body := render()
	sec := body[strings.Index(body, `id="ipgeo-relay"`):]
	sec = sec[:strings.Index(sec, "</div>")]
	if !strings.Contains(sec, `name="ipgeo_relay_list" value="1" checked`) {
		t.Errorf("the relay list is not shown on by default:\n%s", sec)
	}
	if !strings.Contains(sec, "2 ") || !strings.Contains(sec, `data-ts="1791872220"`) {
		t.Errorf("the status line does not report the list:\n%s", sec)
	}

	s := *h.cfg()
	s.IPGeo.RelayListOff = true
	h.SetSettings(s)
	if strings.Contains(render(), `name="ipgeo_relay_list" value="1" checked`) {
		t.Error("switched off, the box is still checked")
	}

	for _, c := range []struct {
		form url.Values
		off  bool
	}{
		{url.Values{"ipgeo_mode": {"dbip"}, "ipgeo_asn_mode": {"dbip"}, "ipgeo_relay_list": {"1"}}, false},
		{url.Values{"ipgeo_mode": {"dbip"}, "ipgeo_asn_mode": {"dbip"}}, true},
	} {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(c.form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		var g settings.IPGeo
		if err := applyIPGeoForm(&g, r, i18n.LangEN); err != nil {
			t.Fatal(err)
		}
		if g.RelayListOff != c.off {
			t.Errorf("form %v: RelayListOff = %v, want %v", c.form, g.RelayListOff, c.off)
		}
	}
}
