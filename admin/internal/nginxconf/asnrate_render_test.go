package nginxconf

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestBuildRenderDataAsnRateGuard: a RatePerMin>0 rule with no ASN mmdb yields
// no rate zone (the walk is skipped), so the config degrades safely instead of
// emitting a zone whose geo block would be empty.  The populated case (real
// CIDRs -> a valid geo/map/limit_req_zone) is validated with `nginx -t` in
// development, where a real ASN mmdb is present.
func TestBuildRenderDataAsnRateGuard(t *testing.T) {
	s := settings.Settings{}
	// rate rule present, but MMDBASNPath empty
	s.Nginx.Asn = settings.AsnConfig{
		Rules: []settings.AsnRule{{ASN: 13335, Action: settings.GeoActionCaptchaOnly, RatePerMin: 100, Enabled: true}},
	}
	d, err := buildRenderData(s, t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.AsnRateZones) != 0 {
		t.Errorf("no mmdb -> want 0 rate zones, got %d", len(d.AsnRateZones))
	}
}
