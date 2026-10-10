package assets

import (
	"encoding/json"
	"testing"
)

// The dashboard's map outline: small enough to ship in every binary and
// serve on every dashboard load, and shaped the way the page expects.
func TestWorldMapAsset(t *testing.T) {
	b, err := Static.ReadFile("static/world-110m.json")
	if err != nil {
		t.Fatalf("read map: %v", err)
	}
	if len(b) > 160<<10 {
		t.Errorf("static/world-110m.json is %d bytes, want at most 160 KiB: round the coordinates or simplify the outline", len(b))
	}
	var m struct {
		W, H      int
		Paths     []string
		Centroids map[string][2]float64
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("map is not the JSON the page reads: %v", err)
	}
	if m.W != 1000 || m.H != 500 || len(m.Paths) < 200 {
		t.Errorf("map box %dx%d with %d paths; the page projects onto 1000x500", m.W, m.H, len(m.Paths))
	}
	// A few countries the map must place where they are (lon, lat).
	for cc, want := range map[string][2]float64{"JP": {138, 37}, "US": {-98.5, 39.5}, "DE": {10.4, 51.1}, "BR": {-52, -10}, "AU": {134, -25}} {
		got, ok := m.Centroids[cc]
		if !ok {
			t.Errorf("no centroid for %s", cc)
			continue
		}
		if d := abs(got[0]-want[0]) + abs(got[1]-want[1]); d > 3 {
			t.Errorf("%s centroid %v, want near %v", cc, got, want)
		}
	}
	if len(m.Centroids) < 150 {
		t.Errorf("%d centroids, want the world", len(m.Centroids))
	}
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

func TestWorldCentroid(t *testing.T) {
	lon, lat, ok := WorldCentroid("JP")
	if !ok || abs(lon-138) > 3 || abs(lat-37) > 3 {
		t.Errorf("JP = %v,%v ok=%v", lon, lat, ok)
	}
	if _, _, ok := WorldCentroid("ZZ"); ok {
		t.Error("an unknown code is on the map")
	}
}
