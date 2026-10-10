package assets

import (
	"encoding/json"
	"sync"
)

// The map outline's country centroids, read once from the embedded file,
// for the server's own position when only its country is known.

var (
	centroidsOnce sync.Once
	centroids     map[string][2]float64 // ISO 3166-1 alpha-2 -> [lon, lat]
)

// WorldCentroid returns the [lon, lat] the map starts a country's streams
// from, and whether the country is on the map.
func WorldCentroid(cc string) (lon, lat float64, ok bool) {
	centroidsOnce.Do(func() {
		centroids = map[string][2]float64{}
		b, err := Static.ReadFile("static/world-110m.json")
		if err != nil {
			return
		}
		var m struct {
			Centroids map[string][2]float64 `json:"centroids"`
		}
		if json.Unmarshal(b, &m) == nil && m.Centroids != nil {
			centroids = m.Centroids
		}
	})
	p, ok := centroids[cc]
	if !ok {
		return 0, 0, false
	}
	return p[0], p[1], true
}
