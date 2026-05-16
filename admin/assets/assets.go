// Package assets: embed-only package for static resources baked into the
// unmask-admin binary.
//
// Contents:
//   - crawler-user-agents.json   bot UA pattern source
//   - templates/*.html           dashboard templates
//   - static/challenge.html      challenge HTML (= canonical source; rpm/nfpm copies this to /usr/share/unmask/challenge/ for site override)
//   - iprange/*.json             official crawler IP-range snapshots from each vendor
package assets

import "embed"

//go:embed crawler-user-agents.json
var CrawlerUserAgentsJSON []byte

//go:embed templates
var Templates embed.FS

//go:embed static
var Static embed.FS

//go:embed iprange/*.json
var IPRange embed.FS
