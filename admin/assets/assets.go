// Package assets: embed-only package for static resources baked into the
// unmask-admin binary.
//
// 内訳:
//   - crawler-user-agents.json   bot UA pattern source
//   - templates/*.html           dashboard templates
//   - static/challenge.html      challenge HTML (= challenge/ から copy)
package assets

import "embed"

//go:embed crawler-user-agents.json
var CrawlerUserAgentsJSON []byte

//go:embed templates
var Templates embed.FS

//go:embed static
var Static embed.FS
