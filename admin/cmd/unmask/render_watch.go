package main

import (
	"context"
	"log"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/renderwatch"
)

// renderAfterGeoUpdate: a new GeoIP snapshot is a new set of address ranges
// for the country and ASN rules, which the render writes into nginx's
// configuration from the mmdb.  Without a render they kept the previous
// snapshot's ranges until something else rendered -- a settings save, a
// restart -- and the reload checks could not see it, since nothing had been
// written yet.  Render, and say whether the configuration moved: the reload
// stays the operator's, and the admin pages show when nginx has not taken it.
func renderAfterGeoUpdate(render func() error, dir string) {
	before, _ := nginxconf.RenderIDOnDisk(dir)
	if err := render(); err != nil {
		log.Printf("ipgeo: render after the update failed: %v", err)
		return
	}
	after, _ := nginxconf.RenderIDOnDisk(dir)
	if after == before {
		log.Printf("ipgeo: the update left nginx's configuration unchanged")
		return
	}
	if before == "" {
		before = "-"
	}
	log.Printf("ipgeo: the update changed nginx's configuration (render %s -> %s); reload nginx to apply it", before, after)
}

// saveRenderWatch keeps the render watch's state file current: every 30
// seconds, when lines came in since the last save.  A failure is logged once,
// and again only when it changes.
func saveRenderWatch(ctx context.Context, w *renderwatch.Watch) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	last := ""
	for tick(ctx, t) {
		msg := ""
		if err := w.Save(); err != nil {
			msg = err.Error()
		}
		if msg != "" && msg != last {
			log.Printf("render watch: cannot keep its state for doctor: %s", msg)
		}
		last = msg
	}
}
