package handlers

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/outbound"
	"github.com/unmask-sh/unmask/admin/internal/safe"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The config watch: config.yml as the daemon's source of truth, not only at
// start and at its own saves.
//
// The daemon read config.yml when it started and inside each settings save
// (which loads, changes and writes under the file's lock).  Between two
// saves its copy was whatever it had last read, and config.yml has other
// writers: `unmask upgrade-review --apply`, an edit by hand, a configuration
// manager.  The CLI tells the operator to render and reload nginx, which
// puts the new settings into nginx -- while the daemon went on judging,
// serving and banning by the old ones, and its next render of its own (the
// IP-range pull, the GeoIP update) wrote the old configuration back over the
// CLI's: presets acknowledged in the review went off again, with nothing to
// say so.
//
// Every few seconds the watch looks at the file (a stat: FileSignature).  A
// file the daemon did not write itself, unchanged since the look before --
// so a writer is not still at it -- is read; settings that differ from the
// live ones are adopted the way a save in the admin is: published, the
// components that keep a copy told (applyLiveSettings), nginx's
// configuration rendered (reloading nginx stays the operator's step, as
// after a save), and the change written to the audit log under the name
// "config.yml" with its diff.  A file that does not load is left alone, and
// said once.

// configWatchEvery: how often the file is looked at.  A change is adopted at
// the second look that finds it as it was, two to four seconds after the
// last write.
const configWatchEvery = 2 * time.Second

// configWatchState: what the watch remembers between two looks.
type configWatchState struct {
	mu sync.Mutex
	// known: the file as the live settings were read from it, or as the
	// daemon last wrote it.
	known string
	// pending: a signature seen once that is neither; adopted when the next
	// look finds it again.
	pending string
	// refused: a signature whose file did not load; not tried again until
	// the file changes.
	refused string
}

// SetConfigSignature records the file the live settings were read from: the
// signature the start took before it loaded config.yml.
func (h *Handler) SetConfigSignature(sig string) {
	h.cfgWatch.mu.Lock()
	h.cfgWatch.known = sig
	h.cfgWatch.mu.Unlock()
}

// noteConfigWritten records the file as the daemon has just written it, so
// the watch does not read its own save back.  Called under settingsMu, after
// a successful write.
func (h *Handler) noteConfigWritten() {
	if h.ConfigPath == "" {
		return
	}
	h.SetConfigSignature(settings.FileSignature(h.ConfigPath))
}

// RunConfigWatch is the loop: a look every configWatchEvery until ctx ends.
func (h *Handler) RunConfigWatch(ctx context.Context) {
	if h.ConfigPath == "" {
		return
	}
	t := time.NewTicker(configWatchEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer safe.Recover("config-watch")
				h.configWatchTick(ctx)
			}()
		}
	}
}

// configWatchTick is one look at config.yml.
func (h *Handler) configWatchTick(ctx context.Context) {
	sig := settings.FileSignature(h.ConfigPath)
	w := &h.cfgWatch
	w.mu.Lock()
	switch {
	case sig == "":
		// Gone, or between a writer's two steps: the next look decides.
		w.pending = ""
		w.mu.Unlock()
		return
	case sig == w.known:
		w.pending = ""
		w.mu.Unlock()
		return
	case sig == w.refused:
		w.mu.Unlock()
		return
	case sig != w.pending:
		// New since the last look.  Wait one more: an editor or a
		// configuration manager may still be writing.
		w.pending = sig
		w.mu.Unlock()
		return
	}
	w.pending = ""
	w.mu.Unlock()
	h.adoptConfigFile(ctx, sig)
}

// adoptConfigFile reads the changed file and makes it the live settings.
func (h *Handler) adoptConfigFile(ctx context.Context, sig string) {
	// Under the lock the saves take: a save cannot land between this read
	// and the publish, and what a save has just written is the daemon's own.
	settingsMu.Lock()
	if now := settings.FileSignature(h.ConfigPath); now != sig {
		// Written again meanwhile -- by a save of ours (known says so at the
		// next look) or by the same writer, which the next looks wait out.
		settingsMu.Unlock()
		return
	}
	loaded, err := settings.Load(h.ConfigPath)
	if err != nil {
		settingsMu.Unlock()
		h.cfgWatch.mu.Lock()
		h.cfgWatch.refused = sig
		h.cfgWatch.mu.Unlock()
		log.Printf("config watch: %s changed on disk and does not load (%v); the settings in use are kept until it does", h.ConfigPath, err)
		return
	}
	before := *h.cfg()
	same := false
	if a, errA := settings.SavedYAML(before); errA == nil {
		if b, errB := settings.SavedYAML(loaded); errB == nil {
			same = a == b
		}
	}
	if same {
		// Touched, re-commented, reformatted: the same settings.
		settingsMu.Unlock()
		h.SetConfigSignature(sig)
		return
	}
	h.settingsPtr.Store(&loaded)
	h.SetConfigSignature(sig)
	settingsMu.Unlock()

	h.applyLiveSettings(loaded)
	rendered := "nginx's configuration is rendered from it; reload nginx to apply"
	if err := nginxconf.RenderFor(loaded, "", h.Version, nginxconf.RenderCause{Kind: nginxconf.RenderByConfigFile}); err != nil {
		rendered = "rendering nginx's configuration from it FAILED: " + err.Error()
	}
	beforeYAML, _ := auditSnapshotYAML(before)
	afterYAML, _ := auditSnapshotYAML(loaded)
	auditWriteSettingsSave(ctx, h, 0, user.ConfigFileActor, "_file", beforeYAML, afterYAML)
	log.Printf("config watch: %s changed on disk (not through the admin) and was re-read; %s", h.ConfigPath, rendered)
	if loaded.Server != before.Server || loaded.DB != before.DB {
		log.Printf("config watch: the listen address or the database settings changed in %s; those are read when unmask starts -- restart unmask to apply them", h.ConfigPath)
	}
}

// applyLiveSettings tells the components that keep a copy of some settings
// about cur: what a settings save does after it has published, and what the
// config watch does after it has adopted a changed file.  One function, so
// the two cannot come to apply different things.
func (h *Handler) applyLiveSettings(cur settings.Settings) {
	// ipgeo hot-swap (= picks up mmdb path changes immediately, no restart)
	if h.IPGeo != nil {
		h.IPGeo.Reload(cur.IPGeo.MMDBPath, cur.IPGeo.MMDBASNPath)
	}
	// classify hot-swap: rebuild the filter of crawlers set one by one so
	// the next IsBot call reflects the settings.
	classify.SetUpstreamUnrescued(nginxconf.UpstreamUnrescued(cur.Nginx))
	// notifier hot-swap (= picks up URL / format / threshold changes immediately)
	if h.Notifier != nil {
		h.Notifier.SetConfig(NotifierConfigFrom(cur.Notifications, h.HostID))
	}
	// outbound policy (= where the daemon's own connections may go)
	outbound.SetPolicy(outbound.Policy{DenyPrivate: cur.Outbound.DenyPrivate, AllowLoopback: cur.Outbound.AllowLoopback})
	// mailer hot-swap (= picks up host/auth changes immediately)
	if h.Mailer != nil {
		h.Mailer.SetConfig(MailConfigFrom(cur.SMTP, h.HostID))
	}
}
