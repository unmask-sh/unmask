package handlers

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/notice"
	"github.com/unmask-sh/unmask/admin/internal/safe"
)

// failsafeWatchEvery is how often the daemon looks at the markers beside the
// rendered files: the plugin's fail-safe marker, and the render's own
// "nginx has not loaded this yet".
const failsafeWatchEvery = 30 * time.Second

// failsafeSeen is the last look at the fail-safe marker, so a notice is
// written when it comes and when it goes, not on every look.
type failsafeSeen struct {
	mu     sync.Mutex
	known  bool // looked at least once since the daemon started
	active bool
}

// RunNativeFailsafeWatch keeps two things current until ctx ends.  The reload
// marker: once the access log shows nginx running the render on disk, the
// marker the render left for it goes (renderwatch.Settle), without waiting
// for an admin page to ask.  And the notification list: when the plugin's
// fail-safe strips the nginx module (place-module.sh leaves
// nginxconf.FailsafeMarker and the configuration is rendered without the
// module), a row says protection is off; when the marker goes, a row says it
// is back.  The first look after a start compares with the list's last word,
// so a restart in either state repeats nothing.
func (h *Handler) RunNativeFailsafeWatch(ctx context.Context) {
	for {
		func() {
			defer safe.Recover("native-failsafe-watch")
			h.failsafeTick(ctx)
		}()
		select {
		case <-ctx.Done():
			return
		case <-time.After(failsafeWatchEvery):
		}
	}
}

// failsafeTick is one look: settle the reload marker, notice the fail-safe.
func (h *Handler) failsafeTick(ctx context.Context) {
	if h.RenderWatch != nil {
		h.RenderWatch.Settle()
	}
	h.noticeFailsafe(ctx, h.renderOutDir())
}

// noticeFailsafe writes the row for a change in the fail-safe marker in dir.
func (h *Handler) noticeFailsafe(ctx context.Context, dir string) {
	active, reason, since := nginxconf.FailsafeState(dir)
	h.failsafe.mu.Lock()
	known, prev := h.failsafe.known, h.failsafe.active
	h.failsafe.known, h.failsafe.active = true, active
	h.failsafe.mu.Unlock()
	if known && prev == active {
		return
	}
	if !known {
		// The first look since the daemon started.  The list's last row on
		// the subject already says what this look found: nothing to add.
		// No row at all and nothing wrong is the usual install -- silence.
		last, ok := h.lastFailsafeNotice(ctx)
		if (ok && last == active) || (!ok && !active) {
			return
		}
	}
	e := notice.Entry{Kind: notice.KindFailsafe, Severity: notice.SeverityInfo, Detail: map[string]any{"active": active}}
	if active {
		e.Severity = notice.SeverityCrit
		if reason != "" {
			e.Detail["reason"] = reason
		}
		if !since.IsZero() {
			e.Detail["since"] = since.Unix()
		}
		log.Printf("native fail-safe: the nginx module is stripped and the configuration is rendered without it (protection off); run `unmask doctor`. %s", reason)
	} else {
		log.Printf("native fail-safe cleared: the nginx module is wired again and the full configuration is rendered; reload nginx")
	}
	if h.Notices == nil {
		return
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := h.Notices.Put(wctx, e); err != nil {
		log.Printf("notice %s: %v", notice.KindFailsafe, err)
	}
}

// lastFailsafeNotice is what the list's newest fail-safe row says (active or
// cleared); ok is false when there is none, or no list.
func (h *Handler) lastFailsafeNotice(ctx context.Context) (active, ok bool) {
	if h.Notices == nil {
		return false, false
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := h.Notices.List(rctx, 0, notice.KindFailsafe, 1, 0)
	if err != nil || len(rows) == 0 {
		return false, false
	}
	return rows[0].Bool("active"), true
}
