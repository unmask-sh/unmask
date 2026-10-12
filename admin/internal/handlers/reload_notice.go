package handlers

import (
	"fmt"
	"html/template"
	"time"
)

// ReloadNotice: the notice that nginx has not loaded the configuration the
// admin last wrote (partial_reload_notice.html, part of header_tools).
type ReloadNotice struct {
	// WrittenHTML: when the waiting configuration was written, as a <time>
	// the page's script shows in the operator's time zone.
	WrittenHTML template.HTML
	// Gateway: the container gateway reloads nginx by itself, so a notice
	// there means that reload did not happen (the configuration is refused).
	Gateway bool
}

// reloadNotice: nil unless the render watch says nginx logs an older
// configuration than the one written.
func (h *Handler) reloadNotice() *ReloadNotice {
	if h == nil || h.RenderWatch == nil {
		return nil
	}
	st := h.RenderWatch.State()
	if !st.Pending {
		return nil
	}
	g := h.cfg().Gateway
	g.Normalize()
	w := st.Written.UTC()
	return &ReloadNotice{
		WrittenHTML: template.HTML(fmt.Sprintf(`<time class="js-datetime" data-ts="%d">%s</time>`,
			w.Unix(), w.Format(time.DateTime+" UTC"))),
		Gateway: g.Active(),
	}
}
