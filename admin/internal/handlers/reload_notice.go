package handlers

import (
	"fmt"
	"html/template"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
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
	// Restart: nginx runs an older module than the file on disk, so a reload
	// would keep that module (and could not read a configuration that needs
	// the new one); the help names the restart (RestartCmd) in place of the
	// reload.  TitleKey: the tip's title -- reload_notice.title, or
	// title_module when the module alone is behind (MsgKey msg_module, and
	// WrittenHTML is when the module file was placed).
	Restart    bool
	RestartCmd string
	TitleKey   string
	// MsgKey: the sentence for why the configuration was written -- a save
	// (reload_notice.msg_saved), an automatic update (msg_auto), the command
	// line (msg_cli) -- or reload_notice.msg when the render left no record.
	MsgKey string
	// CauseHTML: the cause in the operator's words, escaped, for MsgKey's
	// second %s; "" with reload_notice.msg.
	CauseHTML string
	// Changes: what the render changed, block by block, in the operator's
	// words ("国判定の範囲: 変更 2 行、追加 2 行"), for the help tip.
	Changes []string
}

// reloadNotice: nil unless the render watch says nginx logs an older
// configuration than the one written.
func (h *Handler) reloadNotice(lang i18n.Lang) *ReloadNotice {
	if h == nil || h.RenderWatch == nil {
		return nil
	}
	// Settle, not State: a page render is also when the reload marker the
	// render left is removed, once nginx is seen running the render.
	st := h.RenderWatch.Settle()
	if !st.Pending && !st.ModulePending {
		return nil
	}
	g := h.cfg().Gateway
	g.Normalize()
	timeHTML := func(t time.Time) template.HTML {
		t = t.UTC()
		return template.HTML(fmt.Sprintf(`<time class="js-datetime" data-ts="%d">%s</time>`,
			t.Unix(), t.Format(time.DateTime+" UTC")))
	}
	n := &ReloadNotice{
		Gateway:  g.Active(),
		Restart:  st.ModulePending && !g.Active(),
		TitleKey: "reload_notice.title",
		MsgKey:   "reload_notice.msg",
	}
	if n.Restart {
		n.RestartCmd = nginxRestartCommand()
	}
	if !st.Pending {
		// The module alone: the configuration nginx runs is the one on
		// disk, the module is not.
		n.WrittenHTML = timeHTML(st.ModulePlaced)
		n.TitleKey = "reload_notice.title_module"
		n.MsgKey = "reload_notice.msg_module"
		return n
	}
	n.WrittenHTML = timeHTML(st.Written)
	// Why, and what moved: the record the render kept beside the files,
	// when it is about this render (written at about the same time).
	rec, ok := nginxconf.ReadRenderRecord(h.renderOutDir())
	if !ok || !rec.About(st.Written) {
		return n
	}
	n.Changes = h.renderChangeLines(lang, rec.Changes)
	cause := h.renderCauseText(lang, rec.Cause)
	if cause == "" {
		return n
	}
	switch rec.Cause.Kind {
	case nginxconf.RenderBySettings, nginxconf.RenderByRestore, nginxconf.RenderByReview:
		n.MsgKey = "reload_notice.msg_saved"
	case nginxconf.RenderByIPRange, nginxconf.RenderByGeoIP:
		n.MsgKey = "reload_notice.msg_auto"
		// The automatic update's first change, inline: what the sync moved
		// is the whole answer to "why is this here".
		if len(n.Changes) > 0 {
			cause += i18n.T(lang, "reload_notice.cause_sep") + n.Changes[0]
		}
	case nginxconf.RenderByCLI:
		n.MsgKey = "reload_notice.msg_cli"
	}
	n.CauseHTML = template.HTMLEscapeString(cause)
	return n
}

// nginxRestartCommand: how nginx is restarted on this host -- through
// systemd where it runs the system, the init script's `service` elsewhere.
func nginxRestartCommand() string {
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		return "sudo systemctl restart nginx"
	}
	return "sudo service nginx restart"
}

// renderOutDir: where the configuration is rendered (settings, or the
// package default), the dir the render record and watch state live in.
func (h *Handler) renderOutDir() string {
	if d := strings.TrimSpace(h.cfg().Nginx.OutputDir); d != "" {
		return d
	}
	return "/var/lib/unmask/nginx"
}

// renderCauseText: the cause in the operator's words -- the settings tab a
// save was made on, what the sync wrote, the update that ran.
func (h *Handler) renderCauseText(lang i18n.Lang, c nginxconf.RenderCause) string {
	switch c.Kind {
	case nginxconf.RenderBySettings:
		return settingsSectionTitle(lang, c.Detail)
	case nginxconf.RenderByRestore:
		return i18n.T(lang, "reload_notice.cause.restore")
	case nginxconf.RenderByReview:
		return i18n.T(lang, "reload_notice.cause.review")
	case nginxconf.RenderByIPRange:
		what := ""
		if c.Detail == "relay" {
			what = i18n.T(lang, "reload_notice.cause.relay")
		} else if n, ok := strings.CutPrefix(c.Detail, "sources:"); ok {
			if k, err := strconv.Atoi(n); err == nil {
				what = i18n.Tf(lang, "reload_notice.cause.sources", k)
			}
		}
		if what == "" {
			return i18n.T(lang, "reload_notice.cause.iprange")
		}
		return i18n.T(lang, "reload_notice.cause.iprange") + ": " + what
	case nginxconf.RenderByGeoIP:
		return i18n.T(lang, "reload_notice.cause.geoip")
	case nginxconf.RenderByCLI:
		return i18n.T(lang, "reload_notice.cause.cli")
	}
	return ""
}

// settingsSectionTitle: the tab's title for a save's section id
// ("custom-rules", "custom-rules-add"): the settings.tab.* word, found by
// dropping the id's last parts until one names a tab; the id itself when
// none does.
func settingsSectionTitle(lang i18n.Lang, section string) string {
	parts := strings.Split(strings.TrimSpace(section), "-")
	for n := len(parts); n > 0; n-- {
		key := "settings.tab." + strings.Join(parts[:n], "_")
		if t := i18n.T(lang, key); t != key {
			return t
		}
	}
	return section
}

// renderChangeLines: the changes in the operator's words, the block by the
// page's name for it (or as the file names it) and the lines that changed,
// came and went -- only the counts that are not zero.
func (h *Handler) renderChangeLines(lang i18n.Lang, changes []nginxconf.RenderChange) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		name := c.Block
		if k := nginxconf.BlockLabelKey(c.Block); k != "" {
			name = i18n.T(lang, "reload_notice.block."+k)
		}
		if c.File != "http.inc" {
			name = c.File + " " + name
		}
		var parts []string
		if c.Changed > 0 {
			parts = append(parts, i18n.Tf(lang, "reload_notice.n_changed", c.Changed))
		}
		if c.Added > 0 {
			parts = append(parts, i18n.Tf(lang, "reload_notice.n_added", c.Added))
		}
		if c.Removed > 0 {
			parts = append(parts, i18n.Tf(lang, "reload_notice.n_removed", c.Removed))
		}
		out = append(out, name+": "+strings.Join(parts, i18n.T(lang, "reload_notice.n_sep")))
	}
	return out
}
