package notifier

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// OverBlockReport is what the over-block circuit breaker saw when it changed
// state: visitors stuck at the challenge (handlers.checkOverBlock).
type OverBlockReport struct {
	Tripped bool
	// Minutes: the window read.  Stuck of Loaders (StuckPct percent) could not
	// get through: Rechallenged were shown the challenge again right after
	// passing, VerifyFailed failed verification.
	Minutes                         int
	Stuck, Loaders, StuckPct        int
	Rechallenged, VerifyFailed      int
	Passed, Serves, ServeIPs, Loads int
	// MinStuck / MinPct: where the breaker trips.
	MinStuck, MinPct int
	Examples         []OverBlockExample
	AutoPassthrough  bool
	// AdminURL: the admin's address, scheme to base path ("https://host/unmask"),
	// for the link to the bot hunt; "" when it is not known, and the mail says
	// where to look instead.
	AdminURL string
}

// OverBlockExample is one stuck address.
type OverBlockExample struct {
	IP, Site, Path             string
	Rechallenged, VerifyFailed int
}

// OverBlock: the over-block circuit breaker changed state.  Called only on a
// transition (trip or clear), so there is no flap to throttle.
//
// The mail says, in the reader's language, what is happening, the figures it
// was decided on, the addresses stuck, whether protection changed, and where
// to look -- the alert it replaces was one line of "browser-grade challenge
// serves" and a ratio, and stated a loop as fact on an average that one
// scanner had lifted (2026-10-07).
func (n *Notifier) OverBlock(r OverBlockReport) {
	if n == nil {
		return
	}
	cfg := n.currentCfg()
	if cfg.Disabled {
		return
	}
	if cfg.URL != "" && !cfg.WebhookDisabled {
		fields := map[string]any{
			"event":            EventOverBlock,
			"tripped":          r.Tripped,
			"window_minutes":   r.Minutes,
			"stuck":            r.Stuck,
			"ran_challenge":    r.Loaders,
			"stuck_percent":    r.StuckPct,
			"rechallenged":     r.Rechallenged,
			"verify_failed":    r.VerifyFailed,
			"auto_passthrough": r.AutoPassthrough,
			"site":             cfg.Sites,
			"ts":               time.Now().Unix(),
		}
		lang := i18n.Lang(cfg.mailLang())
		go n.send(cfg, EventOverBlock, fields, overBlockLine(r, lang, cfg.Sites))
	}
	go n.sendMailLocalized(func(lang string) (string, string, string) {
		return renderOverBlock(r, i18n.Lang(lang), cfg.Sites, r.AdminURL)
	})
}

// overBlockLine is the webhook's one line.
func overBlockLine(r OverBlockReport, lang i18n.Lang, site string) string {
	head := "[CRITICAL] "
	if !r.Tripped {
		head = "[OK] "
	}
	return head + overBlockTitle(r, lang) + " " + overBlockSummary(r, lang) + siteSuffix(site)
}

func overBlockTitle(r OverBlockReport, lang i18n.Lang) string {
	if r.Tripped {
		return i18n.T(lang, "mail.overblock.title_tripped")
	}
	return i18n.T(lang, "mail.overblock.title_cleared")
}

func overBlockSummary(r OverBlockReport, lang i18n.Lang) string {
	if r.Tripped {
		return i18n.Tf(lang, "mail.overblock.summary_tripped", r.Minutes, r.Stuck, r.Loaders, r.StuckPct)
	}
	return i18n.Tf(lang, "mail.overblock.summary_cleared", r.Minutes, r.Stuck, r.Loaders, r.StuckPct, r.MinStuck, r.MinPct)
}

// overBlockMail is what both parts of the mail are made from.
type overBlockMail struct {
	Tripped              bool
	Site, Title, Summary string
	Reasons              []string
	ExamplesH            string
	Examples             []overBlockRow
	Volume, Protection   string
	ChecksH              string
	Checks               []overBlockCheck
	Why, Footer          string
	HuntURL, HuntLabel   string
}

type overBlockRow struct{ Addr, Where, Marks string }

type overBlockCheck struct{ Text string }

// renderOverBlock writes the mail for one language: subject, text, HTML.
func renderOverBlock(r OverBlockReport, lang i18n.Lang, site, adminURL string) (subject, text, html string) {
	m := overBlockMail{
		Tripped: r.Tripped,
		Site:    site,
		Title:   overBlockTitle(r, lang),
		Summary: overBlockSummary(r, lang),
		Volume:  i18n.Tf(lang, "mail.overblock.volume", r.Serves, r.ServeIPs, r.Loads, r.Passed),
		Footer:  i18n.T(lang, "mail.overblock.footer"),
	}
	if site == "" {
		subject = "[unmask] " + m.Title
	} else {
		subject = "[unmask:" + site + "] " + m.Title
	}
	if adminURL != "" {
		m.HuntURL = strings.TrimRight(adminURL, "/") + "/admin/hunt/?range=1h"
		m.HuntLabel = i18n.T(lang, "mail.overblock.hunt_link")
	}
	if r.Tripped {
		if r.Rechallenged > 0 {
			m.Reasons = append(m.Reasons, i18n.Tf(lang, "mail.overblock.reason_rechallenged", r.Rechallenged))
		}
		if r.VerifyFailed > 0 {
			m.Reasons = append(m.Reasons, i18n.Tf(lang, "mail.overblock.reason_verify", r.VerifyFailed))
		}
		m.Why = i18n.Tf(lang, "mail.overblock.why", r.MinStuck, r.MinPct)
		if r.AutoPassthrough {
			m.Protection = i18n.T(lang, "mail.overblock.protection_passthrough")
		} else {
			m.Protection = i18n.T(lang, "mail.overblock.protection_unchanged")
		}
		m.ChecksH = i18n.T(lang, "mail.overblock.checks_h")
		if m.HuntURL == "" {
			m.Checks = append(m.Checks, overBlockCheck{Text: i18n.T(lang, "mail.overblock.check_hunt")})
		}
		m.Checks = append(m.Checks,
			overBlockCheck{Text: i18n.T(lang, "mail.overblock.check_doctor")},
			overBlockCheck{Text: i18n.T(lang, "mail.overblock.check_restart")})
		if len(r.Examples) > 0 {
			m.ExamplesH = i18n.T(lang, "mail.overblock.examples_h")
			for _, e := range r.Examples {
				var marks []string
				if e.Rechallenged > 0 {
					marks = append(marks, i18n.Tf(lang, "mail.overblock.mark_rechallenged", e.Rechallenged))
				}
				if e.VerifyFailed > 0 {
					marks = append(marks, i18n.Tf(lang, "mail.overblock.mark_verify", e.VerifyFailed))
				}
				m.Examples = append(m.Examples, overBlockRow{Addr: e.IP, Where: e.Site + e.Path, Marks: strings.Join(marks, ", ")})
			}
		}
	}
	return subject, overBlockText(m), overBlockHTML(m)
}

func overBlockText(m overBlockMail) string {
	var b strings.Builder
	b.WriteString(m.Title + "\n\n" + m.Summary + "\n")
	for _, s := range m.Reasons {
		b.WriteString("  - " + s + "\n")
	}
	if len(m.Examples) > 0 {
		b.WriteString("\n" + m.ExamplesH + "\n")
		w := 0
		for _, e := range m.Examples {
			w = max(w, len(e.Addr))
		}
		for _, e := range m.Examples {
			fmt.Fprintf(&b, "  %-*s  %s  %s\n", w, e.Addr, e.Where, e.Marks)
		}
	}
	b.WriteString("\n" + m.Volume + "\n")
	if m.Protection != "" {
		b.WriteString(m.Protection + "\n")
	}
	if m.Why != "" {
		b.WriteString("\n" + m.Why + "\n")
	}
	if m.Tripped {
		b.WriteString("\n" + m.ChecksH + "\n")
		if m.HuntURL != "" {
			b.WriteString("  - " + m.HuntLabel + ": " + m.HuntURL + "\n")
		}
		for _, c := range m.Checks {
			b.WriteString("  - " + c.Text + "\n")
		}
	} else if m.HuntURL != "" {
		b.WriteString("\n" + m.HuntLabel + ": " + m.HuntURL + "\n")
	}
	b.WriteString("\n-- \n" + m.Footer + "\n")
	return b.String()
}

// The HTML part: one column, inline styles only (a mail client drops a style
// sheet), no images and nothing fetched.
var overBlockTmpl = template.Must(template.New("overblock").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:0;background:#f1f5f9">
<div style="max-width:640px;margin:0 auto;padding:24px 16px;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,'Hiragino Sans','Noto Sans JP',sans-serif;font-size:14px;line-height:1.6;color:#0f172a">
<div style="background:#ffffff;border-radius:8px;border-left:4px solid {{if .Tripped}}#dc2626{{else}}#16a34a{{end}};padding:16px 20px">
<p style="margin:0 0 4px;font-size:12px;color:#64748b">unmask{{if .Site}} &middot; {{.Site}}{{end}}</p>
<h1 style="margin:0 0 10px;font-size:18px;line-height:1.4">{{.Title}}</h1>
<p style="margin:0">{{.Summary}}</p>
{{if .Reasons}}<ul style="margin:8px 0 0;padding-left:20px">{{range .Reasons}}<li>{{.}}</li>{{end}}</ul>{{end}}
</div>
{{if .Examples}}<h2 style="margin:20px 0 6px;font-size:14px">{{.ExamplesH}}</h2>
<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;background:#ffffff;border-radius:8px;font-size:13px">
{{range .Examples}}<tr><td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;font-family:ui-monospace,Menlo,Consolas,monospace;white-space:nowrap">{{.Addr}}</td><td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;word-break:break-all">{{.Where}}</td><td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;white-space:nowrap">{{.Marks}}</td></tr>
{{end}}</table>{{end}}
<p style="margin:16px 0 0;color:#334155">{{.Volume}}</p>
{{if .Protection}}<p style="margin:6px 0 0;color:#334155">{{.Protection}}</p>{{end}}
{{if .Why}}<p style="margin:12px 0 0;color:#475569;font-size:13px">{{.Why}}</p>{{end}}
{{if .Tripped}}<h2 style="margin:20px 0 6px;font-size:14px">{{.ChecksH}}</h2>
<ul style="margin:0;padding-left:20px">
{{if .HuntURL}}<li><a href="{{.HuntURL}}" style="color:#1d4ed8">{{.HuntLabel}}</a></li>{{end}}
{{range .Checks}}<li>{{.Text}}</li>{{end}}
</ul>{{else if .HuntURL}}<p style="margin:16px 0 0"><a href="{{.HuntURL}}" style="color:#1d4ed8">{{.HuntLabel}}</a></p>{{end}}
<p style="margin:24px 0 0;font-size:12px;color:#94a3b8">{{.Footer}}</p>
</div>
</body></html>
`))

func overBlockHTML(m overBlockMail) string {
	var b bytes.Buffer
	if err := overBlockTmpl.Execute(&b, m); err != nil {
		return "<pre>" + template.HTMLEscapeString(overBlockText(m)) + "</pre>"
	}
	return b.String()
}
