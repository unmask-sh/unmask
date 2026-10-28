// External webhook notifications (= Slack / Discord / generic JSON).
//
// Design principles:
//   - Just POST to a webhook URL via stdlib net/http.  Zero SDK dependencies.
//   - 3 format adapters:
//     slack     : { text, blocks }    Slack webhook + Mattermost compat
//     discord   : { content, embeds }
//     generic   : POST a straightforward JSON { event, ip, ja4, ua, ts, ... }
//   - Send failures are logged only (= ban / challenge is not blocked).  No retry.
//   - Two hooks at most: URL, and CriticalURL for the alerts whose severity
//     reaches a floor (severity.go), so one channel can hold what needs a
//     person now.
//   - Notification event kinds:
//     ban_created     : auto-BAN from a honeypot trip, or admin manual BAN
//     challenge_burst : five minutes of challenges far above the hour before (burst.go)
//     preview_challenged : an hour's link-preview fetches stopped by a country or ASN rule (preview.go)
//   - A third channel, the admin's own notification list (Inbox, the notice
//     package), gets every event whatever the switches below say: they are
//     about how much mail and webhook traffic the operator wants, and the
//     list is the one channel every install has.
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	FormatSlack   = "slack"
	FormatDiscord = "discord"
	FormatGeneric = "generic"

	EventBanCreated     = "ban_created"
	EventChallengeBurst = "challenge_burst"
	EventOverBlock      = "over_block"
	EventAdvisorDigest  = "advisor_digest"
)

// Config: notification settings.  Disabled mutes both channels; the
// per-channel flags mute one transport while its settings stay intact.
// A webhook also needs a non-empty URL, mail a configured Mailer.  A second
// hook, CriticalURL, takes the alerts of severity CriticalMinSeverity and
// above when it is set (severity.go).
type Config struct {
	Disabled            bool
	URL                 string
	Format              string
	CriticalURL         string   // the hook for the critical alerts; "" = URL takes every alert
	CriticalMinSeverity string   // the lowest severity CriticalURL takes: "crit" (default) or "warn"
	Sites               string   // label to show in notification messages (= arbitrary operator-defined site name)
	BanEvents           bool     // send ban_created (= honeypot / manual)
	ChallengeBurst      bool     // send challenge_burst
	BurstThresholdPer5m int      // the fewest challenges in 5 minutes that can be a burst (burst.go).  0 disables
	WebhookDisabled     bool     // pause the webhook channel (URL kept)
	MailDisabled        bool     // pause alert mail (SMTP transport stays up for password reset)
	MailTo              []string // explicit alert recipients; empty = resolve via mailGetTo (admin users)
	// Lang: the language of mail written per language (the over-block
	// alert) for a recipient whose own is not known -- an address in MailTo
	// that is no account's, or an account that has not used the admin yet
	// ("en" when empty).  Other alert mail is English.
	Lang string
}

// Recipient is an address alert mail goes to, and the language mail written
// per language reaches it in: the account's, as it last used the admin (""
// when unknown -- then Config.Lang).
type Recipient struct{ Email, Lang string }

// MailSender: thin interface used by notifier for mail sending.  Taking
// *mail.Mailer directly would cause an import cycle, so we accept an
// interface.  Sends the same subject / body to every recipient returned by
// resolveRecipients.  If both are nil, the mail feature is disabled.
type MailSender interface {
	Enabled() bool
	Send(to, subject, body string) error
	// SendAlt sends a text part and an HTML part saying the same thing.
	SendAlt(to, subject, text, html string) error
}

// Inbox is the admin's own notification list (internal/notice): it gets
// every event's name and fields -- the same the generic webhook payload
// carries -- so what the list shows and what the webhook sent are one thing.
// An interface, like MailSender, so this package does not import the
// database.
type Inbox interface {
	Add(event string, fields map[string]any)
}

// Notifier: external webhook client.  Every method is nil-safe.
type Notifier struct {
	cfg    Config
	client *http.Client

	// challenge_burst: the challenges per five minutes and the hour before
	// them (burst.go).
	mu    sync.Mutex
	burst burstState
	// preview_challenged: the hour's link-preview fetches a country or ASN
	// rule stopped (preview.go).
	preview previewState
	// now is the clock the burst count reads; nil is time.Now (a test sets it).
	now func() time.Time

	// For config hot-swap.
	dynamic atomic.Pointer[Config]

	// Optional mail integration.  If both are nil, mail notification is skipped.
	mailer    MailSender
	mailGetTo func() []Recipient // recipient list resolver (= wraps UserRepo.AlertRecipients)
	// mailLangOf: the language of the account an address belongs to ("" when
	// none), for the addresses in Config.MailTo.
	mailLangOf func(email string) string

	// inbox: the admin's notification list; nil when the daemon has no
	// database.
	inbox Inbox
}

// New: cfg is passed by value (= hot-swap later via SetConfig).
func New(cfg Config) *Notifier {
	n := &Notifier{
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Second},
	}
	n.dynamic.Store(&cfg)
	return n
}

// SetConfig: call after settings are saved.  No lock needed (= atomic pointer swap).
func (n *Notifier) SetConfig(cfg Config) {
	if n == nil {
		return
	}
	n.dynamic.Store(&cfg)
}

// WithMail: configure mail notifications in parallel with the webhook.  If
// m.Enabled() is true, alert mail goes to every recipient returned by
// resolveTo() -- or to Config.MailTo, when the operator set addresses there,
// each in the language langOf finds for it (nil: Config.Lang for all).  If
// either m or resolveTo is nil, mail notification is skipped.
func (n *Notifier) WithMail(m MailSender, resolveTo func() []Recipient, langOf func(email string) string) *Notifier {
	if n == nil {
		return n
	}
	n.mailer = m
	n.mailGetTo = resolveTo
	n.mailLangOf = langOf
	return n
}

// WithInbox keeps every event for the admin's notification list, beside the
// webhook and the mail.
func (n *Notifier) WithInbox(ib Inbox) *Notifier {
	if n == nil {
		return n
	}
	n.inbox = ib
	return n
}

// toInbox hands an event to the list.  Off the caller's path, like the
// other channels: a ban's caller does not wait on the database.
func (n *Notifier) toInbox(event string, fields map[string]any) {
	if n == nil || n.inbox == nil {
		return
	}
	go n.inbox.Add(event, fields)
}

// recipients resolves who alert mail goes to now, each with a language.
func (n *Notifier) recipients(cfg Config) []Recipient {
	var out []Recipient
	if len(cfg.MailTo) > 0 {
		for _, e := range cfg.MailTo {
			r := Recipient{Email: e}
			if n.mailLangOf != nil {
				r.Lang = n.mailLangOf(e)
			}
			out = append(out, r)
		}
	} else if n.mailGetTo != nil {
		out = n.mailGetTo()
	}
	for i := range out {
		if out[i].Lang == "" {
			out[i].Lang = cfg.mailLang()
		}
	}
	return out
}

// mailLang: the default language of alert mail.
func (c Config) mailLang() string {
	if c.Lang == "" {
		return "en"
	}
	return c.Lang
}

func (n *Notifier) currentCfg() Config {
	if n == nil {
		return Config{Disabled: true}
	}
	if p := n.dynamic.Load(); p != nil {
		return *p
	}
	return n.cfg
}

// BanCreated: called from places like the ban manager.  ip / ja4 / source / reason / bannedBy.
// Sends webhook + mail in parallel (= no-op when both are disabled).
// The BanEvents flag is a shared switch for webhook / mail.  Mail is still
// sent even if the webhook URL is empty.  The admin's list gets the ban
// whatever the switches say (it folds an hour's bans into one line).
func (n *Notifier) BanCreated(ip, ja4, source, reason, bannedBy string) {
	if n == nil {
		return
	}
	cfg := n.currentCfg()
	fields := map[string]any{
		"event":     EventBanCreated,
		"ip":        ip,
		"ja4":       ja4,
		"source":    source,
		"reason":    reason,
		"banned_by": bannedBy,
		"site":      cfg.Sites,
		"ts":        time.Now().Unix(),
	}
	fields["severity"] = Severity(EventBanCreated, fields)
	n.toInbox(EventBanCreated, fields)
	if cfg.Disabled || !cfg.BanEvents {
		return
	}
	text := formatBanText(ip, ja4, source, reason, bannedBy, cfg.Sites)
	if u := cfg.hookFor(EventBanCreated, fields); u != "" {
		go n.send(u, cfg.Format, EventBanCreated, fields, text)
	}
	subject := "[unmask] BAN: " + ip
	if cfg.Sites != "" {
		subject = "[unmask:" + cfg.Sites + "] BAN: " + ip
	}
	go n.sendMail(subject, text)
}

// sendMail: send the same mail to every alert recipient.  Recipients come
// from cfg.MailTo when the operator set one explicitly; otherwise from the
// mailGetTo resolver (the admin users' emails).  no-op if the mailer is
// nil / disabled, or the mail channel is paused (MailDisabled mutes alert
// mail only — the mailer itself stays up for password reset).  Failures are
// logged only.
func (n *Notifier) sendMail(subject, body string) {
	if n == nil || n.mailer == nil || !n.mailer.Enabled() {
		return
	}
	cfg := n.currentCfg()
	if cfg.MailDisabled {
		return
	}
	for _, r := range n.recipients(cfg) {
		if r.Email == "" {
			continue
		}
		if err := n.mailer.Send(r.Email, subject, body); err != nil {
			log.Printf("notifier mail to %s: %v", r.Email, err)
		}
	}
}

// sendMailLocalized sends alert mail written for each recipient's language:
// build returns the subject, the text and the HTML for a language.  Same
// gating as sendMail.
func (n *Notifier) sendMailLocalized(build func(lang string) (subject, text, html string)) {
	if n == nil || n.mailer == nil || !n.mailer.Enabled() {
		return
	}
	cfg := n.currentCfg()
	if cfg.MailDisabled {
		return
	}
	for _, r := range n.recipients(cfg) {
		if r.Email == "" {
			continue
		}
		subject, text, html := build(r.Lang)
		if err := n.mailer.SendAlt(r.Email, subject, text, html); err != nil {
			log.Printf("notifier mail to %s: %v", r.Email, err)
		}
	}
}

// TestSend: for the settings UI "test send" button.  Fires a test event.
func (n *Notifier) TestSend(ctx context.Context) error {
	if n == nil {
		return fmt.Errorf("notifier nil")
	}
	cfg := n.currentCfg()
	if cfg.URL == "" {
		return fmt.Errorf("webhook URL is empty")
	}
	body, contentType := buildPayload(cfg.Format, "test_event", map[string]any{
		"event": "test_event",
		"site":  cfg.Sites,
		"ts":    time.Now().Unix(),
	}, "[OK] unmask webhook test"+siteSuffix(cfg.Sites))
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "unmask/0.1 (+webhook)")
	resp, err := n.client.Do(req)
	if err != nil {
		return withoutURL(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d%s", resp.StatusCode, bodyHint(resp.Body))
	}
	return nil
}

// withoutURL drops the request URL from a client error.  A webhook URL is its
// own secret (a Slack or Discord hook's token is in the path), and these
// errors reach the settings page and the daemon log.  What remains says what
// went wrong: "Post: dial tcp: lookup hooks.example: no such host".
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// bodyHint: the start of a refusing webhook's answer, as ": <text>" for the
// error, or "" when it sent none.  The body says more than the status -- a
// Slack hook answers 404 "no_service" for one that was removed and 403
// "invalid_token" for a wrong token.  One line, at most 200 bytes.
func bodyHint(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 200))
	s := strings.Join(strings.Fields(strings.ToValidUTF8(string(b), "")), " ")
	if s == "" {
		return ""
	}
	return ": " + s
}

// send posts one alert to the hook at hook, in format.  The caller chose the
// hook (Config.hookFor) and runs this off its own path.
func (n *Notifier) send(hook, format, event string, fields map[string]any, text string) {
	body, contentType := buildPayload(format, event, fields, text)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook, bytes.NewReader(body))
	if err != nil {
		log.Printf("notifier %s build request: %v", event, err)
		return
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "unmask/0.1 (+webhook)")
	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("notifier %s POST: %v", event, withoutURL(err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("notifier %s response: HTTP %d%s", event, resp.StatusCode, bodyHint(resp.Body))
	}
}

// buildPayload: build the message body per format.  Returns JSON-marshalled
// bytes + Content-Type.
func buildPayload(format, event string, fields map[string]any, text string) ([]byte, string) {
	switch format {
	case FormatSlack:
		body, _ := json.Marshal(map[string]any{"text": text})
		return body, "application/json"
	case FormatDiscord:
		body, _ := json.Marshal(map[string]any{"content": text})
		return body, "application/json"
	default: // generic
		body, _ := json.Marshal(fields)
		return body, "application/json"
	}
}

func formatBanText(ip, ja4, source, reason, bannedBy, site string) string {
	var b strings.Builder
	b.WriteString("[BLOCK] unmask: ban created")
	b.WriteString(siteSuffix(site))
	b.WriteString("\n• ip: `")
	b.WriteString(ip)
	b.WriteString("`")
	if ja4 != "" {
		b.WriteString("\n• ja4: `")
		b.WriteString(ja4)
		b.WriteString("`")
	}
	b.WriteString("\n• source: ")
	b.WriteString(source)
	if reason != "" {
		b.WriteString("\n• reason: ")
		b.WriteString(reason)
	}
	if bannedBy != "" {
		b.WriteString("\n• by: ")
		b.WriteString(bannedBy)
	}
	return b.String()
}

func siteSuffix(site string) string {
	if site == "" {
		return ""
	}
	return " (site: " + site + ")"
}
