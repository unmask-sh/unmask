// External webhook notifications (= Slack / Discord / generic JSON).
//
// Design principles:
//   - Just POST to a webhook URL via stdlib net/http.  Zero SDK dependencies.
//   - 3 format adapters:
//     slack     : { text, blocks }    Slack webhook + Mattermost compat
//     discord   : { content, embeds }
//     generic   : POST a straightforward JSON { event, ip, ja4, ua, ts, ... }
//   - Send failures are logged only (= ban / challenge is not blocked).  No retry.
//   - Notification event kinds:
//     ban_created     : auto-BAN from a honeypot trip, or admin manual BAN
//     challenge_burst : challenge count in the last 5 minutes exceeds the threshold
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
)

// Config: notification settings.  Disabled mutes both channels; the
// per-channel flags mute one transport while its settings stay intact.
// A webhook also needs a non-empty URL, mail a configured Mailer.
type Config struct {
	Disabled            bool
	URL                 string
	Format              string
	Sites               string   // label to show in notification messages (= arbitrary operator-defined site name)
	BanEvents           bool     // send ban_created (= honeypot / manual)
	ChallengeBurst      bool     // send challenge_burst
	BurstThresholdPer5m int      // challenge count in the last 5 minutes.  0 disables
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

// Notifier: external webhook client.  Every method is nil-safe.
type Notifier struct {
	cfg    Config
	client *http.Client

	// 5-minute sliding-window aggregation for challenge_burst + suppression of repeated fires.
	mu             sync.Mutex
	burstCount5m   int64
	burstWindowEnd time.Time
	lastBurstSent  time.Time

	// For config hot-swap.
	dynamic atomic.Pointer[Config]

	// Optional mail integration.  If both are nil, mail notification is skipped.
	mailer    MailSender
	mailGetTo func() []Recipient // recipient list resolver (= wraps UserRepo.AlertRecipients)
	// mailLangOf: the language of the account an address belongs to ("" when
	// none), for the addresses in Config.MailTo.
	mailLangOf func(email string) string
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
// sent even if the webhook URL is empty.
func (n *Notifier) BanCreated(ip, ja4, source, reason, bannedBy string) {
	if n == nil {
		return
	}
	cfg := n.currentCfg()
	if cfg.Disabled || !cfg.BanEvents {
		return
	}
	text := formatBanText(ip, ja4, source, reason, bannedBy, cfg.Sites)
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
	if cfg.URL != "" && !cfg.WebhookDisabled {
		go n.send(cfg, EventBanCreated, fields, text)
	}
	subject := "[unmask] BAN: " + ip
	if cfg.Sites != "" {
		subject = "[unmask:" + cfg.Sites + "] BAN: " + ip
	}
	go n.sendMail(subject, text)
}

// ChallengeServed: call every time the challenge page is served.  5-min
// aggregation → burst event when the threshold is exceeded.
//
// Even if the threshold is exceeded many times within the same window, the
// burst event only fires once per 5 minutes (= flap prevention).  Mail is
// sent even when the webhook URL is empty.
func (n *Notifier) ChallengeServed() {
	if n == nil {
		return
	}
	cfg := n.currentCfg()
	if cfg.Disabled || !cfg.ChallengeBurst || cfg.BurstThresholdPer5m <= 0 {
		return
	}
	now := time.Now()
	n.mu.Lock()
	if now.After(n.burstWindowEnd) {
		n.burstWindowEnd = now.Add(5 * time.Minute)
		n.burstCount5m = 0
	}
	n.burstCount5m++
	count := n.burstCount5m
	thresh := int64(cfg.BurstThresholdPer5m)
	canSend := count == thresh && now.Sub(n.lastBurstSent) >= 5*time.Minute
	if canSend {
		n.lastBurstSent = now
	}
	n.mu.Unlock()
	if !canSend {
		return
	}
	text := fmt.Sprintf("[WARN] challenge fired %d times in the last 5 minutes (= threshold %d exceeded)%s", count, thresh, siteSuffix(cfg.Sites))
	fields := map[string]any{
		"event":        EventChallengeBurst,
		"count_per_5m": count,
		"threshold":    thresh,
		"site":         cfg.Sites,
		"ts":           now.Unix(),
	}
	if cfg.URL != "" && !cfg.WebhookDisabled {
		go n.send(cfg, EventChallengeBurst, fields, text)
	}
	subject := fmt.Sprintf("[unmask] challenge burst: %d/5min", count)
	if cfg.Sites != "" {
		subject = fmt.Sprintf("[unmask:%s] challenge burst: %d/5min", cfg.Sites, count)
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
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (n *Notifier) send(cfg Config, event string, fields map[string]any, text string) {
	body, contentType := buildPayload(cfg.Format, event, fields, text)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		log.Printf("notifier %s build request: %v", event, err)
		return
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "unmask/0.1 (+webhook)")
	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("notifier %s POST: %v", event, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("notifier %s response: HTTP %d", event, resp.StatusCode)
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
