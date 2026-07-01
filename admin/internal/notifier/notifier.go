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

// Config: webhook notification settings.  Disabled or empty URL → no-op.
type Config struct {
	Disabled            bool
	URL                 string
	Format              string
	Sites               string // label to show in notification messages (= arbitrary operator-defined site name)
	BanEvents           bool   // send ban_created (= honeypot / manual)
	ChallengeBurst      bool   // send challenge_burst
	BurstThresholdPer5m int    // challenge count in the last 5 minutes.  0 disables
}

// MailSender: thin interface used by notifier for mail sending.  Taking
// *mail.Mailer directly would cause an import cycle, so we accept an
// interface.  Sends the same subject / body to every recipient returned by
// resolveRecipients.  If both are nil, the mail feature is disabled.
type MailSender interface {
	Enabled() bool
	Send(to, subject, body string) error
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
	mailGetTo func() []string // recipient list resolver (= wraps UserRepo.AlertRecipients)
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
// m.Enabled() is true, send the same subject / body to every recipient
// returned by resolveTo().  If either m or resolveTo is nil, mail
// notification is skipped.
func (n *Notifier) WithMail(m MailSender, resolveTo func() []string) *Notifier {
	if n == nil {
		return n
	}
	n.mailer = m
	n.mailGetTo = resolveTo
	return n
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
	if cfg.URL != "" {
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
	if cfg.URL != "" {
		go n.send(cfg, EventChallengeBurst, fields, text)
	}
	subject := fmt.Sprintf("[unmask] challenge burst: %d/5min", count)
	if cfg.Sites != "" {
		subject = fmt.Sprintf("[unmask:%s] challenge burst: %d/5min", cfg.Sites, count)
	}
	go n.sendMail(subject, text)
}

// OverBlock: the over-block circuit breaker changed state.  Called only on a
// transition (trip or clear), so there is no flap to throttle.  When tripped,
// the same visitors are being re-challenged instead of passing (serves/IP = the
// ratio over the window); autoPass reports whether the breaker also dropped
// protection to passthrough.
func (n *Notifier) OverBlock(tripped bool, serves, ips int, ratio float64, autoPass bool) {
	if n == nil {
		return
	}
	cfg := n.currentCfg()
	if cfg.Disabled {
		return
	}
	state := "cleared"
	var text string
	if tripped {
		state = "TRIPPED"
		act := "alert only (protection unchanged)"
		if autoPass {
			act = "AUTO-PASSTHROUGH engaged (visitors let through until it clears)"
		}
		text = fmt.Sprintf("[CRITICAL] over-block %s: %d challenge serves to %d IPs (= %.1f/IP) -- the same visitors are being re-challenged instead of passing. %s%s",
			state, serves, ips, ratio, act, siteSuffix(cfg.Sites))
	} else {
		text = fmt.Sprintf("[OK] over-block %s: serves/IP back to %.1f -- the challenge funnel recovered%s",
			state, ratio, siteSuffix(cfg.Sites))
	}
	fields := map[string]any{
		"event":            EventOverBlock,
		"tripped":          tripped,
		"serves":           serves,
		"ips":              ips,
		"serves_per_ip":    ratio,
		"auto_passthrough": autoPass,
		"site":             cfg.Sites,
		"ts":               time.Now().Unix(),
	}
	if cfg.URL != "" {
		go n.send(cfg, EventOverBlock, fields, text)
	}
	subject := "[unmask] over-block " + state
	if cfg.Sites != "" {
		subject = "[unmask:" + cfg.Sites + "] over-block " + state
	}
	go n.sendMail(subject, text)
}

// sendMail: if both mailer and recipient resolver are set, send the same
// mail to every recipient.  no-op if either is nil or mailer.Enabled()=false.
// Failures are logged only.
func (n *Notifier) sendMail(subject, body string) {
	if n == nil || n.mailer == nil || n.mailGetTo == nil || !n.mailer.Enabled() {
		return
	}
	to := n.mailGetTo()
	for _, t := range to {
		if t == "" {
			continue
		}
		if err := n.mailer.Send(t, subject, body); err != nil {
			log.Printf("notifier mail to %s: %v", t, err)
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
