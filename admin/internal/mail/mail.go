// Package mail: outbound SMTP mail sender.
//
// Design principles:
//   - Send via stdlib net/smtp.  Zero SDK dependencies.  Auth is AUTH PLAIN (= every modern relay supports it).
//   - Port 587 STARTTLS is the default.  Port 465 (implicit TLS) takes a separate path.
//   - When SMTP config is empty / Host is empty, no-op (= just log and skip).
//     Alert sending and reset-mail features call this unconditionally, so be
//     silent when disabled.
//   - Hot-swap config support (= same atomic-pointer-swap pattern as notifier).
//
// Use cases:
//   1. Alert notifications (= ban_created / challenge_burst.  In parallel with webhook.)
//   2. Password reminder (= send reset link.)
//
// Failures are logged and returned as error (= callers that want to branch can inspect err).
package mail

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strings"
	"sync/atomic"
	"time"
)

// Config: SMTP connection settings.  Empty Host means disabled.
type Config struct {
	Host               string
	Port               int
	Username           string
	Password           string
	FromAddress        string
	FromName           string
	StartTLS           bool
	InsecureSkipVerify bool
}

// Mailer: SMTP sender.  Every method is nil-safe + no-op when Config is disabled.
type Mailer struct {
	cfg     Config
	dynamic atomic.Pointer[Config]
}

// New: cfg is passed by value.  Hot-swap later via SetConfig.
func New(cfg Config) *Mailer {
	m := &Mailer{cfg: cfg}
	m.dynamic.Store(&cfg)
	return m
}

// SetConfig: call after settings are saved.  No lock needed.
func (m *Mailer) SetConfig(cfg Config) {
	if m == nil {
		return
	}
	m.dynamic.Store(&cfg)
}

func (m *Mailer) currentCfg() Config {
	if m == nil {
		return Config{}
	}
	if p := m.dynamic.Load(); p != nil {
		return *p
	}
	return m.cfg
}

// Enabled: whether the SMTP config is active (= Host is non-empty).  For caller's no-op check.
func (m *Mailer) Enabled() bool {
	if m == nil {
		return false
	}
	cfg := m.currentCfg()
	return strings.TrimSpace(cfg.Host) != ""
}

// Send: send one message.  `to` is a single address.  Loop in the caller for multiple recipients.
// On disabled / misconfigured state, return nil (= callers can call freely).
func (m *Mailer) Send(to, subject, body string) error {
	if m == nil {
		return nil
	}
	cfg := m.currentCfg()
	if strings.TrimSpace(cfg.Host) == "" {
		// disabled.  If the caller wants to distinguish "mail disabled," check Enabled().
		return nil
	}
	to = strings.TrimSpace(to)
	if to == "" {
		return errors.New("mail: empty recipient")
	}
	return m.sendOne(cfg, to, subject, body)
}

// TestSend: for the settings UI "test send" button.  Send a confirmation mail to `to`.
// When disabled, return an explicit error (= so the UI can render "SMTP not configured").
func (m *Mailer) TestSend(to string) error {
	cfg := m.currentCfg()
	if strings.TrimSpace(cfg.Host) == "" {
		return errors.New("mail: smtp.host is empty (= not configured.  Fill in host under the SMTP tab.)")
	}
	to = strings.TrimSpace(to)
	if to == "" {
		return errors.New("mail: please specify a recipient address")
	}
	subject := "[unmask] SMTP test send"
	body := "This is a test mail for the unmask admin SMTP settings.\n\n" +
		"If this message arrives, the SMTP configuration is working.\n" +
		"From: " + cfg.FromAddress + " (" + cfg.FromName + ")\n" +
		"sent at: " + time.Now().Format(time.RFC3339) + "\n"
	return m.sendOne(cfg, to, subject, body)
}

// sendOne: send one message in a single SMTP session.  Handles both port 587
// (= STARTTLS) and port 465 (= full TLS).  Also supports plaintext (=
// STARTTLS=false) as a fallback (= e.g. same-host relays).
func (m *Mailer) sendOne(cfg Config, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, port(cfg.Port))
	from := cfg.FromAddress
	if from == "" {
		from = "unmask@" + cfg.Host
	}
	msg := buildMessage(cfg, to, subject, body)

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	// port 465 = implicit TLS (= submissions).  TLS-dial first, then speak SMTP.
	if port(cfg.Port) == 465 {
		return sendImplicitTLS(addr, cfg, auth, from, to, msg)
	}

	// Everything else (587 / 25 / etc): plain dial → STARTTLS upgrade or plaintext.
	if cfg.StartTLS {
		return sendStartTLS(addr, cfg, auth, from, to, msg)
	}
	// plaintext.  Limited to use cases like internal relays.
	if err := smtp.SendMail(addr, auth, from, []string{to}, msg); err != nil {
		log.Printf("mail send failed (plain): %v", err)
		return err
	}
	return nil
}

func sendStartTLS(addr string, cfg Config, auth smtp.Auth, from, to string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer c.Close()
	if err := c.Hello(localhostHello()); err != nil {
		return fmt.Errorf("smtp hello: %w", err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return c.Quit()
}

func sendImplicitTLS(addr string, cfg Config, auth smtp.Auth, from, to string, msg []byte) error {
	tlsCfg := &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp newclient: %w", err)
	}
	defer c.Close()
	if err := c.Hello(localhostHello()); err != nil {
		return fmt.Errorf("smtp hello: %w", err)
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return c.Quit()
}

// buildMessage: RFC 5322 minimal.  From / To / Subject / Date / MIME headers + body.
// Non-ASCII subjects are wrapped in a UTF-8 base64 encoded-word (= "=?utf-8?B?...?=").
func buildMessage(cfg Config, to, subject, body string) []byte {
	from := cfg.FromAddress
	if from == "" {
		from = "unmask@" + cfg.Host
	}
	if cfg.FromName != "" {
		from = fmt.Sprintf("%s <%s>", encodeHeader(cfg.FromName), from)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeHeader(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&b, "Content-Transfer-Encoding: 8bit\r\n")
	fmt.Fprintf(&b, "\r\n")
	b.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

// encodeHeader: wrap a header value containing non-ASCII characters in a MIME encoded-word.
// All-ASCII values are returned as-is.
func encodeHeader(s string) string {
	allASCII := true
	for _, r := range s {
		if r > 127 {
			allASCII = false
			break
		}
	}
	if allASCII {
		return s
	}
	return mimeQ(s)
}

// mimeQ: convert a UTF-8 string to a Base64 encoded-word (= simplified.  No multi-word splitting on newlines).
func mimeQ(s string) string {
	enc := base64StdEncoding(s)
	return "=?utf-8?B?" + enc + "?="
}

func base64StdEncoding(s string) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	src := []byte(s)
	var b strings.Builder
	for i := 0; i < len(src); i += 3 {
		var n uint32
		j := 0
		for ; j < 3 && i+j < len(src); j++ {
			n |= uint32(src[i+j]) << (16 - 8*j)
		}
		b.WriteByte(tbl[(n>>18)&0x3F])
		b.WriteByte(tbl[(n>>12)&0x3F])
		if j > 1 {
			b.WriteByte(tbl[(n>>6)&0x3F])
		} else {
			b.WriteByte('=')
		}
		if j > 2 {
			b.WriteByte(tbl[n&0x3F])
		} else {
			b.WriteByte('=')
		}
	}
	return b.String()
}

func port(p int) int {
	if p <= 0 {
		return 587
	}
	return p
}

// localhostHello: hostname to advertise in HELO / EHLO.  Falls back to "localhost" on resolution failure.
func localhostHello() string {
	if h, err := net.LookupCNAME("localhost"); err == nil && h != "" {
		return strings.TrimSuffix(h, ".")
	}
	return "localhost"
}
