package mail

import (
	"strings"
	"testing"
)

// A header value carrying CRLF must not become a header.
//
// buildMessage writes "Name: value\r\n" lines, and a header line ends at the
// first CRLF -- so a value containing one is not a value any more: what follows
// is parsed as the next header, and after a blank line, as the body.  net/smtp
// stops this on the SMTP commands (MAIL FROM / RCPT TO / EHLO all run through
// validateLine), but the message goes out through Data()'s writer, which it
// never inspects.
//
// The reachable source is a notification subject: it names the address or the
// site an event came from, so whoever caused the event chose part of it.
func TestHeaderInjectionIsNotPossible(t *testing.T) {
	cfg := Config{Host: "mail.example.com", FromAddress: "unmask@example.com"}

	// Count the headers a parser would see before the blank line.
	headersOf := func(msg []byte) []string {
		head, _, _ := strings.Cut(string(msg), "\r\n\r\n")
		return strings.Split(head, "\r\n")
	}

	t.Run("a subject cannot add a header", func(t *testing.T) {
		msg := buildMessage(cfg, "ops@example.com",
			"BAN: 1.2.3.4\r\nBcc: attacker@evil.example\r\nX-Injected: yes", "body")
		for _, h := range headersOf(msg) {
			if strings.HasPrefix(strings.ToLower(h), "bcc:") || strings.HasPrefix(h, "X-Injected:") {
				t.Errorf("an injected header survived: %q", h)
			}
		}
		// And the text is still there to read, just flattened onto one line.
		if !strings.Contains(string(msg), "Bcc: attacker@evil.example") {
			t.Error("the value was dropped rather than neutralised; it should still be readable")
		}
	})

	t.Run("a subject cannot end the headers and write a body", func(t *testing.T) {
		msg := buildMessage(cfg, "ops@example.com", "x\r\n\r\nnot the real body", "real body")
		_, body, found := strings.Cut(string(msg), "\r\n\r\n")
		if !found {
			t.Fatal("no header/body separator at all")
		}
		// The injected text stays inside the Subject value -- flattened, which
		// is the point -- so what must hold is that it did not BECOME the body,
		// and that the separator is still the one buildMessage wrote.
		if !strings.HasPrefix(body, "real body") {
			t.Errorf("the body is not the one that was passed: %q", body)
		}
		if got := strings.Count(string(msg), "\r\n\r\n"); got != 1 {
			t.Errorf("the message has %d header/body separators, want exactly 1", got)
		}
		for _, h := range headersOf(msg) {
			if !strings.HasPrefix(h, "From: ") && !strings.HasPrefix(h, "To: ") &&
				!strings.HasPrefix(h, "Subject: ") && !strings.HasPrefix(h, "Date: ") &&
				!strings.HasPrefix(h, "MIME-Version: ") && !strings.HasPrefix(h, "Content-") {
				t.Errorf("an unexpected header line appeared: %q", h)
			}
		}
	})

	t.Run("a recipient address cannot add a header", func(t *testing.T) {
		msg := buildMessage(cfg, "ops@example.com\r\nBcc: attacker@evil.example", "subject", "body")
		for _, h := range headersOf(msg) {
			if strings.HasPrefix(strings.ToLower(h), "bcc:") {
				t.Errorf("an injected header survived from the recipient: %q", h)
			}
		}
	})

	t.Run("the operator's from_name and address cannot either", func(t *testing.T) {
		c := Config{
			Host:        "mail.example.com",
			FromAddress: "unmask@example.com\r\nX-From-Injected: yes",
			FromName:    "unmask\r\nX-Name-Injected: yes",
		}
		msg := buildMessage(c, "ops@example.com", "subject", "body")
		for _, h := range headersOf(msg) {
			if strings.Contains(h, "X-From-Injected") && strings.HasPrefix(h, "X-From-Injected") {
				t.Errorf("an injected header survived from from_address: %q", h)
			}
			if strings.HasPrefix(h, "X-Name-Injected") {
				t.Errorf("an injected header survived from from_name: %q", h)
			}
		}
	})

	t.Run("NUL and other C0 controls are dropped", func(t *testing.T) {
		msg := buildMessage(cfg, "ops@example.com", "sub\x00ject\x07", "body")
		if strings.ContainsAny(string(msg[:strings.Index(string(msg), "\r\n\r\n")]), "\x00\x07") {
			t.Error("a C0 control survived into the headers")
		}
	})

	t.Run("an ordinary subject is untouched", func(t *testing.T) {
		msg := buildMessage(cfg, "ops@example.com", "[unmask] over-block tripped", "body")
		if !strings.Contains(string(msg), "Subject: [unmask] over-block tripped\r\n") {
			t.Error("a clean subject was altered")
		}
	})

	// The non-ASCII path base64-encodes, so it could never emit a line break --
	// but it must still round-trip, and must not be reached by ASCII CRLF.
	t.Run("a non-ASCII subject still encodes", func(t *testing.T) {
		msg := buildMessage(cfg, "ops@example.com", "日本語の件名", "body")
		if !strings.Contains(string(msg), "Subject: =?utf-8?B?") {
			t.Errorf("the non-ASCII subject lost its encoded-word: %q", string(msg))
		}
	})
}
