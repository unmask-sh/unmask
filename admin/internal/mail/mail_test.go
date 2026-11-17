package mail

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// smtpStub: a minimal plaintext SMTP server that ADVERTISES STARTTLS but
// records (and refuses) any attempt to use it.  That advertisement is the
// trap under test: a client that upgrades opportunistically reveals itself
// here, which is exactly what stdlib smtp.SendMail does.
type smtpStub struct {
	ln          net.Listener
	sawStartTLS atomic.Bool
	sawMail     atomic.Bool // a MAIL FROM arrived: the client went on to send
	noStartTLS  bool        // the greeting offers no STARTTLS (startPlainSMTPStub)
	data        bytes.Buffer
	done        chan struct{}
}

func startSMTPStub(t *testing.T) *smtpStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpStub{ln: ln, done: make(chan struct{})}
	t.Cleanup(func() { ln.Close() })
	go s.serveOne()
	return s
}

// startPlainSMTPStub: the stub with a greeting that offers no STARTTLS -- a
// relay that has none, or one whose offer was taken out on the way.
func startPlainSMTPStub(t *testing.T) *smtpStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpStub{ln: ln, done: make(chan struct{}), noStartTLS: true}
	t.Cleanup(func() { ln.Close() })
	go s.serveOne()
	return s
}

func (s *smtpStub) addr() string { return s.ln.Addr().String() }
func (s *smtpStub) port() int    { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *smtpStub) serveOne() {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	fmt.Fprintf(conn, "220 stub ESMTP\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			if s.noStartTLS {
				fmt.Fprintf(conn, "250-stub\r\n250 8BITMIME\r\n")
			} else {
				fmt.Fprintf(conn, "250-stub\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
			}
		case cmd == "STARTTLS":
			s.sawStartTLS.Store(true)
			fmt.Fprintf(conn, "454 TLS not available\r\n")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			s.sawMail.Store(true)
			fmt.Fprintf(conn, "250 OK\r\n")
		case strings.HasPrefix(cmd, "RCPT TO"), cmd == "RSET", cmd == "NOOP":
			fmt.Fprintf(conn, "250 OK\r\n")
		case cmd == "DATA":
			fmt.Fprintf(conn, "354 go\r\n")
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
				s.data.WriteString(dl)
			}
			fmt.Fprintf(conn, "250 queued\r\n")
		case cmd == "QUIT":
			fmt.Fprintf(conn, "221 bye\r\n")
			close(s.done)
			return
		default:
			fmt.Fprintf(conn, "250 OK\r\n")
		}
	}
}

func (s *smtpStub) waitDone(t *testing.T) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		t.Fatal("stub: session did not complete")
	}
}

// TestPlaintextNeverUpgrades: `starttls: false` must mean plaintext even when
// the server advertises STARTTLS.  The previous implementation delegated to
// stdlib smtp.SendMail, which upgrades opportunistically and verifies the
// certificate -- so the plaintext setting still failed against a localhost
// relay with an expired self-signed certificate, the exact relay the setting
// exists for (observed on a production postfix relay, 2026-08-19).
func TestPlaintextNeverUpgrades(t *testing.T) {
	s := startSMTPStub(t)
	m := New(Config{Host: "127.0.0.1", Port: s.port(), FromAddress: "notify@example.com", FromName: "unmask test"})
	if err := m.Send("dest@example.com", "plain subject", "plain body"); err != nil {
		t.Fatalf("Send over plaintext: %v", err)
	}
	s.waitDone(t)
	if s.sawStartTLS.Load() {
		t.Error("client sent STARTTLS although the config says starttls: false")
	}
	got := s.data.String()
	if !strings.Contains(got, "plain subject") || !strings.Contains(got, "plain body") {
		t.Errorf("stub did not receive the message; got:\n%s", got)
	}
}

// With `starttls: true` the session upgrades when the relay offers
// STARTTLS, and a refusal of the upgrade is the send's error.
func TestStartTLSUpgradesWhenOffered(t *testing.T) {
	s := startSMTPStub(t)
	cfg := Config{Host: "127.0.0.1", Port: s.port(), StartTLS: true}
	err := sendSession(s.addr(), cfg, nil, "a@b", "c@d", []byte("x"), true)
	if err == nil {
		t.Fatal("want an error: the stub refuses STARTTLS with 454")
	}
	if !s.sawStartTLS.Load() {
		t.Error("starttls: true against an advertising server must attempt the upgrade")
	}
	if s.sawMail.Load() {
		t.Error("the message went on after the upgrade failed")
	}
}

// The offer of STARTTLS is a line of the relay's greeting, in the clear:
// anyone between the daemon and the relay can take it out.  With `starttls:
// true` the session used to carry on without the upgrade, and the mail -- a
// password-reset link -- went in the clear with Send reporting success.  A
// relay elsewhere that offers none now gets no message, and the send says
// why.
func TestStartTLSIsRequiredOfARelayElsewhere(t *testing.T) {
	elsewhere := peerOnThisHost
	peerOnThisHost = func(net.Conn) bool { return false }
	t.Cleanup(func() { peerOnThisHost = elsewhere })

	s := startPlainSMTPStub(t)
	m := New(Config{Host: "127.0.0.1", Port: s.port(), Username: "user", Password: "secret",
		FromAddress: "notify@example.com", StartTLS: true})
	err := m.Send("admin@example.com", "[unmask] password reset", "https://admin.example.com/unmask/admin/reset-password?token=deadbeef")
	if !errors.Is(err, ErrNoStartTLS) {
		t.Fatalf("Send to a relay that offers no STARTTLS: %v, want ErrNoStartTLS", err)
	}
	if s.sawMail.Load() || s.data.Len() != 0 {
		t.Errorf("the relay was sent the message in the clear:\n%s", s.data.String())
	}

	// `starttls: false` is the operator's word that this relay takes its
	// mail in the clear: sent as before.
	s = startPlainSMTPStub(t)
	m = New(Config{Host: "127.0.0.1", Port: s.port(), FromAddress: "notify@example.com"})
	if err := m.Send("admin@example.com", "plain subject", "plain body"); err != nil {
		t.Fatalf("Send with starttls off: %v", err)
	}
	s.waitDone(t)
	if !strings.Contains(s.data.String(), "plain body") {
		t.Errorf("starttls off: the stub did not receive the message:\n%s", s.data.String())
	}
}

// A relay on this host is the one sent to in the clear with `starttls: true`:
// the local postfix that offers no STARTTLS is the common relay, and loopback
// has no path for anyone to sit on.
func TestStartTLSNotOfferedOnThisHostSendsInTheClear(t *testing.T) {
	s := startPlainSMTPStub(t)
	m := New(Config{Host: "127.0.0.1", Port: s.port(), FromAddress: "notify@example.com", StartTLS: true})
	if err := m.Send("admin@example.com", "local subject", "local body"); err != nil {
		t.Fatalf("Send to a relay on loopback that offers no STARTTLS: %v", err)
	}
	s.waitDone(t)
	if !strings.Contains(s.data.String(), "local body") {
		t.Errorf("the stub did not receive the message:\n%s", s.data.String())
	}

	// What the exception reads is the connection's own far end.
	c, err := net.Dial("tcp", startPlainSMTPStub(t).addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !peerOnThisHost(c) {
		t.Error("a connection to 127.0.0.1 does not read as this host")
	}
}
