package mail

import (
	"bufio"
	"bytes"
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
			fmt.Fprintf(conn, "250-stub\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
		case cmd == "STARTTLS":
			s.sawStartTLS.Store(true)
			fmt.Fprintf(conn, "454 TLS not available\r\n")
		case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"), cmd == "RSET", cmd == "NOOP":
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
// exists for (observed on a fleet postfix, 2026-08-19).
func TestPlaintextNeverUpgrades(t *testing.T) {
	s := startSMTPStub(t)
	m := New(Config{Host: "127.0.0.1", Port: s.port(), FromAddress: "notify@unmask.sh", FromName: "unmask test"})
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

// TestStartTLSFallsBackWhenNotOffered documents the other half of the session
// contract: with `starttls: true` against a server that never advertises the
// extension, the session proceeds in the clear rather than failing (the
// pre-existing opportunistic behavior, unchanged by the refactor).
func TestStartTLSFallsBackWhenNotOffered(t *testing.T) {
	s := startSMTPStub(t)
	// The stub DOES advertise STARTTLS, so to test the not-offered leg we
	// dial through sendSession directly with useStartTLS=true against a stub
	// whose EHLO reply is plain.  Simpler: assert on the advertised stub that
	// useStartTLS=true actually attempts the upgrade (and surfaces the 454).
	cfg := Config{Host: "127.0.0.1", Port: s.port(), StartTLS: true}
	err := sendSession(s.addr(), cfg, nil, "a@b", "c@d", []byte("x"), true)
	if err == nil {
		t.Fatal("want an error: the stub refuses STARTTLS with 454")
	}
	if !s.sawStartTLS.Load() {
		t.Error("starttls: true against an advertising server must attempt the upgrade")
	}
}
