package handlers

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/mail"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// inviteSMTPStub: a minimal plaintext SMTP server that accepts any number of
// sessions and delivers each message's DATA body on a channel.
type inviteSMTPStub struct {
	ln       net.Listener
	messages chan string
}

func startInviteSMTPStub(t *testing.T) *inviteSMTPStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &inviteSMTPStub{ln: ln, messages: make(chan string, 8)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *inviteSMTPStub) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *inviteSMTPStub) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	fmt.Fprintf(conn, "220 stub ESMTP\r\n")
	var data strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			fmt.Fprintf(conn, "250-stub\r\n250 8BITMIME\r\n")
		case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"), cmd == "RSET", cmd == "NOOP":
			fmt.Fprintf(conn, "250 OK\r\n")
		case cmd == "DATA":
			fmt.Fprintf(conn, "354 go\r\n")
			data.Reset()
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
				data.WriteString(dl)
			}
			fmt.Fprintf(conn, "250 queued\r\n")
			s.messages <- data.String()
		case cmd == "QUIT":
			fmt.Fprintf(conn, "221 bye\r\n")
			return
		default:
			fmt.Fprintf(conn, "250 OK\r\n")
		}
	}
}

func (s *inviteSMTPStub) waitMessage(t *testing.T) string {
	t.Helper()
	select {
	case m := <-s.messages:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no mail reached the SMTP stub")
		return ""
	}
}

// newInviteTestHandler: a handler with a real (migrated) user repo and a real
// Mailer pointed at the stub -- the invite path exercises token issuance and
// SMTP delivery end to end.
func newInviteTestHandler(t *testing.T) (*Handler, *inviteSMTPStub) {
	t.Helper()
	h := newTestHandler(t)
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "users.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	h.UserRepo = &user.Repository{DB: conn}
	// AuthMiddleware / SetupNeeded consult h.DB for the admin-user count; point
	// it at the same migrated DB so a populated repo reads as "setup done".
	h.DB = conn
	stub := startInviteSMTPStub(t)
	h.Mailer = mail.New(mail.Config{Host: "127.0.0.1", Port: stub.port(), FromAddress: "notify@unmask.sh"})
	return h, stub
}

func postUsersSave(t *testing.T, h *Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/users/save",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey{},
		&SessionPayload{UserID: 999, Role: "superadmin"}))
	rr := httptest.NewRecorder()
	h.AdminUsersSave(rr, req)
	return rr
}

var setupLinkRE = regexp.MustCompile(`/admin/reset-password\?token=([0-9a-f]{64})`)

// TestCreateWithInviteMailsSetupLink: op=create with send_invite=1 and no
// password creates the account and mails a working password-setup link.  The
// mail must carry ONLY the link -- the account's initial password is random
// and discarded, so nothing in the message can sign in by itself.
func TestCreateWithInviteMailsSetupLink(t *testing.T) {
	h, stub := newInviteTestHandler(t)
	rr := postUsersSave(t, h, url.Values{
		"op":          {"create"},
		"username":    {"alice"},
		"role":        {"admin"},
		"email":       {"alice@example.com"},
		"send_invite": {"1"},
	})
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("create+invite: code=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
	body := stub.waitMessage(t)
	m := setupLinkRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("invite mail has no setup link:\n%s", body)
	}
	// The link works: consuming the token yields the invited account.
	u, err := h.UserRepo.ConsumeResetToken(context.Background(), m[1])
	if err != nil || u.Username != "alice" {
		t.Fatalf("mailed token does not resolve to the invitee: u=%v err=%v", u, err)
	}
}

// TestSendSetupLinkResend: the list-page button mails a fresh link for an
// existing user and lands back with its own success marker (not saved=1 --
// nothing was saved, a mail left).
func TestSendSetupLinkResend(t *testing.T) {
	h, stub := newInviteTestHandler(t)
	u, err := h.UserRepo.CreateWithProfile(context.Background(), "bob", "hunter2-hunter2", "admin", "bob@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	rr := postUsersSave(t, h, url.Values{
		"op": {"send_setup_link"},
		"id": {fmt.Sprint(u.ID)},
	})
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "link_sent=1") {
		t.Fatalf("resend: code=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
	if m := setupLinkRE.FindStringSubmatch(stub.waitMessage(t)); m == nil {
		t.Fatal("resend mail has no setup link")
	}
}

// TestInviteGuards: an invite needs an email and a configured mailer; either
// missing refuses BEFORE creating the account, so a failed invite leaves no
// half-set-up user behind.
func TestInviteGuards(t *testing.T) {
	h, _ := newInviteTestHandler(t)
	rr := postUsersSave(t, h, url.Values{
		"op": {"create"}, "username": {"carol"}, "role": {"admin"}, "send_invite": {"1"},
	})
	if rr.Code != http.StatusFound || strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatalf("no-email invite must fail: code=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
	if _, err := h.UserRepo.GetByUsername(context.Background(), "carol"); err == nil {
		t.Error("no-email invite still created the account")
	}

	h.Mailer = nil
	rr = postUsersSave(t, h, url.Values{
		"op": {"create"}, "username": {"dave"}, "role": {"admin"},
		"email": {"dave@example.com"}, "send_invite": {"1"},
	})
	if strings.Contains(rr.Header().Get("Location"), "saved=1") {
		t.Fatal("no-SMTP invite must fail")
	}
	if _, err := h.UserRepo.GetByUsername(context.Background(), "dave"); err == nil {
		t.Error("no-SMTP invite still created the account")
	}
}
