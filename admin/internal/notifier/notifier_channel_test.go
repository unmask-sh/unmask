package notifier

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// chanMailer records alert-mail sends; Enabled is always true so only the
// notifier's own gating decides whether Send is reached.
type chanMailer struct{ sent chan string }

func (m *chanMailer) Enabled() bool { return true }
func (m *chanMailer) Send(to, subject, body string) error {
	m.sent <- subject
	return nil
}

// overBlockDelivery fires one OverBlock transition under cfg and reports
// which channels it reached.  The webhook URL always points at a live stub;
// pauses must stop the send BEFORE the transport.
func overBlockDelivery(t *testing.T, cfg Config) (webhook, mail bool) {
	t.Helper()
	posts := make(chan struct{}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts <- struct{}{}
	}))
	defer srv.Close()
	cfg.URL = srv.URL

	m := &chanMailer{sent: make(chan string, 4)}
	n := New(cfg).WithMail(m, func() []string { return []string{"ops@example.com"} })
	n.OverBlock(true, 100, 5, 20.0, false)

	// Sends run in goroutines, but a paused channel never starts one -- so a
	// short window is only needed for the positive cases to land.
	deadline := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-posts:
			webhook = true
		case <-m.sent:
			mail = true
		case <-deadline:
			return webhook, mail
		case <-time.After(150 * time.Millisecond):
			return webhook, mail
		}
	}
	return webhook, mail
}

// TestMailToOverridesResolver: an explicit MailTo list IS the recipient list
// -- the admin-users resolver is not consulted -- and an empty MailTo falls
// back to it.  This is what lets an operator point alerts at a shared box
// without registering a pseudo-user to carry the address.
func TestMailToOverridesResolver(t *testing.T) {
	send := func(cfg Config) (subjects []string, resolverCalled bool) {
		m := &chanMailer{sent: make(chan string, 8)}
		n := New(cfg).WithMail(m, func() []string {
			resolverCalled = true
			return []string{"admin@example.com"}
		})
		n.OverBlock(true, 100, 5, 20.0, false)
		for {
			select {
			case s := <-m.sent:
				subjects = append(subjects, s)
			case <-time.After(300 * time.Millisecond):
				return subjects, resolverCalled
			}
		}
	}

	got, resolver := send(Config{MailTo: []string{"a@x", "b@x"}})
	if len(got) != 2 {
		t.Errorf("MailTo with 2 addresses sent %d mails, want 2", len(got))
	}
	if resolver {
		t.Error("MailTo set, but the admin-users resolver was still consulted")
	}

	got, resolver = send(Config{})
	if len(got) != 1 || !resolver {
		t.Errorf("empty MailTo must fall back to the resolver (sent=%d resolver=%v)", len(got), resolver)
	}
}

// TestPerChannelPause pins the channel gating: the master switch mutes both,
// each pause flag mutes exactly its own channel, and the settings themselves
// (URL, mailer) stay usable underneath -- pausing is not un-configuring.
func TestPerChannelPause(t *testing.T) {
	cases := []struct {
		name              string
		cfg               Config
		wantWeb, wantMail bool
	}{
		{"both channels live", Config{}, true, true},
		{"webhook paused", Config{WebhookDisabled: true}, false, true},
		{"mail paused", Config{MailDisabled: true}, true, false},
		{"both paused", Config{WebhookDisabled: true, MailDisabled: true}, false, false},
		{"master switch mutes both", Config{Disabled: true}, false, false},
	}
	for _, c := range cases {
		web, mail := overBlockDelivery(t, c.cfg)
		if web != c.wantWeb || mail != c.wantMail {
			t.Errorf("%s: webhook=%v mail=%v, want %v/%v", c.name, web, mail, c.wantWeb, c.wantMail)
		}
	}
}
