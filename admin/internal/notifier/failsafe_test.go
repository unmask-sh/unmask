package notifier

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The nginx module stripped by the plugin's fail-safe is the alert every
// operator wants: critical, on the webhook (the critical hook when there is
// one) and in the mail, gated on nothing but the section being on; its
// return is information on the same channels.
func TestNativeFailsafeReachesWebhookAndMail(t *testing.T) {
	type post struct {
		hook string
		body map[string]any
	}
	posts := make(chan post, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		posts <- post{hook: r.URL.Path, body: m}
	}))
	defer srv.Close()
	m := &chanMailer{sent: make(chan string, 4)}
	// Neither ban nor burst alerts are on: the fail-safe alert does not
	// depend on them.  The critical hook takes the loss, the first the
	// return.
	n := New(Config{URL: srv.URL + "/all", CriticalURL: srv.URL + "/crit", Format: FormatGeneric, Sites: "shop"}).
		WithMail(m, func() []Recipient { return []Recipient{{Email: "ops@example.com"}} }, nil)

	since := time.Date(2026, 11, 3, 1, 2, 3, 0, time.UTC)
	n.NativeFailsafe(FailsafeReport{Active: true, Reason: "no bundled module for host nginx 1.99.0", Since: since})
	var got post
	select {
	case got = <-posts:
	case <-time.After(3 * time.Second):
		t.Fatal("no webhook POST for the loss")
	}
	if got.hook != "/crit" {
		t.Errorf("the loss went to %s, want the critical hook", got.hook)
	}
	if got.body["event"] != EventNativeFailsafe || got.body["active"] != true || got.body["severity"] != SeverityCrit ||
		got.body["reason"] != "no bundled module for host nginx 1.99.0" || got.body["site"] != "shop" || got.body["since"] != float64(since.Unix()) {
		t.Errorf("the loss payload: %v", got.body)
	}
	select {
	case subject := <-m.sent:
		if !strings.Contains(subject, "nginx module OFF") || !strings.Contains(subject, "shop") {
			t.Errorf("mail subject %q", subject)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no mail for the loss")
	}

	n.NativeFailsafe(FailsafeReport{Active: false})
	select {
	case got = <-posts:
	case <-time.After(3 * time.Second):
		t.Fatal("no webhook POST for the return")
	}
	if got.hook != "/crit" || got.body["active"] != false || got.body["severity"] != SeverityInfo {
		t.Errorf("the return: hook %s, payload %v", got.hook, got.body)
	}
	select {
	case subject := <-m.sent:
		if !strings.Contains(subject, "nginx module back") {
			t.Errorf("mail subject %q", subject)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no mail for the return")
	}

	// The Slack text says what is off and what to do, and what
	// place-module wrote is escaped like any other field.
	text := failsafeLine(FailsafeReport{Active: true, Reason: "no bundled module <!channel>"}, "")
	slack, _ := buildPayload(FormatSlack, EventNativeFailsafe, nil, text)
	var sp struct{ Text string }
	if err := json.Unmarshal(slack, &sp); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[CRITICAL]", "protection is OFF", "unmask doctor", "&lt;!channel&gt;"} {
		if !strings.Contains(sp.Text, want) {
			t.Errorf("slack text lacks %q: %s", want, sp.Text)
		}
	}

	// The section off: nothing, on either channel.
	off := New(Config{Disabled: true, URL: srv.URL}).WithMail(m, func() []Recipient { return []Recipient{{Email: "ops@example.com"}} }, nil)
	off.NativeFailsafe(FailsafeReport{Active: true})
	select {
	case <-posts:
		t.Error("a webhook POST with notifications off")
	case <-m.sent:
		t.Error("mail with notifications off")
	case <-time.After(200 * time.Millisecond):
	}
}
