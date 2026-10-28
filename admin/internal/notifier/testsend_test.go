package notifier

import (
	"bytes"
	"context"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The settings page's "send test" shows TestSend's error as it is, and the
// daemon logs it.  A refusing hook's own word is the useful part -- a removed
// Slack hook answers 404 "no_service" -- so it rides along with the status.
func TestTestSendSaysWhyTheHookRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("no_service\n"))
	}))
	defer srv.Close()
	err := New(Config{URL: srv.URL + "/services/T0/B0/hook-secret", Format: "slack"}).TestSend(context.Background())
	if err == nil || err.Error() != "webhook returned HTTP 404: no_service" {
		t.Fatalf("got %v, want the status and the hook's own answer", err)
	}
}

// deadHookURL: a hook URL on a port nothing listens on, its token in the path
// as a Slack or Discord hook carries it.
func deadHookURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr + "/services/T0/B0/hook-secret"
}

// A hook URL is its own secret, and the client's error quotes the URL: kept
// as it was, the token went to the settings page and the daemon log.  The
// reason stays, the URL goes.
func TestTestSendKeepsTheURLOutOfTheError(t *testing.T) {
	err := New(Config{URL: deadHookURL(t), Format: "slack"}).TestSend(context.Background())
	if err == nil {
		t.Fatal("a dead hook must fail the test send")
	}
	if strings.Contains(err.Error(), "hook-secret") {
		t.Errorf("the error carries the hook URL: %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("the error lost the reason: %v", err)
	}
}

// The same holds for a real alert, whose failure only reaches the log.
func TestSendLogsWithoutTheURL(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	cfg := Config{URL: deadHookURL(t), Format: "slack"}
	New(cfg).send(cfg.URL, cfg.Format, "test_event", map[string]any{}, "x")
	out := buf.String()
	if !strings.Contains(out, "notifier test_event POST:") || !strings.Contains(out, "connection refused") {
		t.Fatalf("the failure was not logged with its reason: %q", out)
	}
	if strings.Contains(out, "hook-secret") {
		t.Errorf("the log carries the hook URL: %q", out)
	}
}

func TestBodyHintIsOneShortLine(t *testing.T) {
	if got := bodyHint(strings.NewReader("  invalid\n\ttoken \n")); got != ": invalid token" {
		t.Errorf("got %q, want the body on one line", got)
	}
	if got := bodyHint(strings.NewReader("")); got != "" {
		t.Errorf("an empty body must add nothing, got %q", got)
	}
	if got := bodyHint(strings.NewReader(strings.Repeat("x", 300))); got != ": "+strings.Repeat("x", 200) {
		t.Errorf("a long body must stop at 200 bytes, got %d", len(got))
	}
}
