package settings

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A per-pass figure below its window's minutes cannot be saved from the
// settings page, so it reaches a running daemon only through config.yml.
// There it renders -- as the figure at once and nginx's one request a minute
// -- and the operator is told what it runs as; a pair that stands, and a cap
// that is off, say nothing.
func TestPassWindowIssue(t *testing.T) {
	for _, c := range []struct {
		ru   ReuseLimitConfig
		want []string // "" in the first slot: silence
	}{
		{ReuseLimitConfig{}, nil},
		{ReuseLimitConfig{PassRequests: 30, PassMinutes: 5}, nil},
		{ReuseLimitConfig{PassRequests: 60}, nil},
		{ReuseLimitConfig{PassRequests: 30}, []string{"30 requests every 60 minutes", "30 at once and one back a minute", "(30 every 30 minutes)"}},
		{ReuseLimitConfig{PassMinutes: 720}, []string{"500 requests every 720 minutes", "(500 every 500 minutes)"}},
		{ReuseLimitConfig{PassRequests: 30, Disabled: true}, nil},
	} {
		got := c.ru.PassWindowIssue()
		if len(c.want) == 0 {
			if got != "" {
				t.Errorf("%+v: %q, want silence", c.ru, got)
			}
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%+v: the issue must carry %q, got: %s", c.ru, w, got)
			}
		}
		// What it says it runs as is what the render is given.
		if c.ru.PassRatePerMin() != 1 {
			t.Errorf("%+v renders at %d r/m, and the issue says one a minute", c.ru, c.ru.PassRatePerMin())
		}
	}
}

func TestLoadWarnsOfAPassWindowBelowOneAMinute(t *testing.T) {
	dir := t.TempDir()
	load := func(body string) string {
		t.Helper()
		p := filepath.Join(dir, "config.yml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		old := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(old)
		if _, err := Load(p); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	got := load("rate_limit:\n  reuse:\n    pass_requests: 30\n")
	for _, want := range []string{"30 requests every 60 minutes", "pass_requests to at least pass_minutes"} {
		if !strings.Contains(got, want) {
			t.Errorf("Load must say what the pair runs as (%q), logged: %s", want, got)
		}
	}
	if got := load("rate_limit:\n  reuse:\n    pass_requests: 30\n    pass_minutes: 5\n"); strings.Contains(got, "rate_limit.reuse") {
		t.Errorf("a pair that stands must load without a word, logged: %s", got)
	}
}
