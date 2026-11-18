package settings

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A leftover rate_limit.reuse.pass_per_hour held a figure the operator chose,
// and the install is back at the seed without it: the log has to name the
// key, the figure, and the key that takes it now.
func TestWarnRemovedReusePassPerHour(t *testing.T) {
	capture := func(raw string) string {
		var buf bytes.Buffer
		old := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(old)
		warnRemovedReusePassPerHour("/etc/unmask/config.yml", []byte(raw))
		return buf.String()
	}

	got := capture("rate_limit:\n  reuse:\n    pass_per_hour: 3000\n    action: deny\n")
	for _, want := range []string{
		"rate_limit.reuse.pass_per_hour: 3000", "REMOVED in 0.1.58", "pass_requests: 3000", "pass_minutes",
		"500 every 60 minutes",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("the warning must mention %q, got: %s", want, got)
		}
	}

	if got := capture("rate_limit:\n  reuse:\n    pass_requests: 300\n    pass_minutes: 5\n"); got != "" {
		t.Fatalf("the keys that replaced it must not warn, got: %s", got)
	}
	if got := capture("rate_limit:\n  key: ip\n"); got != "" {
		t.Fatalf("no leftover key -> no warning, got: %s", got)
	}
	if got := capture(":: not yaml ::"); got != "" {
		t.Fatalf("unparsable yaml must stay silent here (Load already errors), got: %s", got)
	}
}

// Load is where the operator meets it: the old key changes nothing (the
// budget is the seed), and the two keys that replaced it are read.
func TestLoadReadsThePassWindowAndIgnoresPassPerHour(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "config.yml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	s, err := Load(write("rate_limit:\n  reuse:\n    pass_per_hour: 3000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if ru := s.RateLimit.Reuse; ru.ResolvedPassRequests() != ReusePassSeedRequests || ru.ResolvedPassMinutes() != ReusePassSeedMinutes {
		t.Errorf("the removed key must change nothing: %d every %d minutes", ru.ResolvedPassRequests(), ru.ResolvedPassMinutes())
	}
	if !strings.Contains(buf.String(), "REMOVED in 0.1.58") {
		t.Errorf("Load must name the removed key, logged: %s", buf.String())
	}

	buf.Reset()
	s, err = Load(write("rate_limit:\n  reuse:\n    pass_requests: 300\n    pass_minutes: 5\n"))
	if err != nil {
		t.Fatal(err)
	}
	if ru := s.RateLimit.Reuse; ru.PassRequests != 300 || ru.PassMinutes != 5 || ru.PassRatePerMin() != 60 {
		t.Errorf("read %d every %d minutes at %d r/m, want 300 every 5 at 60 r/m", ru.PassRequests, ru.PassMinutes, ru.PassRatePerMin())
	}
	if strings.Contains(buf.String(), "pass_") {
		t.Errorf("the new keys must load without a word, logged: %s", buf.String())
	}
}
