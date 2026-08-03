package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A UA black-list row can pin its own chain.  Until it could, the list ran one
// action for every pattern in it, so a rule that needed captcha_only could
// only get there by moving the whole list -- which is what a residential
// browser farm forced: it solves PoW at scale (96% of one node's passes), so
// pow_then_captcha lets it straight through, while the rest of the black list
// is better served by exactly that.
func TestUARowActionOverridesTheListDefault(t *testing.T) {
	n := settings.Nginx{}
	n.ChallengeTargets.Extra = []string{"FirstBot", "X11; Linux x86_64", "ThirdBot"}
	n.ChallengeTargets.ExtraAction = []string{"", "captcha_only", ""}
	n.ChallengeTargets.DefaultAction = "pow_then_captcha"

	for _, tc := range []struct {
		ua   string
		want string
	}{
		{"FirstBot/1.0", ""}, // inherits
		{"Mozilla/5.0 (X11; Linux x86_64) Chrome/149", "captcha_only"}, // pinned
		{"ThirdBot/2.0", ""},
	} {
		listed, cat, act := lookupUAListed(tc.ua, n)
		if listed == "" || cat != "challenge" {
			t.Errorf("%q: not recognised as a challenge target (%q/%q)", tc.ua, listed, cat)
			continue
		}
		if act != tc.want {
			t.Errorf("%q: action = %q, want %q", tc.ua, act, tc.want)
		}
	}

	// A short action column must not shift the rows that follow it.  The
	// parallel-slice shape makes this the easy mistake: drop one entry and
	// every later row silently inherits the wrong chain.
	n.ChallengeTargets.ExtraAction = []string{"", "captcha_only"}
	if _, _, act := lookupUAListed("ThirdBot/2.0", n); act != "" {
		t.Errorf("a row past the end of the action column resolved to %q, want inherit", act)
	}
}

// Both wires have to agree.  Native picks the chain in ServeChallenge and
// forward-auth in uaDecide, from the same settings -- a per-row action honoured
// by one and not the other means the same visitor is treated differently
// depending on how unmask is deployed.
func TestUARowActionAppliesOnBothWires(t *testing.T) {
	var s settings.Settings
	s.Nginx.ChallengeTargets.Extra = []string{"X11; Linux x86_64"}
	s.Nginx.ChallengeTargets.ExtraAction = []string{"captcha_only"}
	s.Nginx.ChallengeTargets.DefaultAction = "pow_then_captcha"

	const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"

	// forward-auth
	dec, ok := uaDecide(ua, "", s, nil)
	if !ok {
		t.Fatal("forward-auth did not decide on a black-listed UA")
	}
	if dec.chMode != settings.RateChallengeCaptchaOnly {
		t.Errorf("forward-auth chMode = %q, want captcha_only (the row's own chain, not the list default)", dec.chMode)
	}

	// native: same settings, the serve path's resolution
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Nginx.ChallengeTargets = s.Nginx.ChallengeTargets
	h.SetSettings(cur)
	if _, _, act := lookupUAListed(ua, h.cfg().Nginx); act != settings.RateChallengeCaptchaOnly {
		t.Errorf("native lookup returned %q, want captcha_only", act)
	}
}

// The action survives a save/load round trip and stays lined up with its
// pattern.  An unknown value is dropped to "inherit" rather than persisted:
// a row claiming a chain nothing implements would fail open at serve time.
func TestUARowActionRoundTripsAndRejectsUnknown(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	base := h.snapshotSettings()
	base.Server.BasePath = "/unmask"
	base.Nginx.OutputDir = filepath.Join(dir, "nginx")
	cfgPath := filepath.Join(dir, "config.yml")
	if err := settings.Save(base, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(base)

	form := strings.NewReader(strings.Join([]string{
		"black_extra=FirstBot&black_extra_title=a&black_extra_enabled=1&black_extra_created_at=&black_extra_updated_at=&black_extra_action=",
		"black_extra=SecondBot&black_extra_title=b&black_extra_enabled=1&black_extra_created_at=&black_extra_updated_at=&black_extra_action=captcha_only",
		"black_extra=ThirdBot&black_extra_title=c&black_extra_enabled=1&black_extra_created_at=&black_extra_updated_at=&black_extra_action=not-a-chain",
	}, "&"))
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=ua-filter", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	n := base.Nginx
	applyUAFilterForm(&n, req)

	if got := n.ChallengeTargets.Extra; len(got) != 3 {
		t.Fatalf("patterns = %v, want 3", got)
	}
	want := []string{"", "captcha_only", ""}
	for i, w := range want {
		var got string
		if i < len(n.ChallengeTargets.ExtraAction) {
			got = n.ChallengeTargets.ExtraAction[i]
		}
		if got != w {
			t.Errorf("row %d (%s): action = %q, want %q", i, n.ChallengeTargets.Extra[i], got, w)
		}
	}
}

// The hunt dialog writes the same column, so a rule added from the ranking is
// indistinguishable from one typed on the settings tab.
func TestHuntUARuleCarriesItsAction(t *testing.T) {
	h := ruleTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/hunt/action", nil)
	if err := h.appendUABlacklist(req, "PlainBot", "t", "", "admin", 1); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := h.appendUABlacklist(req, "X11; Linux x86_64", "t", "captcha_only", "admin", 1); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := h.appendUABlacklist(req, "Nope", "t", "not-a-chain", "admin", 1); err == nil {
		t.Error("an unknown action was accepted from the hunt dialog")
	}
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	ct := cur.Nginx.ChallengeTargets
	if len(ct.Extra) != 2 || len(ct.ExtraAction) != 2 {
		t.Fatalf("patterns=%v actions=%v, want 2 each", ct.Extra, ct.ExtraAction)
	}
	if ct.ExtraAction[0] != "" || ct.ExtraAction[1] != "captcha_only" {
		t.Errorf("actions = %v, want [\"\" captcha_only]", ct.ExtraAction)
	}
}

// The row UI has to end up with ONE action pill.  The server renders the pill
// and syncRowPills rebuilds it on confirm, so unless they agree on the same
// element the confirm appends a second one -- measured in a browser as
// "継承(pow_then_captcha) , captcha_only" side by side on one row.
func TestUARowActionPillIsNotDuplicatedOnConfirm(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)

	// The server-rendered pill carries the identity syncRowPills upserts.
	if !regexp.MustCompile(`ua-act-pill[^>]*data-pill="action"`).MatchString(tpl) {
		t.Error("the UA action pill has no data-pill=action, so a confirm adds a second pill beside it")
	}
	// And "inherit" keeps a pill rather than losing one: the row still has to
	// say which chain it will run.
	if !regexp.MustCompile(`<option value="" data-inherit-pill`).MatchString(tpl) {
		t.Error("the inherit option is not marked, so confirming an inherit row drops its pill entirely")
	}
	if !strings.Contains(tpl, "hasAttribute('data-inherit-pill')") {
		t.Error("syncRowPills does not honour the inherit marker")
	}
}
