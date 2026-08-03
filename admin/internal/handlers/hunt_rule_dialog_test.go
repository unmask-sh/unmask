package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A UA pattern from the hunt ranking is rendered verbatim into an nginx map,
// so it has to clear the same bar the settings form applies.  It did not, and
// the strings it let through were the ones the feature exists for: a crawler
// that identifies itself writes "Name/1.0 (+https://example.com/bot)", and the
// "(+" is not a valid repeat.  The config was written, the page said applied,
// and nginx refused the whole file at the operator's next reload -- which
// could be an urgent one for an unrelated reason.
func TestHuntUAPatternIsValidatedLikeTheSettingsForm(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		ok      bool
	}{
		{"self-identifying crawler, raw", `OmvionLeadLake/1.0 (+https://omvion.org/crawler)`, false},
		{"the token from the same UA", `OmvionLeadLake`, true},
		{"quote escapes the map entry", `bad" 1; #`, false},
		{"backslash", `bad\x22`, false},
		{"newline", "two\nlines", false},
		{"empty", "   ", false},
		{"unbalanced paren", `Bytespider)`, false},
		{"ordinary pattern", `python-requests`, true},
	} {
		err := validUAPattern(tc.pattern)
		if tc.ok && err != nil {
			t.Errorf("%s: %q rejected: %v", tc.name, tc.pattern, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: %q accepted, but nginx would refuse it", tc.name, tc.pattern)
		}
	}
}

// The dialog proposes a pattern, and it has to be one that both matches and
// survives validation -- there is no escaping available (a backslash is
// rejected outright), so the token itself must carry no regex meaning.
func TestProposedUATokenMatchesAndValidates(t *testing.T) {
	for _, ua := range []string{
		`OmvionLeadLake/1.0 (+https://omvion.org/crawler)`,
		`Quantcastbot/2.0 (+http://www.quantcast.com/bot)`,
		`Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`,
		`Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)`,
		`python-requests/2.31.0`,
	} {
		tok := classify.UARuleToken(ua)
		if tok == "" {
			t.Errorf("%q: no pattern proposed for a self-identifying client", ua)
			continue
		}
		if err := validUAPattern(tok); err != nil {
			t.Errorf("%q -> %q: the proposal does not pass validation: %v", ua, tok, err)
		}
		if !strings.Contains(ua, tok) {
			t.Errorf("%q -> %q: the proposal does not appear in the UA it came from", ua, tok)
		}
	}
	// An ordinary browser names nothing but "Mozilla", and a rule on that
	// challenges every visitor.  No proposal is the correct answer.
	if tok := classify.UARuleToken(
		`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`); tok != "" {
		t.Errorf("a plain browser UA proposed %q as a black-list pattern", tok)
	}
}

// ruleTestHandler: a handler whose config.yml is writable.  These paths load,
// append and save the real settings file, which the default test handler
// points at /etc/unmask.
func ruleTestHandler(t *testing.T) *Handler {
	t.Helper()
	h := newTestHandler(t)
	dir := t.TempDir()
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	// These paths render as part of saving; without an output dir they would
	// write into the real /var/lib/unmask/nginx.
	s.Nginx.OutputDir = filepath.Join(dir, "nginx")
	cfgPath := filepath.Join(dir, "config.yml")
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(s)
	return h
}

// A rule added from the ranking is a new row, not an edited one.  The hunt
// path stamped the edit date and left the creation date empty, so the settings
// list showed "updated <date>" for a row nobody had ever edited and no sign of
// where it came from.
func TestHuntAddedRulesCarryTheirCreationDate(t *testing.T) {
	h := ruleTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/hunt/action", nil)
	if err := h.appendUABlacklist(req, "Bytespider", "bot hunt (5 req)", "", "admin", 1); err != nil {
		t.Fatalf("append: %v", err)
	}
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	ct := cur.Nginx.ChallengeTargets
	if n := len(ct.Extra); n != 1 {
		t.Fatalf("Extra has %d rows, want 1", n)
	}
	if len(ct.ExtraCreatedAt) != 1 || ct.ExtraCreatedAt[0] <= 0 {
		t.Errorf("the new row has no creation date: %v", ct.ExtraCreatedAt)
	}
	if len(ct.ExtraUpdatedAt) != 1 || ct.ExtraUpdatedAt[0] != 0 {
		t.Errorf("the new row is stamped as edited: %v", ct.ExtraUpdatedAt)
	}
}

// The ASN ranking registers its rule from the page the evidence is on.  The
// row has to come out the same shape the settings tab writes, or the two
// entry points produce rules that read differently in the same list.
func TestHuntASNRuleIsWrittenLikeATabRule(t *testing.T) {
	h := ruleTestHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/hunt/action", nil)
	if err := h.appendASNRule(req, 398781, "Acme Hosting", "pow_then_captcha", "admin", 1); err != nil {
		t.Fatalf("append: %v", err)
	}
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	rules := cur.Nginx.Asn.Rules
	if len(rules) != 1 {
		t.Fatalf("Rules has %d entries, want 1", len(rules))
	}
	r := rules[0]
	if r.ASN != 398781 || r.Label != "Acme Hosting" || r.Action != "pow_then_captcha" {
		t.Errorf("rule = %+v, want AS398781 / Acme Hosting / pow_then_captcha", r)
	}
	if !r.Enabled {
		t.Error("the rule was added disabled")
	}
	if r.CreatedAt <= 0 {
		t.Error("the rule has no creation date")
	}
	// Rate stays unset so the rule inherits: a ranking row says nothing about
	// throttling, and a pinned 0 would silently mean "act on every request".
	if r.RatePerMin != nil {
		t.Errorf("rate = %v, want unset (inherit)", *r.RatePerMin)
	}

	// A second rule for the same network would be dead weight -- only the
	// first is evaluated -- and the ranking marks the network as covered.
	if err := h.appendASNRule(req, 398781, "", "deny", "admin", 1); err == nil {
		t.Error("a duplicate rule for the same AS was accepted")
	}
	if err := h.appendASNRule(req, 64500, "", "not-an-action", "admin", 1); err == nil {
		t.Error("an unknown action was accepted")
	}
}

// The BAN file is re-read by mtime, so a BAN is live when it is written.  A UA
// or ASN rule is a line in the nginx config and is not -- unmask renders it
// and never reloads.  Reporting both as "applied" was true of only one.
func TestRuleOpsSayTheyNeedAReload(t *testing.T) {
	h := ruleTestHandler(t)

	post := func(form string) string {
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/hunt/action", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey{},
			&SessionPayload{UserID: 1, Role: "admin"}))
		rr := httptest.NewRecorder()
		h.AdminHuntAction(rr, req)
		return rr.Header().Get("Location")
	}
	if loc := post("op=ua_blacklist&pattern=Bytespider&title=t&range=1h"); !strings.Contains(loc, "reload=1") {
		t.Errorf("UA rule redirected to %q: the banner will claim it is already applied", loc)
	}
	if loc := post("op=asn_rule&asn=64500&action=deny&range=1h"); !strings.Contains(loc, "reload=1") {
		t.Errorf("ASN rule redirected to %q: the banner will claim it is already applied", loc)
	}
}

// A pattern that compiles is not a pattern that works.  Pasting a UA verbatim
// produces one that passes every check and matches nothing: "(X11; Linux
// x86_64)" is a capture group, so the pattern requires the UA with its
// parentheses removed.  The dialog offered exactly that as its "full UA"
// option, and an operator who typed one by hand got the same silence -- the
// rule sat in the config looking correct while the traffic walked past it.
func TestFullUAOptionProducesAPatternThatMatches(t *testing.T) {
	for _, ua := range []string{
		`Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36`,
		`Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15`,
		`OmvionLeadLake/1.0 (+https://omvion.org/crawler)`,
		`curl/8.0`,
		`Some[Bot]/1.0 {beta} a|b`,
	} {
		// The raw string is the trap: valid, accepted, and inert.
		if re, err := regexp.Compile(ua); err == nil && !re.MatchString(ua) {
			// expected for anything carrying regex syntax -- this is the bug
		} else if err != nil {
			continue // an invalid regex is caught by validUAPattern already
		}

		pat := uaLiteralPatternForTest(ua)
		if err := validUAPattern(pat); err != nil {
			t.Errorf("%q -> %q: the escaped form is rejected: %v", ua, pat, err)
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			t.Errorf("%q -> %q: does not compile: %v", ua, pat, err)
			continue
		}
		if !re.MatchString(ua) {
			t.Errorf("%q -> %q: the escaped pattern does not match the UA it came from", ua, pat)
		}
	}
}

// uaLiteralPatternForTest mirrors the dialog's uaLiteralPattern (hunt.html).
// Kept in step by TestDialogEscapesTheSameCharacters below.
func uaLiteralPatternForTest(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`.*+?()[{|$`, r) {
			b.WriteString("[" + string(r) + "]")
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// The dialog no longer escapes on the operator's behalf -- it asks how the
// pattern should be read and resolves it the same way the server does.  What
// has to hold is that the two agree, and that the dialog says up front whether
// the rule will match the UA it was built from.
func TestDialogResolvesPatternsTheSameWayTheServerDoes(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/hunt.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)
	if !strings.Contains(tpl, "function asRegex(") {
		t.Fatal("the dialog no longer resolves a pattern before checking it")
	}
	for _, want := range []string{"'^' + q + '$'", "mode === 'regex'"} {
		if !strings.Contains(tpl, want) {
			t.Errorf("the dialog's resolver is missing %s, so its reading differs from the server's", want)
		}
	}
	// The check that catches a pattern which is valid but wrong.
	if !strings.Contains(tpl, "!re.test(srcUA)") {
		t.Error("the dialog does not verify the pattern against the UA it came from")
	}
	// The marker has to go on at submit time, or the row is stored as a regex
	// whatever the operator picked.
	if !strings.Contains(tpl, "MARKERS[curMode()]") {
		t.Error("the dialog does not record the chosen reading on the stored pattern")
	}
	// A UA from the ranking is a whole string, so exact is the default; the
	// token option is a fragment and can only be contains.
	if !strings.Contains(tpl, `value="exact" checked`) {
		t.Error("the dialog does not default to exact for a UA taken whole")
	}
	if !strings.Contains(tpl, `setMode(ev.target.value === 'token' ? 'contains' : 'exact')`) {
		t.Error("picking the token does not move the reading to contains, so the rule would match nothing")
	}
}
