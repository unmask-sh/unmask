package nginxconf

import (
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// pinFreshSnapshot makes the derivation see address data of a fixed, fresh
// vintage for the duration of one test — the embed's real age must never
// decide a test's outcome (it grows by itself until the next release).
func pinFreshSnapshot(t *testing.T, age time.Duration) {
	t.Helper()
	prev := snapshotDataAtFn
	snapshotDataAtFn = func() time.Time { return time.Now().Add(-age) }
	t.Cleanup(func() { snapshotDataAtFn = prev })
}

func nginxWithSearchBots(sb settings.SearchBotsConfig) settings.Nginx {
	var n settings.Nginx
	n.SearchBots = sb
	return n
}

// The headline case: an install whose saved preset list predates the claude
// preset, UA filter untouched.  ClaudeBot passes by name today, so the
// derivation enables the claude preset — the flip to address verification.
func TestAutoBypassDerivesFromUAPass(t *testing.T) {
	pinFreshSnapshot(t, time.Hour)
	n := nginxWithSearchBots(settings.SearchBotsConfig{})
	auto := AutoBypassPresetIDs(n)
	pats, ok := auto["claude"]
	if !ok {
		t.Fatalf("claude preset not derived; got %v", auto)
	}
	found := false
	for _, p := range pats {
		if strings.Contains(p, "laude") {
			found = true
		}
	}
	if !found {
		t.Fatalf("claude preset justified by unexpected patterns: %v", pats)
	}
	if _, ok := auto["amazonbot"]; !ok {
		t.Fatalf("amazonbot preset not derived (its UA passes by default)")
	}
}

// A vendor the operator explicitly challenges must never gain an address
// bypass: bypass outranks the challenge axes, so deriving here would override
// an explicit block.
func TestAutoBypassRespectsBlocks(t *testing.T) {
	pinFreshSnapshot(t, time.Hour)

	// Per-pattern disable: every Anthropic pattern off -> no claude preset.
	n := nginxWithSearchBots(settings.SearchBotsConfig{
		UpstreamDisabled: []string{
			`[cC]laude[bB]ot`, `Claude-User`, `Claude-SearchBot`, `Claude-Web`, `anthropic-ai`,
		},
	})
	if auto := AutoBypassPresetIDs(n); auto["claude"] != nil {
		t.Fatalf("claude derived despite every pattern disabled: %v", auto["claude"])
	}

	// Group mode black: ai-user / ai-training groups challenged -> none of
	// their vendors derive.
	n2 := nginxWithSearchBots(settings.SearchBotsConfig{
		UpstreamGroupMode: map[string]string{
			"ai-user": "black", "ai-training": "black", "search-engine": "black",
		},
	})
	auto2 := AutoBypassPresetIDs(n2)
	for _, id := range []string{"claude", "openai-gptbot", "google-common"} {
		if auto2[id] != nil {
			t.Fatalf("%s derived despite its group set to black: %v", id, auto2[id])
		}
	}
}

// Explicit rows and recorded opt-outs are both left alone.
func TestAutoBypassExplicitAndExcluded(t *testing.T) {
	pinFreshSnapshot(t, time.Hour)
	n := nginxWithSearchBots(settings.SearchBotsConfig{})
	n.BypassIPEnabledPresets = []string{"claude"}
	n.BypassIPAutoExcluded = []string{"amazonbot"}
	auto := AutoBypassPresetIDs(n)
	if auto["claude"] != nil {
		t.Fatalf("explicitly enabled preset re-derived")
	}
	if auto["amazonbot"] != nil {
		t.Fatalf("opted-out preset derived anyway")
	}
	eff := EffectiveBypassIPPresets(n)
	effSet := map[string]bool{}
	for _, id := range eff {
		effSet[id] = true
	}
	if !effSet["claude"] {
		t.Fatalf("explicit preset missing from effective list: %v", eff)
	}
	if effSet["amazonbot"] {
		t.Fatalf("opted-out preset in effective list: %v", eff)
	}
}

// The kill switch and the freshness gate both stop the derivation cold.
func TestAutoBypassGates(t *testing.T) {
	off := false
	n := nginxWithSearchBots(settings.SearchBotsConfig{})
	n.BypassIPAutoFromUA = &off
	pinFreshSnapshot(t, time.Hour)
	if auto := AutoBypassPresetIDs(n); len(auto) != 0 {
		t.Fatalf("feature off but derived: %v", auto)
	}

	n2 := nginxWithSearchBots(settings.SearchBotsConfig{})
	pinFreshSnapshot(t, AutoBypassMaxSnapshotAge+time.Hour)
	if auto := AutoBypassPresetIDs(n2); len(auto) != 0 {
		t.Fatalf("stale snapshot but derived: %v", auto)
	}
	ids, _, suspended := AutoBypassSuspended(n2)
	if !suspended || len(ids) == 0 {
		t.Fatalf("stale snapshot not reported as suspended (ids=%v suspended=%v)", ids, suspended)
	}
}

func TestSnapshotFreshEnoughBoundary(t *testing.T) {
	now := time.Now()
	if snapshotFreshEnough(time.Time{}, now) {
		t.Fatal("zero vintage counted as fresh")
	}
	if !snapshotFreshEnough(now.Add(-AutoBypassMaxSnapshotAge+time.Minute), now) {
		t.Fatal("data inside the ceiling counted as stale")
	}
	if snapshotFreshEnough(now.Add(-AutoBypassMaxSnapshotAge-time.Minute), now) {
		t.Fatal("data past the ceiling counted as fresh")
	}
}

// The derived preset flips the vendor's UA rescue off (uarange resolution) —
// the whole point: name-pass becomes address-verification, one direction, no
// oscillation.
func TestAutoBypassFlipsUARescue(t *testing.T) {
	pinFreshSnapshot(t, time.Hour)
	n := nginxWithSearchBots(settings.SearchBotsConfig{})
	uaOff := EffectiveUpstreamUAOff(n)
	if !uaOff[`[cC]laude[bB]ot`] {
		t.Fatalf("ClaudeBot UA rescue still on despite auto-derived claude preset")
	}
	// And the matcher actually carries the vendor's addresses.
	g := bypassIPGroupByID("claude")
	if g == nil || g.PrefixCount() == 0 {
		t.Fatal("claude group empty — embed missing?")
	}
	m := NewChallengeBypassMatcher(n)
	probe := strings.TrimSpace(g.Prefixes()[0])
	ip := probe
	if i := strings.Index(probe, "/"); i > 0 {
		ip = probe[:i]
	}
	if !m.Match(ip) {
		t.Fatalf("matcher does not carry auto-derived claude address %s", ip)
	}
}
