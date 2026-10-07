package nginxconf

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestPresetVersions: the settings page shows a preset's "since" and, where a
// later release changed it, "updated" beside it -- an "updated" that is not
// later than "since" would read as nonsense, and an unparseable one as a typo.
// A honeypot group's DefaultOnIn (the release the upgrade review holds it
// from) is a release after the group shipped opt-in, so it never sits on an
// opt-in group.
func TestPresetVersions(t *testing.T) {
	type pv struct{ kind, id, added, updated string }
	var all []pv
	for _, g := range JA4VerdictGroups {
		all = append(all, pv{"ja4", g.ID, g.AddedIn, g.UpdatedIn})
	}
	for _, g := range ChallengeTargetGroups {
		all = append(all, pv{"challenge-target", g.ID, g.AddedIn, g.UpdatedIn})
	}
	for _, g := range HoneypotPresetGroups {
		all = append(all, pv{"honeypot", g.ID, g.AddedIn, g.UpdatedIn})
		if g.DefaultOnIn != "" && (g.OptIn || !VersionParseable(g.DefaultOnIn) || !VersionLess(g.AddedIn, g.DefaultOnIn)) {
			t.Errorf("honeypot %s: on by default in %q, added in %q, opt-in %v", g.ID, g.DefaultOnIn, g.AddedIn, g.OptIn)
		}
	}
	for _, g := range BypassPathPresetGroups {
		all = append(all, pv{"bypass-path", g.ID, g.AddedIn, g.UpdatedIn})
	}
	for _, g := range ProtectedPathPresetGroups {
		all = append(all, pv{"protected-path", g.ID, g.AddedIn, g.UpdatedIn})
	}
	for _, g := range RedirectExemptPresetGroups {
		all = append(all, pv{"redirect-exempt", g.ID, g.AddedIn, g.UpdatedIn})
	}
	for _, g := range BypassIPGroups {
		all = append(all, pv{"bypass-ip", g.ID, g.AddedIn, g.UpdatedIn})
	}
	for _, g := range LBIPRanges {
		all = append(all, pv{"trusted-lb", g.ID, g.AddedIn, g.UpdatedIn})
	}
	for _, p := range settings.HostingProviders {
		all = append(all, pv{"asn-provider", p.ID, p.AddedIn, p.UpdatedIn})
	}
	for _, p := range all {
		added := p.added
		if added == "" {
			added = "v0.1.0" // shown without a "since": the first release
		}
		if !VersionParseable(added) {
			t.Errorf("%s %s: added in %q", p.kind, p.id, p.added)
		}
		if p.updated != "" && (!VersionParseable(p.updated) || !VersionLess(added, p.updated)) {
			t.Errorf("%s %s: updated in %q, which is not after it was added (%s)", p.kind, p.id, p.updated, added)
		}
	}
}
