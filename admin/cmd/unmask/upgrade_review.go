package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// cmdUpgradeReview inspects and manages the "don't silently change enforcement
// on upgrade" hold from the shell -- the headless / fleet path that does not go
// through the settings UI.
//
//	unmask upgrade-review                 # list held enforcement presets
//	unmask upgrade-review --apply         # acknowledge: activate all held presets
//	unmask upgrade-review --policy review # set the policy (review | apply)
func cmdUpgradeReview(args []string) error {
	fs := flag.NewFlagSet("upgrade-review", flag.ExitOnError)
	configPath := fs.String("config", os.Getenv("UNMASK_CONFIG"), "path to config.yml")
	apply := fs.Bool("apply", false, "acknowledge the upgrade: activate every held enforcement preset")
	policy := fs.String("policy", "", `set the upgrade-review policy: "review" or "apply"`)
	_ = fs.Parse(args)

	resolved := settings.ResolvePath(*configPath)
	s, err := settings.Load(resolved)
	if err != nil {
		return fmt.Errorf("load config %s: %w", resolved, err)
	}

	// --policy: set and persist.
	if *policy != "" {
		switch *policy {
		case settings.UpgradeReviewApply, settings.UpgradeReviewReview:
		default:
			return fmt.Errorf("invalid -policy %q (want %q or %q)", *policy, settings.UpgradeReviewReview, settings.UpgradeReviewApply)
		}
		s.Nginx.UpgradeReviewPolicy = *policy
		// Switching TO review with no baseline would hold nothing until a later
		// ack; stamp the current version so review protects upgrades from here on
		// (a no-op for "apply", and it never overwrites an existing baseline).
		if *policy == settings.UpgradeReviewReview && !nginxconf.VersionParseable(s.Nginx.EnforcementReviewedVersion) {
			s.Nginx.EnforcementReviewedVersion = "v" + Version
		}
		if err := settings.Save(s, resolved); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		fmt.Printf("upgrade-review policy set to %q in %s\n", *policy, resolved)
		fmt.Println("re-render and reload nginx to apply: unmask render-nginx && nginx -s reload")
		return nil
	}

	held := nginxconf.HeldEnforcementPresets(s)

	// --apply: acknowledge the upgrade -> advance the reviewed version so every
	// held preset activates on the next render.
	if *apply {
		if s.Nginx.ResolvedUpgradeReviewPolicy() != settings.UpgradeReviewReview {
			fmt.Printf("policy is %q: nothing is held, nothing to acknowledge.\n", settings.UpgradeReviewApply)
			return nil
		}
		if len(held) == 0 {
			fmt.Println("no held enforcement presets; nothing to acknowledge.")
			return nil
		}
		s.Nginx.EnforcementReviewedVersion = "v" + Version
		if err := settings.Save(s, resolved); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		fmt.Printf("acknowledged %d enforcement preset(s), reviewed up to v%s:\n", len(held), Version)
		for _, h := range held {
			fmt.Printf("  + [%s] %s (added %s)\n", h.Category, h.ID, h.AddedIn)
		}
		fmt.Println("re-render and reload nginx to activate: unmask render-nginx && nginx -s reload")
		return nil
	}

	// default: report status + list held presets.
	reviewed := s.Nginx.EnforcementReviewedVersion
	if reviewed == "" {
		reviewed = "(unset -- runs tip, nothing held)"
	}
	fmt.Printf("upgrade-review policy:        %s\n", s.Nginx.ResolvedUpgradeReviewPolicy())
	fmt.Printf("enforcement reviewed up to:  %s\n", reviewed)
	fmt.Printf("this binary:                 v%s\n\n", Version)
	if len(held) == 0 {
		fmt.Println("no enforcement presets are held for review.")
		return nil
	}
	fmt.Printf("%d enforcement preset(s) held pending review (inert until acknowledged):\n", len(held))
	for _, h := range held {
		fmt.Printf("  [%-16s] %-22s %s (added %s)\n", h.Category, h.ID, h.Label, h.AddedIn)
	}
	fmt.Println("\nactivate all with: unmask upgrade-review --apply")
	return nil
}
