// preset: apply a protection-mode preset in one line.
//
//	unmask-admin apply-preset strict          # challenge all UAs (v0.2 default)
//	unmask-admin apply-preset balanced        # known browsers only (v0.1 default)
//	unmask-admin apply-preset monitor         # observe only (= suppress challenges)
//
// Flow:
//
//  1. load config.yml
//  2. presets.Apply() rewrites related fields (= currently ChallengeTargets.All only)
//  3. settings.Save() atomically writes back to the same path
//  4. user restarts admin serve (= reload settings)
//
// Existing per-user tuning (= JA4 verdict / honeypot / rate-limit zones etc.) is
// left alone.  The preset is a starting point, not a replacement for hand tuning.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/unmask-sh/unmask/admin/internal/presets"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func cmdApplyPreset(args []string) error {
	fs := flag.NewFlagSet("apply-preset", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: unmask-admin apply-preset <mode> [-config PATH]\n\nmodes:\n")
		for _, m := range []presets.Mode{presets.ModeStrict, presets.ModeBalanced, presets.ModeMonitor} {
			fmt.Fprintf(os.Stderr, "  %-9s %s\n", m, presets.Describe(m))
		}
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("mode is required")
	}
	mode := presets.Mode(fs.Arg(0))
	if !mode.IsValid() {
		return fmt.Errorf("unknown mode: %q (valid: strict / balanced / monitor)", mode)
	}

	path := *configPath
	if path == "" {
		path = os.Getenv("UNMASK_CONFIG")
	}
	if path == "" {
		path = "/etc/unmask/config.yml"
	}

	s, err := settings.Load(path)
	if err != nil {
		return fmt.Errorf("load %s: %w", path, err)
	}
	if err := presets.Apply(&s, mode); err != nil {
		return fmt.Errorf("apply preset: %w", err)
	}
	if err := settings.Save(s, path); err != nil {
		return fmt.Errorf("save %s: %w", path, err)
	}
	fmt.Printf("applied preset %q to %s\n", mode, path)
	fmt.Println("→ restart admin serve to apply (systemctl restart unmask-admin)")
	return nil
}
