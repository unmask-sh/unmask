// install_ipgeo.go — `unmask install-ipgeo` sub-command.
//
// Fetches the current month's DB-IP Country Lite mmdb (= CC BY 4.0)
// and atomically installs it to /var/lib/unmask/mmdb/dbip-country.mmdb
// (or the path passed via -path / configured in admin.yml).
//
// The action is named "install-ipgeo" rather than "install-mmdb" because
// mmdb is a generic file format that could in principle carry any IP-keyed
// data; this command specifically installs the IP-geolocation database.
//
// If a running admin daemon was using the old DB, it picks up the new file
// on the next settings save / SIGHUP / restart.  For zero-touch reload use
// the web UI's 1-click install button (= calls the same library function
// and reloads in-process).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func cmdInstallIPGeo(args []string) error {
	fs := flag.NewFlagSet("install-ipgeo", flag.ExitOnError)
	configPath := fs.String("config", os.Getenv("UNMASK_CONFIG"), "path to admin.yml")
	pathOverride := fs.String("path", "", "destination path (= overrides config / default)")
	kindFlag := fs.String("kind", "country", "which DB to fetch (= country / asn)")
	urlTemplate := fs.String("url", "", "override URL template (= must contain %s for YYYY-MM; testing only)")
	quiet := fs.Bool("quiet", false, "suppress success output (= cron-friendly)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	kindRaw := strings.ToLower(strings.TrimSpace(*kindFlag))
	// Allow "all" / "both" to fetch country + asn in one invocation (=
	// common cron pattern: monthly refresh of every DB the admin uses).
	if kindRaw == "all" || kindRaw == "both" {
		errs := []string{}
		for _, k := range []ipgeo.InstallKind{ipgeo.InstallKindCountry, ipgeo.InstallKindASN} {
			if err := installOneIPGeo(k, *pathOverride, *configPath, *urlTemplate, *quiet); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", k, err))
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("install-ipgeo (some kinds failed):\n  - %s", strings.Join(errs, "\n  - "))
		}
		return nil
	}
	kind := ipgeo.InstallKind(kindRaw)
	switch kind {
	case ipgeo.InstallKindCountry, ipgeo.InstallKindASN:
	default:
		return fmt.Errorf("install-ipgeo: -kind must be country / asn / all (got %q)", *kindFlag)
	}
	return installOneIPGeo(kind, *pathOverride, *configPath, *urlTemplate, *quiet)
}

// installOneIPGeo is the per-kind worker shared by the single-kind and
// "all" code paths.  Reads the configured destination path (= overridable
// via -path) and delegates to ipgeo.InstallDBIPLite.
func installOneIPGeo(kind ipgeo.InstallKind, pathOverride, configPath, urlTemplate string, quiet bool) error {
	// Resolve destination path: -path > config (matching kind) > library default.
	path := strings.TrimSpace(pathOverride)
	if path == "" {
		if cfg, err := settings.Load(configPath); err == nil {
			if kind == ipgeo.InstallKindASN {
				path = strings.TrimSpace(cfg.IPGeo.MMDBASNPath)
			} else {
				path = strings.TrimSpace(cfg.IPGeo.MMDBPath)
			}
		}
	}
	if path == "" {
		path = ipgeo.DefaultPathForKind(kind)
	}

	res, err := ipgeo.InstallDBIPLite(ipgeo.InstallOptions{
		Kind:        kind,
		Path:        path,
		URLTemplate: urlTemplate,
	})
	if err != nil {
		// Hint actionable diagnostics for the common failure modes.
		hint := ""
		if errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission") {
			hint = "\n  hint: run as root or chown the ipgeo directory to the unmask user"
		} else if strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "dial tcp") {
			hint = "\n  hint: check outbound HTTPS to download.db-ip.com is reachable"
		}
		return fmt.Errorf("install-ipgeo: %w%s", err, hint)
	}

	if quiet {
		return nil
	}
	fmt.Printf("install-ipgeo[%s]: OK\n", kind)
	fmt.Printf("  path     : %s\n", res.Path)
	fmt.Printf("  source   : %s\n", res.Source)
	fmt.Printf("  month    : %s%s\n", res.Month, fallbackNote(res.Fallback))
	fmt.Printf("  size     : %d bytes\n", res.Bytes)
	fmt.Println()
	return nil
}

func fallbackNote(b bool) string {
	if b {
		return " (= fell back to previous month; current month not yet published)"
	}
	return ""
}
