// render-nginx: generate the nginx config snippets from config.yml + embedded
// preset.  Native mode: http.inc (http-scope directives + maps),
// server.inc, protect.inc.  Forward-auth mode: forward-auth-lbtrust.conf (the
// LB-trust JA4 gate) and upstream.conf (`upstream unmask_daemon`) -- the latter,
// once hand-written by the postinstall to /etc/unmask, now renders to output_dir
// so it tracks server.bind / port.
// Per-host gating of the admin UI is done at the HTTP layer via
// settings.Nginx.AdminAllowedHosts; nginx unconditionally proxies /unmask/*
// for every Host that includes server.inc.
//
// Usage:
//
//	unmask render-nginx                       # write to config.yml output_dir
//	unmask render-nginx -out-dir /var/lib/unmask/nginx  # explicit dir
//	unmask render-nginx -dry-run              # print to stdout only
//
// Apply with a separate `nginx -s reload` (= unmask does not touch nginx itself).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/browsermajors"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

func cmdRenderNginx(args []string) error {
	fs := flag.NewFlagSet("render-nginx", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	outDir := fs.String("out-dir", "", "output dir (= falls back to nginx.output_dir in config.yml when empty)")
	dryRun := fs.Bool("dry-run", false, "render to stdout instead of files")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}

	// Load the hub-pulled bypass IP ranges (Googlebot / Bingbot / AI crawlers)
	// the daemon keeps under SyncDefaultDir, exactly as cmdServe's iprange Sync
	// does, so a standalone render-nginx produces the SAME bypass map as the
	// running daemon.  Without this the command was embed-only: re-rendering on
	// a node that has already pulled would drop those ranges and the native
	// plugin would start challenging search bots (= ranking accident).  Empty /
	// absent dir falls back to the embedded snapshot, so installs that never
	// pulled are unaffected.
	nginxconf.SetOverrideDir(nginxconf.SyncDefaultDir)

	// Load the hub-pulled browser baselines (stale-browser tier) the daemon
	// persists, for the same reason: a standalone render must emit the SAME
	// $unmask_stale_browser pattern as the running daemon.  Absent state falls
	// back to the shipped built-ins.
	if err := browsermajors.LoadState(""); err != nil {
		fmt.Fprintf(os.Stderr, "warning: browser-majors state: %v (using built-in baselines)\n", err)
	}

	// Probe nginx so Render's "auto" rate-compose mode resolves the SAME way the
	// daemon does (compose on nginx 1.17.6+, classic below) -- otherwise a
	// standalone render on a modern host would emit classic while serve emits
	// compose.  Skipped (→ classic) when nginx isn't on PATH.  See cmdServe.
	dryOK, ngxVer, ngxDetected := nginxconf.DetectDryRunSupport()
	if ngxDetected {
		nginxconf.SetDryRunSupported(dryOK)
	}
	// Warn on stderr (never stdout: -dry-run pipes the config there) when the
	// resolved mode would emit a config nginx can't load -- e.g.
	// rate_compose_mode=always on a confirmed < 1.17.6 nginx renders a
	// limit_req_dry_run that fails `nginx -t`.  serve/doctor warn too; render is
	// the command most likely run before a reload, so it must not stay silent.
	if diag := nginxconf.DiagnoseComposeMode(s, ngxVer, ngxDetected, dryOK); diag.Level != nginxconf.ComposeDiagOK {
		tag := "WARNING"
		if diag.Level == nginxconf.ComposeDiagError {
			tag = "ERROR"
		}
		fmt.Fprintf(os.Stderr, "unmask render-nginx: %s: %s\n", tag, diag.Message)
	}

	// renderedFiles: the files nginxconf.Render writes, relative to outDir.
	// Keep in sync with internal/nginxconf/render.go::Render.
	renderedFiles := []string{
		"http.inc",
		"server.inc",
		"protect.inc",
	}

	if *dryRun {
		// dry-run: write to temp dir, then dump every file to stdout.
		tmpDir, err := os.MkdirTemp("", "unmask-render-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpDir)
		if err := nginxconf.Render(s, tmpDir, Version); err != nil {
			return err
		}
		for _, name := range renderedFiles {
			body, err := os.ReadFile(filepath.Join(tmpDir, name))
			if err != nil {
				return err
			}
			fmt.Printf("# === %s ===\n%s\n", name, body)
		}
		return nil
	}

	dst := *outDir
	if dst == "" {
		dst = s.Nginx.OutputDir
	}
	// Read the PoW difficulty the running nginx is still enforcing BEFORE the
	// render overwrites it, so the warning below can compare the two.
	prevDiff := renderedPowDifficulty(filepath.Join(dst, "http.inc"))

	if err := nginxconf.Render(s, *outDir, Version); err != nil {
		return err
	}
	for _, name := range renderedFiles {
		fmt.Fprintf(os.Stderr, "rendered: %s\n", filepath.Join(dst, name))
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "To apply:  sudo nginx -s reload")
	// Lowering the PoW difficulty is the one config change that BREAKS the site
	// until the reload lands, and it does so silently.  The daemon starts
	// serving easier puzzles the moment it restarts, while the native plugin
	// keeps verifying against the value nginx parsed at its last reload: a
	// solve two bits short of the old gate passes only 1 time in 4, so the
	// visitor solves, is refused, and is challenged again -- about four times
	// on average before one happens to clear.  Seen in production 2026-08-04,
	// reported as "the PoW screen loops about five times".
	//
	// Ordering rule: lower the GATE first (this render + a reload), then the
	// daemon.  Raising is the mirror image -- old solves stop clearing the new
	// gate -- but that resolves itself as cookies are re-minted, so only the
	// dangerous direction is called out here.
	if newDiff := s.Challenge.Default.ResolvedPowDifficulty(); prevDiff > 0 && newDiff < prevDiff {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "WARNING: PoW difficulty drops %d -> %d bits.  Until nginx reloads it keeps\n", prevDiff, newDiff)
		fmt.Fprintf(os.Stderr, "         verifying against %d, so roughly %d%% of the solves the daemon is\n",
			prevDiff, 100-100/(1<<uint(prevDiff-newDiff)))
		fmt.Fprintln(os.Stderr, "         already handing out will be refused and those visitors re-challenged")
		fmt.Fprintln(os.Stderr, "         in a loop.  Reload now:")
		fmt.Fprintln(os.Stderr, "             sudo nginx -t && sudo nginx -s reload")
	}
	// Reload is the right advice for a config-only change -- but not while the
	// running nginx still maps libraries a package already replaced, where a
	// reload forks fresh workers from the stale master image and they can
	// segfault.  This hint lands exactly where it is needed: a package upgrade
	// runs render-nginx from its postinstall, so the operator reads this line
	// moments before deciding how to apply.  Silent when nothing is stale or
	// when the running nginx cannot be inspected (see staleNginxLibs).
	if paths, checked := staleNginxLibs(); checked && len(paths) > 0 {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintf(os.Stderr, "WARNING: the running nginx is executing %d %s that no longer match the file on\n",
			len(paths), plural(len(paths), "file", "files"))
		fmt.Fprintf(os.Stderr, "         disk (%s).  A reload does NOT re-exec the master, so it\n",
			staleNginxLibsList(paths))
		fmt.Fprintln(os.Stderr, "         keeps that stale mapping and its workers can segfault.  Restart instead:")
		fmt.Fprintln(os.Stderr, "             sudo systemctl restart nginx")
	}
	return nil
}

// renderedPowDifficulty reads the unmask_bv_pow_difficulty directive out of an
// already-rendered http.inc -- i.e. the value the running nginx parsed at its
// last reload.  0 when the file is absent or carries no such line (a fresh
// install, or a forward-auth deployment that renders no plugin directives), so
// callers treat it as "nothing to compare".
func renderedPowDifficulty(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || f[0] != "unmask_bv_pow_difficulty" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSuffix(f[1], ";"))
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}
