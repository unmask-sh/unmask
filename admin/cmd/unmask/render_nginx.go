// render-nginx: generate the nginx config snippets from config.yml + embedded
// preset.  Native mode: http.inc (with its own `upstream unmask` at the tail),
// server.inc, protect.inc.  Forward-auth mode: forward-auth-lbtrust.conf (the
// LB-trust JA4 gate) and upstream.conf (`upstream unmask_admin`) -- the latter,
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

	if err := nginxconf.Render(s, *outDir, Version); err != nil {
		return err
	}
	dst := *outDir
	if dst == "" {
		dst = s.Nginx.OutputDir
	}
	for _, name := range renderedFiles {
		fmt.Fprintf(os.Stderr, "rendered: %s\n", filepath.Join(dst, name))
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "To apply:  sudo nginx -s reload")
	return nil
}
