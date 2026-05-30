// render-nginx: generate the native-mode snippets (native/http.inc,
// native/server.inc, native/protect.inc, upstream.conf) from config.yml +
// embedded preset.
//
// Usage:
//
//	unmask render-nginx                       # write to config.yml output_dir
//	unmask render-nginx -out-dir /etc/unmask  # explicit dir
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

	// renderedFiles: the files nginxconf.Render writes, relative to outDir.
	renderedFiles := []string{
		"native/http.inc",
		"native/server.inc",
		"native/protect.inc",
		"upstream.conf",
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
