// render-nginx: generate nginx-rendered.conf and nginx-rendered-server.conf
// (2 files) from config.yml + embedded preset.
//
// Usage:
//
//	unmask-admin render-nginx                       # write to config.yml output_dir
//	unmask-admin render-nginx -out-dir /etc/unmask  # explicit dir
//	unmask-admin render-nginx -dry-run              # print to stdout only
//
// Apply with a separate `nginx -s reload` (= unmask does not touch nginx itself).
package main

import (
	"flag"
	"fmt"
	"os"

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

	if *dryRun {
		// dry-run: write to temp dir, then dump both files to stdout.
		tmpDir, err := os.MkdirTemp("", "unmask-render-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpDir)
		if err := nginxconf.Render(s, tmpDir, Version); err != nil {
			return err
		}
		for _, name := range []string{"nginx-rendered.conf", "nginx-rendered-server.conf"} {
			body, err := os.ReadFile(tmpDir + "/" + name)
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
	fmt.Fprintf(os.Stderr, "rendered: %s/nginx-rendered.conf\n", dst)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "To apply:  sudo nginx -s reload")
	return nil
}
