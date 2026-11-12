package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/handlers"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// `unmask upgrade-review --apply` is the headless path: it writes the
// acknowledgement into config.yml and tells the operator to render and
// reload nginx.  The running daemon used to read config.yml only at its
// start and inside its own saves, so its copy still held the presets, and
// its next render of its own -- the IP-range pull, the GeoIP update -- wrote
// the configuration from before the acknowledgement back over the CLI's.
// The config watch re-reads the file a few seconds after the command, and
// the daemon's renders are the acknowledged configuration from then on.
func TestUpgradeReviewApplyReachesTheRunningDaemon(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	out := filepath.Join(dir, "nginx")
	body := "server:\n  bind: 127.0.0.1\n  port: 19480\n" +
		"secret:\n  bv_secret: 0123456789abcdef0123456789abcdef\n" +
		"  captcha_secret_base: 0123456789abcdef0123456789abcdef\n" +
		"  admin_secret: 0123456789abcdef0123456789abcdef\n" +
		"nginx:\n  output_dir: " + out + "\n" +
		"  upgrade_review_policy: review\n  enforcement_reviewed_version: v0.1.50\n" +
		"  honeypot:\n    ban_file_path: " + filepath.Join(dir, "banned.txt") + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// The daemon as cmdServe starts it: the signature, the load, the watch.
	sig := settings.FileSignature(cfg)
	live, err := settings.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(nginxconf.HeldEnforcementPresets(live)) == 0 {
		t.Fatal("precondition: nothing is held")
	}
	h := &handlers.Handler{ConfigPath: cfg, Version: Version}
	h.SetSettings(live)
	h.SetConfigSignature(sig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.RunConfigWatch(ctx)

	// The operator, in another shell.
	if err := cmdUpgradeReview([]string{"-config", cfg, "-apply"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for len(nginxconf.HeldEnforcementPresets(h.SnapshotSettings())) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the running daemon still holds %v after the acknowledgement", nginxconf.HeldEnforcementPresets(h.SnapshotSettings()))
		}
		time.Sleep(100 * time.Millisecond)
	}

	// What the daemon renders on its own from here is what `unmask
	// render-nginx` renders from the file.
	read := func() map[string]string {
		m := map[string]string{}
		for _, f := range []string{"http.inc", "server.inc"} {
			b, err := os.ReadFile(filepath.Join(out, f))
			if err != nil {
				t.Fatal(err)
			}
			m[f] = nginxconf.MaskRenderID(nginxconf.StripRenderStamps(b))
		}
		return m
	}
	onDisk, err := settings.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := nginxconf.RenderFor(onDisk, out, Version, nginxconf.RenderCause{Kind: nginxconf.RenderByCLI}); err != nil {
		t.Fatal(err)
	}
	acked := read()
	if err := nginxconf.RenderFor(h.SnapshotSettings(), out, Version, nginxconf.RenderCause{Kind: nginxconf.RenderByIPRange, Detail: "relay"}); err != nil {
		t.Fatal(err)
	}
	daemon := read()
	for f := range acked {
		if acked[f] != daemon[f] {
			t.Errorf("%s: the daemon's own render differs from the acknowledged configuration", f)
		}
	}
}
