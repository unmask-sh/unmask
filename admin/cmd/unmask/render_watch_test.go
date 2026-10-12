package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestRenderAfterGeoUpdate: a GeoIP update renders, and the log says whether
// nginx's configuration moved (and so whether a reload is due) -- or that the
// render failed.
func TestRenderAfterGeoUpdate(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	observe := false
	calls := 0
	render := func() error {
		calls++
		var s settings.Settings
		s.Nginx.OutputDir = dir
		s.Nginx.ConfPath = conf
		if observe {
			s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
		}
		return nginxconf.Render(s, dir, "test")
	}

	renderAfterGeoUpdate(render, dir) // nothing rendered before: a change
	if calls != 1 || !strings.Contains(buf.String(), "changed nginx's configuration (render - -> ") {
		t.Errorf("first render: calls=%d log=%q", calls, buf.String())
	}
	buf.Reset()
	renderAfterGeoUpdate(render, dir)
	if !strings.Contains(buf.String(), "left nginx's configuration unchanged") {
		t.Errorf("same configuration: log=%q", buf.String())
	}
	buf.Reset()
	observe = true // stands in for ranges the new snapshot moved
	renderAfterGeoUpdate(render, dir)
	if !strings.Contains(buf.String(), "reload nginx to apply it") {
		t.Errorf("changed configuration: log=%q", buf.String())
	}
	buf.Reset()
	renderAfterGeoUpdate(func() error { return errors.New("disk full") }, dir)
	if !strings.Contains(buf.String(), "render after the update failed: disk full") {
		t.Errorf("failed render: log=%q", buf.String())
	}
}
