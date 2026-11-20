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
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

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

// TestRenderAtStart: the daemon's start renders from the settings it read.
// Settings that were rendered before move nothing and the log stays quiet;
// settings changed while the daemon was stopped are rendered, named as the
// start's in the record the reload notice reads, and the log asks for the
// reload; a failed render is said.
func TestRenderAtStart(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	settingsWith := func(observe bool) settings.Settings {
		var s settings.Settings
		s.Nginx.OutputDir = dir
		s.Nginx.ConfPath = conf
		if observe {
			s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
		}
		return s
	}
	// The last render before the stop: `unmask render-nginx` at install.
	if err := nginxconf.RenderFor(settingsWith(false), dir, "test", nginxconf.RenderCause{Kind: nginxconf.RenderByCLI}); err != nil {
		t.Fatal(err)
	}
	startWith := func(observe bool) func() error {
		return func() error {
			return nginxconf.RenderFor(settingsWith(observe), dir, "test", nginxconf.RenderCause{Kind: nginxconf.RenderByStart})
		}
	}

	renderAtStart(startWith(false), dir) // the settings it was rendered from
	if buf.Len() != 0 {
		t.Errorf("same settings: the log says %q, want nothing", buf.String())
	}
	if rec, ok := nginxconf.ReadRenderRecord(dir); !ok || rec.Cause.Kind != nginxconf.RenderByCLI {
		t.Errorf("same settings: the record says %+v (ok=%v), want the install's render still", rec.Cause, ok)
	}

	before, _ := nginxconf.RenderIDOnDisk(dir)
	renderAtStart(startWith(true), dir) // config.yml edited while it was stopped
	after, _ := nginxconf.RenderIDOnDisk(dir)
	if after == before {
		t.Fatalf("changed settings: the render id stayed %s", after)
	}
	if want := "(render " + before + " -> " + after + "); reload nginx to apply it"; !strings.Contains(buf.String(), want) {
		t.Errorf("changed settings: log=%q, want it to contain %q", buf.String(), want)
	}
	if rec, ok := nginxconf.ReadRenderRecord(dir); !ok || rec.Cause.Kind != nginxconf.RenderByStart || len(rec.Changes) == 0 {
		t.Errorf("changed settings: the record says %+v (ok=%v), want the start's with the changes", rec, ok)
	}

	buf.Reset()
	renderAtStart(func() error { return errors.New("disk full") }, dir)
	if !strings.Contains(buf.String(), "rendering nginx's configuration at start failed: disk full") {
		t.Errorf("failed render: log=%q", buf.String())
	}
}
