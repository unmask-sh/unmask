package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestCheckHTTPSRedirectApplied covers the stale-render warning for the
// nginx.https_redirect option:
//  1. option off -> silent, whatever the rendered file says
//  2. on + rendered 301 present -> OK
//  3. on + rendered server.inc without the 301 -> WARN (stale render)
//  4. on + nothing rendered yet -> silent (render checks cover that)
func TestCheckHTTPSRedirectApplied(t *testing.T) {
	write := func(t *testing.T, dir, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "server.inc"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("off is silent", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "server config without redirect\n")
		var s settings.Settings
		s.Nginx.OutputDir = dir
		cap, addOK, addWarn, _ := newCaptures()
		checkHTTPSRedirectApplied(s, addOK, addWarn)
		if len(cap.ok)+len(cap.warn) != 0 {
			t.Errorf("expected silence, got ok=%v warn=%v", cap.ok, cap.warn)
		}
	})

	t.Run("on and rendered -> OK", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "if ($unmask_forwarded_proto = \"http\") {\n    return 301 https://$host$request_uri;\n}\n")
		var s settings.Settings
		s.Nginx.OutputDir = dir
		s.Nginx.HTTPSRedirect = true
		cap, addOK, addWarn, _ := newCaptures()
		checkHTTPSRedirectApplied(s, addOK, addWarn)
		if len(cap.ok) != 1 || len(cap.warn) != 0 {
			t.Errorf("expected 1 OK, got ok=%v warn=%v", cap.ok, cap.warn)
		}
	})

	t.Run("on but stale render -> WARN", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "server config without redirect\n")
		var s settings.Settings
		s.Nginx.OutputDir = dir
		s.Nginx.HTTPSRedirect = true
		cap, addOK, addWarn, _ := newCaptures()
		checkHTTPSRedirectApplied(s, addOK, addWarn)
		if len(cap.warn) != 1 || len(cap.ok) != 0 {
			t.Errorf("expected 1 WARN, got ok=%v warn=%v", cap.ok, cap.warn)
		}
	})

	t.Run("nothing rendered is silent", func(t *testing.T) {
		var s settings.Settings
		s.Nginx.OutputDir = t.TempDir() // no server.inc
		s.Nginx.HTTPSRedirect = true
		cap, addOK, addWarn, _ := newCaptures()
		checkHTTPSRedirectApplied(s, addOK, addWarn)
		if len(cap.ok)+len(cap.warn) != 0 {
			t.Errorf("expected silence, got ok=%v warn=%v", cap.ok, cap.warn)
		}
	})
}
