package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

// The plugin's fail-safe marker is an error in the doctor (protection is
// off), with the cause place-module wrote; no marker is nothing to say.
func TestDoctorNativeFailsafeIsAnError(t *testing.T) {
	dir := t.TempDir()
	run := func() []string {
		var errs []string
		checkNativeFailsafe(dir, func(_, m string) { errs = append(errs, m) })
		return errs
	}
	if errs := run(); len(errs) != 0 {
		t.Fatalf("no marker: %v", errs)
	}
	if err := os.WriteFile(filepath.Join(dir, nginxconf.FailsafeMarker), []byte("reason: no bundled module for host nginx 1.99.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	errs := run()
	if len(errs) != 1 || !strings.Contains(errs[0], "no bundled module for host nginx 1.99.0") || !strings.Contains(errs[0], "place-module.sh") {
		t.Errorf("marker: %v", errs)
	}
}
