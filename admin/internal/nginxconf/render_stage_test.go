package nginxconf

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A render whose template fails part of the way through replaces none of the
// files: every file is rendered before any is moved into place, so nginx is
// never left an http.inc of one render beside a server.inc of the one before.
// The rendered copies are cleaned up, and the same render, once the template
// works, goes through.
func TestRenderReplacesNoFileWhenATemplateFails(t *testing.T) {
	dir := t.TempDir()
	var s settings.Settings
	s.Nginx.OutputDir = dir
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("first render: %v", err)
	}
	names := []string{"http.inc", "server.inc", "protect.inc", "forward-auth-lbtrust.conf", "upstream.conf"}
	before := map[string][]byte{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("after the first render: %v", err)
		}
		before[n] = b
	}

	// A change that moves http.inc, rendered while a later template fails.
	s.Challenge.Default.PowDifficulty = settings.PowDifficultyDefault + 2
	works := execTemplate
	t.Cleanup(func() { execTemplate = works })
	execTemplate = func(tm *template.Template, w io.Writer, data any) error {
		if tm.Name() == "protect.inc" {
			return errors.New("a template that fails")
		}
		return works(tm, w, data)
	}
	if err := Render(s, dir, "test"); err == nil {
		t.Fatal("the render reported no error with a template that failed")
	}
	for _, n := range names {
		if b, _ := os.ReadFile(filepath.Join(dir, n)); !bytes.Equal(b, before[n]) {
			t.Errorf("%s was replaced by a render that failed", n)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp-*")); len(left) != 0 {
		t.Errorf("the failed render left its copies behind: %v", left)
	}

	execTemplate = works
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("the render once the template works: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "http.inc")); bytes.Equal(b, before["http.inc"]) {
		t.Error("http.inc is still the first render's after a render that went through")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp-*")); len(left) != 0 {
		t.Errorf("a render that went through left copies behind: %v", left)
	}
}
