package ban

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A manual ban with no action of its own is enforced with the default
// action of its source.  Changing that default in the settings did not
// rewrite the file -- only a ban added or lifted marked it -- so nginx kept
// the old action until the next one, however long (65 seconds later in the
// report, and on a quiet install for good).  The tick now notices that the
// resolver answers otherwise, and the bans page writes at once.
func TestChangedDefaultActionRewritesTheFile(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	banFile := filepath.Join(dir, "ban.list")
	mgr := New(d, banFile, time.Hour)
	var mu sync.Mutex
	manual := "captcha_only"
	mgr.SetActionResolver(func(source string) string {
		mu.Lock()
		defer mu.Unlock()
		if source == SourceManual {
			return manual
		}
		return "deny"
	})
	if err := mgr.AddManual(context.Background(), "203.0.113.40", "", "test", "admin", "", 0); err != nil {
		t.Fatal(err)
	}
	if err := mgr.flush(); err != nil {
		t.Fatal(err)
	}
	file := func() string {
		b, err := os.ReadFile(banFile)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if !strings.Contains(file(), "captcha_only") {
		t.Fatalf("the ban is not written with its default action:\n%s", file())
	}
	if mgr.actionsChangedSinceWrite() {
		t.Error("nothing changed, and the tick would write again")
	}

	mu.Lock()
	manual = "deny"
	mu.Unlock()
	if !mgr.actionsChangedSinceWrite() {
		t.Fatal("a changed default action goes unnoticed by the tick")
	}
	time.Sleep(flushDebounce) // past the debounce of the write above
	mgr.ActionsChanged()
	deadline := time.Now().Add(2 * time.Second)
	for strings.Contains(file(), "captcha_only") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := file(); strings.Contains(got, "captcha_only") || !strings.Contains(got, "deny") {
		t.Errorf("the file keeps the old action after ActionsChanged:\n%s", got)
	}
	if mgr.actionsChangedSinceWrite() {
		t.Error("the write did not record the actions it wrote")
	}
}
