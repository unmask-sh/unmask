package browsermajors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func resetHub(t *testing.T) {
	t.Helper()
	settings.SetHubBrowserBaselines(settings.HubBrowserBaselinesData{})
	t.Cleanup(func() { settings.SetHubBrowserBaselines(settings.HubBrowserBaselinesData{}) })
}

const goodDoc = `{"schemaVersion":1,"generatedAt":"2026-07-21T00:00:00Z",
"chrome":{"major":151,"version":"151.0.1.1"},
"firefox":{"major":153,"version":"153.0","esrMajors":[140,153]}}`

func TestPullOnceAppliesAndPersists(t *testing.T) {
	resetHub(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(goodDoc))
	}))
	defer srv.Close()

	dir := t.TempDir()
	s := NewSync()
	s.HubURL = srv.URL
	s.StatePath = filepath.Join(dir, "state.json")
	if err := s.PullOnce(context.Background()); err != nil {
		t.Fatalf("pull: %v", err)
	}
	hub, ok := settings.HubBrowserBaselines()
	if !ok || hub.Chrome != 151 || hub.Firefox != 153 || !reflect.DeepEqual(hub.FirefoxESR, []int{140, 153}) {
		t.Fatalf("hub baselines not applied: %+v ok=%v", hub, ok)
	}
	if s.LastSyncedAt().IsZero() || s.LastError() != "" {
		t.Errorf("sync state not recorded: at=%v err=%q", s.LastSyncedAt(), s.LastError())
	}
	if _, err := os.Stat(s.StatePath); err != nil {
		t.Errorf("state not persisted: %v", err)
	}

	// The resolve chain now rides the hub values (no operator override).
	var g settings.GlobalConfig
	if got := g.CurrentChromeMajorResolved(); got != 151 {
		t.Errorf("chrome resolved = %d, want 151 (hub above built-in)", got)
	}
	if got := g.CurrentFirefoxMajorResolved(); got != 153 {
		t.Errorf("firefox resolved = %d, want 153", got)
	}
	esr := g.FirefoxESRMajors()
	want := map[int]bool{settings.DefaultFirefoxESRMajor: true, 153: true}
	if len(esr) != len(want) {
		t.Errorf("esr union = %v, want built-in + hub extras", esr)
	}
	for _, m := range esr {
		if !want[m] {
			t.Errorf("unexpected esr major %d in %v", m, esr)
		}
	}
	// An operator-set value still wins over the hub.
	g.CurrentChromeMajor = 149
	if got := g.CurrentChromeMajorResolved(); got != 149 {
		t.Errorf("manual override must win over hub, got %d", got)
	}
}

// A hub value BELOW the built-in must not lower the effective baseline (a
// stale hub / rollback can only ever be ignored).
func TestHubBelowBuiltinIsIgnored(t *testing.T) {
	resetHub(t)
	Apply(Doc{SchemaVersion: 1,
		Chrome:  Family{Major: settings.DefaultCurrentChromeMajor - 5},
		Firefox: Family{Major: settings.DefaultCurrentFirefoxMajor - 5, ESRMajors: []int{140}},
	}, time.Now())
	var g settings.GlobalConfig
	if got := g.CurrentChromeMajorResolved(); got != settings.DefaultCurrentChromeMajor {
		t.Errorf("chrome resolved = %d, want built-in %d", got, settings.DefaultCurrentChromeMajor)
	}
	if got := g.FirefoxBaselineSource(); got != settings.BaselineSourceBuiltin {
		t.Errorf("source = %q, want builtin when hub is older", got)
	}
}

func TestValidateRejectsBrokenDocs(t *testing.T) {
	cases := []struct {
		name string
		doc  Doc
	}{
		{"wrong schema", Doc{SchemaVersion: 2, Chrome: Family{Major: 150}}},
		{"empty", Doc{SchemaVersion: 1}},
		{"chrome absurd", Doc{SchemaVersion: 1, Chrome: Family{Major: settings.DefaultCurrentChromeMajor + maxAdvance + 1}}},
		{"esr absurd", Doc{SchemaVersion: 1, Firefox: Family{Major: 153, ESRMajors: []int{99999}}}},
	}
	for _, c := range cases {
		if err := Validate(c.doc); err == nil {
			t.Errorf("%s: want error, got nil", c.name)
		}
	}
}

func TestLoadStateAbsentIsNoop(t *testing.T) {
	resetHub(t)
	if err := LoadState(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatalf("absent state must be a silent no-op, got %v", err)
	}
	if _, ok := settings.HubBrowserBaselines(); ok {
		t.Error("absent state must not publish baselines")
	}
}

func TestLoadStateAppliesPersistedDoc(t *testing.T) {
	resetHub(t)
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(goodDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LoadState(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	hub, ok := settings.HubBrowserBaselines()
	if !ok || hub.Chrome != 151 {
		t.Fatalf("persisted doc not applied: %+v ok=%v", hub, ok)
	}
}

func TestPullOnceRejectsGarbage(t *testing.T) {
	resetHub(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"schemaVersion":1,"chrome":{"major":99999}}`))
	}))
	defer srv.Close()
	s := NewSync()
	s.HubURL = srv.URL
	s.StatePath = filepath.Join(t.TempDir(), "state.json")
	if err := s.PullOnce(context.Background()); err == nil {
		t.Fatal("absurd doc must fail the pull")
	}
	if _, ok := settings.HubBrowserBaselines(); ok {
		t.Error("rejected doc must not publish baselines")
	}
	if s.LastError() == "" {
		t.Error("pull error must be observable for the UI")
	}
}
