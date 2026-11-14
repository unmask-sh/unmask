package spill

import (
	"os"
	"path/filepath"
	"testing"
)

type row struct {
	Name string
	N    int
	B    []byte
}

func TestSaveTakeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := []row{{"a", 1, []byte{0, 1, 255}}, {"b", 2, nil}}
	if err := Save(dir, "held-x.json", in); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "held-x.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	var out []row
	found, err := Take(dir, "held-x.json", &out)
	if err != nil || !found {
		t.Fatalf("Take: found=%v err=%v", found, err)
	}
	if len(out) != 2 || out[0].Name != "a" || string(out[0].B) != string([]byte{0, 1, 255}) || out[1].N != 2 {
		t.Errorf("round trip: %+v", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "held-x.json")); !os.IsNotExist(err) {
		t.Errorf("Take left the file behind")
	}
	// Nothing left to take.
	found, err = Take(dir, "held-x.json", &out)
	if found || err != nil {
		t.Errorf("second Take: found=%v err=%v", found, err)
	}
	// No temporary files left over.
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Errorf("left in the directory: %v", ents)
	}
}

func TestTakeSetsAsideWhatDoesNotDecode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "held-y.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out []row
	found, err := Take(dir, "held-y.json", &out)
	if !found || err == nil {
		t.Fatalf("an unreadable file: found=%v err=%v", found, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "held-y.json.unreadable")); err != nil {
		t.Errorf("not kept aside: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "held-y.json")); !os.IsNotExist(err) {
		t.Errorf("still in the next start's way")
	}
}

func TestNoDirectory(t *testing.T) {
	if err := Save("", "x.json", 1); err == nil {
		t.Errorf("Save with no directory succeeded")
	}
	var v int
	if found, err := Take("", "x.json", &v); found || err != nil {
		t.Errorf("Take with no directory: found=%v err=%v", found, err)
	}
}
