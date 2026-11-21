package settings

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withPresetStampFile points the preset backfill's stamp at path for the
// test and starts it from a process that has given no stamp yet.
func withPresetStampFile(t *testing.T, path string) {
	t.Helper()
	oldFile, oldKept := presetBackfillStampFile, presetBackfillKept.Load()
	t.Cleanup(func() {
		presetBackfillStampFile = oldFile
		presetBackfillKept.Store(oldKept)
	})
	presetBackfillStampFile = path
	presetBackfillKept.Store(0)
}

// unwritableStamp is a stamp file that can be neither read nor written: the
// directory it would be in is a file.  What the CI runner has -- no
// /var/lib/unmask, and no right to make one.
func unwritableStamp(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(blocker, "preset-backfill.stamp")
}

// TestPresetBackfillStampIsOnePerProcess: an install whose stamp file cannot
// be written is given one stamp for the life of the process, not the second
// of each load; a stamp config.yml carries is left alone; and where the file
// can be written, it is what a later process reads.
func TestPresetBackfillStampIsOnePerProcess(t *testing.T) {
	withPresetStampFile(t, unwritableStamp(t))

	var first, later RateLimitConfig
	rateLimitPresetBackfill(&first, 1000)
	rateLimitPresetBackfill(&later, 2000)
	if first.PresetsBackfilledAt != 1000 || later.PresetsBackfilledAt != 1000 {
		t.Errorf("two loads in one process are stamped %d and %d, want the first's (1000) for both",
			first.PresetsBackfilledAt, later.PresetsBackfilledAt)
	}

	own := RateLimitConfig{PresetsBackfilledAt: 500}
	rateLimitPresetBackfill(&own, 3000)
	if own.PresetsBackfilledAt != 500 {
		t.Errorf("a stamp config.yml carries was replaced: %d", own.PresetsBackfilledAt)
	}

	// A state directory that can be written: the file is the record.
	file := filepath.Join(t.TempDir(), "state", "preset-backfill.stamp")
	withPresetStampFile(t, file)
	var wrote, read RateLimitConfig
	rateLimitPresetBackfill(&wrote, 4000)
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("the stamp was not written: %v", err)
	}
	presetBackfillKept.Store(0) // the next process
	rateLimitPresetBackfill(&read, 5000)
	if wrote.PresetsBackfilledAt != 4000 || read.PresetsBackfilledAt != 4000 {
		t.Errorf("the written stamp: %d, and as the next process reads it: %d; want 4000 for both",
			wrote.PresetsBackfilledAt, read.PresetsBackfilledAt)
	}
}

// TestLoadTwiceASecondApartIsTheSameSettings: one config.yml loaded twice is
// the same settings, whatever the clock says in between.  The config watch
// asks exactly this of a file that was touched (SavedYAML of the settings in
// use against SavedYAML of the file re-read); where the stamp could not be
// written the two differed by rate_limit.presets_backfilled_at, a second
// apart, and a comment added to config.yml was adopted as a change.
func TestLoadTwiceASecondApartIsTheSameSettings(t *testing.T) {
	withPresetStampFile(t, unwritableStamp(t))

	path := filepath.Join(t.TempDir(), "config.yml")
	conf := "secret:\n  bv_secret: test-bv-secret\n  captcha_secret_base: test-captcha-secret\n  admin_secret: test-admin-secret\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	inUse, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if inUse.RateLimit.PresetsBackfilledAt == 0 {
		t.Fatal("the load gave no stamp: this test would compare nothing")
	}
	// Into the next second, and a comment the operator added.
	time.Sleep(time.Until(time.Unix(time.Now().Unix()+1, 0)) + 20*time.Millisecond)
	if err := os.WriteFile(path, []byte("# a note by the operator\n"+conf), 0o600); err != nil {
		t.Fatal(err)
	}
	reread, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, errA := SavedYAML(inUse)
	b, errB := SavedYAML(reread)
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	if a != b {
		t.Errorf("the same file read a second later is other settings (presets_backfilled_at %d, then %d)",
			inUse.RateLimit.PresetsBackfilledAt, reread.RateLimit.PresetsBackfilledAt)
	}
}
