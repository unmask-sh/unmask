package db

import (
	"os"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// SQLite's cache_size and mmap_size are PER CONNECTION while the pool opens up
// to sqliteMaxOpen() of them, so the sizing has to be expressed as a
// pool-wide budget.  These tests pin the budget arithmetic -- the property that
// matters is "total stays bounded on a small box", which is what makes unmask
// usable on a 1GB VPS (measured: the previous flat 128MB cache + 256MB mmap
// peaked at 3.7GB RSS under 8 concurrent dashboard-shaped queries).
func TestSQLitePerConnBudget(t *testing.T) {
	const mb = 1 << 20
	for _, c := range []struct {
		name       string
		overrideMB int
		wantTotal  int64 // expected total across the pool, in MB (0 = derived)
	}{
		{"explicit override pins the total", 64, 64},
		{"override below the pool size still leaves 1MB/conn", 1, int64(sqliteMaxOpen())},
	} {
		t.Run(c.name, func(t *testing.T) {
			per := sqlitePerConnBytes(c.overrideMB)
			conns := int64(sqliteMaxOpen())
			total := per * conns
			// The split truncates, so the pool total lands at or just under the
			// budget -- never above it, which is the property that matters.
			want := c.wantTotal * mb
			if total > want || total < want-conns {
				t.Errorf("total = %d bytes (%d conns), want <= %d and within %d of it", total, conns, want, conns)
			}
		})
	}

	// Automatic mode: whatever this machine reports, the TOTAL must land inside
	// the floor/ceiling band -- never the multi-GB aggregate the flat constants
	// produced, and never so small that caching is pointless.
	t.Run("automatic total stays within the budget band", func(t *testing.T) {
		per := sqlitePerConnBytes(0)
		total := per * int64(sqliteMaxOpen())
		if total > sqliteBudgetCeil {
			t.Errorf("total %dMB exceeds the ceiling %dMB", total/mb, int64(sqliteBudgetCeil)/mb)
		}
		// The floor is a total, but the 1MB/conn minimum can push slightly above
		// it on a tiny box; both are far below the ceiling, so just assert the
		// pool gets a usable amount.
		if per < 1*mb {
			t.Errorf("per-conn %d bytes is below the 1MB minimum", per)
		}
	})
}

// The DSN must carry the derived sizes, not the old flat constants: a
// regression here silently restores the per-connection multiplication.
func TestSQLiteDSNUsesDerivedSizes(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(settings.DB{
		Driver:     "sqlite",
		SQLitePath: dir + "/unmask.sqlite",
		// Pin the total so the assertion is independent of the test machine.
		// The pin only applies under the custom profile -- that is the contract.
		PerfProfile:   settings.PerfProfileCustom,
		SQLiteCacheMB: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	// 64MB budget split across the CPU-sized pool.  cache_size is expressed in
	// KiB (so it truncates to a KiB boundary) while mmap_size is bytes.
	perConn := int64(64<<20) / int64(sqliteMaxOpenFor(settings.DB{PerfProfile: settings.PerfProfileCustom, SQLiteCacheMB: 64}))
	wantPerConnKiB := int(perConn / 1024)
	var cacheKiB int
	if err := d.QueryRow("PRAGMA cache_size").Scan(&cacheKiB); err != nil {
		t.Fatal(err)
	}
	// Negative = KiB of cache; SQLite reports back what we set.
	if cacheKiB != -wantPerConnKiB {
		t.Errorf("cache_size = %d, want -%d (64MB across the pool)", cacheKiB, wantPerConnKiB)
	}
	var mmap int64
	if err := d.QueryRow("PRAGMA mmap_size").Scan(&mmap); err != nil {
		t.Fatal(err)
	}
	if mmap != perConn {
		t.Errorf("mmap_size = %d, want %d (bytes, not KiB-rounded)", mmap, perConn)
	}
}

// The profiles must order as conservative < standard < generous, and a pinned
// custom budget must win over all of them.  They are a RESOURCE dial: this
// pins the ordering, not any absolute number (which is host-derived).
func TestPerfProfilesOrdering(t *testing.T) {
	per := func(profile string) int64 {
		return sqlitePerConnBytesFor(settings.DB{PerfProfile: profile})
	}
	cons, std, gen := per(settings.PerfProfileConservative), per(settings.PerfProfileStandard), per(settings.PerfProfileGenerous)
	if !(cons <= std && std <= gen) {
		t.Errorf("profiles out of order: conservative=%d standard=%d generous=%d", cons, std, gen)
	}
	// An empty profile must behave exactly like standard (upgrade safety: every
	// existing config has no perf_profile key).
	if per("") != std {
		t.Errorf("empty profile = %d, want standard %d", per(""), std)
	}
	// Custom with an absurd value is capped rather than trusted blindly.
	huge := sqlitePerConnBytesFor(settings.DB{PerfProfile: settings.PerfProfileCustom, SQLiteCacheMB: 1 << 20})
	if huge*int64(sqliteMaxOpenFor(settings.DB{PerfProfile: settings.PerfProfileCustom, SQLiteCacheMB: 1 << 20})) > sqliteBudgetCustomCeil {
		t.Errorf("custom budget %d exceeds the custom ceiling", huge)
	}
}

// A custom pool size overrides the CPU derivation, but stays bounded.
func TestCustomPoolSize(t *testing.T) {
	got := sqliteMaxOpenFor(settings.DB{PerfProfile: settings.PerfProfileCustom, MaxConns: 3})
	if got != 3 {
		t.Errorf("custom MaxConns=3 -> %d, want 3", got)
	}
	if got := sqliteMaxOpenFor(settings.DB{PerfProfile: settings.PerfProfileCustom, MaxConns: 9999}); got != sqliteMaxConnsCustomCeil {
		t.Errorf("absurd MaxConns -> %d, want the ceiling %d", got, sqliteMaxConnsCustomCeil)
	}
	// Without the custom profile the override is ignored (CPU-derived).
	if got := sqliteMaxOpenFor(settings.DB{MaxConns: 3}); got != sqliteMaxOpen() {
		t.Errorf("MaxConns outside custom profile leaked: %d", got)
	}
}

// memLimitBytes must not mistake cgroup v1's "unlimited" sentinel for a real
// limit: that value is astronomically large and would hand the pool the
// ceiling budget on a box that may be tiny.
func TestMemLimitSanity(t *testing.T) {
	v := memLimitBytes()
	if v < 0 {
		t.Fatalf("negative limit %d", v)
	}
	if v > 0 && v < 16<<20 {
		t.Errorf("implausibly small limit %d bytes", v)
	}
	// 1<<52 is the sentinel guard in memLimitBytes; anything at or above it
	// means the guard let a fake "unlimited" through.
	if v >= 1<<52 {
		t.Errorf("limit %d looks like a cgroup 'unlimited' sentinel", v)
	}
}

// The old flat pragmas must not come back: assert on the shipped source so a
// future edit that reinstates them fails here with the reason attached.
func TestNoFlatPragmaConstants(t *testing.T) {
	src := readSource(t, "db.go")
	for _, gone := range []string{"cache_size(-131072)", "mmap_size(268435456)"} {
		if strings.Contains(src, gone) {
			t.Errorf("db.go still hardcodes %q -- it is per connection and multiplies by the pool size", gone)
		}
	}
}

// readSource returns a file from this package's directory.
func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
