package main

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// doctor's write-ahead log check: a small log is fine, a large one is the
// sign that checkpoints are not completing, said with the file and its size
// and what a stop and the next start will do about it.
func TestWALSizeVerdict(t *testing.T) {
	if warn, msg := walSizeVerdict("/var/lib/unmask/unmask.sqlite-wal", 0); warn || !strings.Contains(msg, "none") {
		t.Errorf("no log: warn=%v msg=%q", warn, msg)
	}
	if warn, msg := walSizeVerdict("/var/lib/unmask/unmask.sqlite-wal", 12<<20); warn || !strings.Contains(msg, "12.0 MB") {
		t.Errorf("a small log: warn=%v msg=%q", warn, msg)
	}
	warn, msg := walSizeVerdict("/var/lib/unmask/unmask.sqlite-wal", db.WALLargeBytes)
	if !warn || !strings.Contains(msg, "unmask.sqlite-wal") || !strings.Contains(msg, "256.0 MB") || !strings.Contains(msg, "replays") {
		t.Errorf("a large log must WARN with the file, the size and the consequence, got warn=%v msg=%q", warn, msg)
	}

	// On a live database the check reads the file next to it.
	d := retentionTestDB(t)
	var oks, warns []string
	checkWALSize(d, func(_, m string) { oks = append(oks, m) }, func(_, m string) { warns = append(warns, m) })
	if len(warns) != 0 || len(oks) != 1 {
		t.Errorf("a fresh database: oks=%v warns=%v", oks, warns)
	}
}
