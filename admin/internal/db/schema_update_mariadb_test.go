package db

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestMariaDB_CancelStopsTheBuildOnTheServer: a cancelled schema update is
// stopped where it runs.
//
// The driver answers a cancelled context by closing its connection, and the
// server does not look at the connection while it builds an index: the run
// said "cancelled" and the build went on to its end -- a minute on a table of
// 1.5 million rows, with the load the operator had cancelled it for.  The
// cancel now kills the statement on the server, so when the run returns there
// is no build and no index.
//
// UNMASK_TEST_MARIADB_ROWS sets the size of the table (default 300000): large
// enough that the build is still running when the cancel arrives.
func TestMariaDB_CancelStopsTheBuildOnTheServer(t *testing.T) {
	conn, err := Open(mariadbSettingsFromEnv(t))
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	// Closed by a cleanup, not a defer: the cleanup below needs it open, and
	// cleanups run after the deferred calls, last registered first.
	t.Cleanup(func() { conn.Close() })
	if err := Migrate(conn); err != nil {
		t.Fatal(err)
	}
	rows := 300000
	if v, err := strconv.Atoi(os.Getenv("UNMASK_TEST_MARIADB_ROWS")); err == nil && v > 0 {
		rows = v
	}
	const site = "cancel-test.example"
	t.Cleanup(func() {
		if _, err := conn.Exec(`DELETE FROM unmask_event WHERE site = ?`, site); err != nil {
			t.Logf("cleanup: %v", err)
		}
		// Whatever the test left of the schema, the next test gets it whole.
		if err := Migrate(conn); err != nil {
			t.Logf("cleanup: migrate: %v", err)
		}
	})
	t0 := time.Now()
	if _, err := conn.Exec(`INSERT INTO unmask_event (site, host, ip_address, user_agent, ja4, phase, payload_json, date_created)
		SELECT ?, 'h', X'0A000001', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
		       CONCAT('t13d', LPAD(seq % 977, 4, '0'), 'h2_e2e000000000_e2e000000000'),
		       ELT(1 + seq % 3, 'serve', 'load', 'bv_pow_only'),
		       CONCAT('{"bt":"x', seq, '","pad":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}'),
		       DATE_SUB(UTC_TIMESTAMP(), INTERVAL (seq % 400000) SECOND)
		  FROM seq_1_to_`+strconv.Itoa(rows), site); err != nil {
		t.Fatal(err)
	}
	t.Logf("a table of %d events in %s", rows, time.Since(t0).Round(time.Millisecond))
	for _, q := range []string{
		`DROP INDEX IF EXISTS idx_unmask_event_ja4_phase ON unmask_event`,
		`DELETE FROM schema_migrations WHERE version IN (32, 33)`,
		`DELETE FROM unmask_maint_state WHERE name IN ('schema_update', 'schema_rate')`,
	} {
		if _, err := conn.Exec(q); err != nil {
			t.Fatal(err)
		}
	}

	indexThere := func() bool {
		t.Helper()
		var n int
		if err := conn.QueryRow(`SELECT COUNT(*) FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = 'unmask_event' AND index_name = 'idx_unmask_event_ja4_phase'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	building := func() int {
		t.Helper()
		var n int
		if err := conn.QueryRow(`SELECT COUNT(*) FROM information_schema.processlist
			WHERE info LIKE 'CREATE INDEX%idx_unmask_event_ja4_phase%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		res SchemaUpdateResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := ApplySchemaUpdate(ctx, conn, SchemaUpdateOptions{Host: "test-host", By: "test", Logf: t.Logf})
		done <- outcome{res, err}
	}()
	// Cancel once the build is under way on the server.
	seen := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if building() > 0 {
			seen = true
			break
		}
	}
	if !seen {
		t.Fatal("the index build never showed on the server: the table is too small for this test, or the update did not start")
	}
	cancelled := time.Now()
	cancel()
	var out outcome
	select {
	case out = <-done:
	case <-time.After(serverStopWait + 15*time.Second):
		t.Fatal("the cancelled run did not return")
	}
	t.Logf("the run returned %s after the cancel: %v", time.Since(cancelled).Round(time.Millisecond), out.err)
	if out.err == nil || !errors.Is(out.err, context.Canceled) {
		t.Fatalf("err = %v, want the cancel", out.err)
	}
	// What the run said is true of the server: nothing is building, and
	// nothing was built.
	if n := building(); n != 0 {
		t.Errorf("%d index build(s) still running on the server after the run returned as cancelled", n)
	}
	if indexThere() {
		t.Error("the index is there after a cancelled build")
	}
	rec, ok, err := conn.LoadSchemaUpdate(context.Background())
	if err != nil || !ok || rec.State != SchemaUpdateCancelled {
		t.Errorf("record = %+v (ok=%v, err=%v), want it to read cancelled", rec, ok, err)
	}
	pending, err := PendingMigrations(conn)
	if err != nil {
		t.Fatal(err)
	}
	still := false
	for _, m := range pending {
		if m.Version == 32 {
			still = true
		}
	}
	if !still {
		t.Error("the cancelled migration is no longer pending")
	}
	// The server must stay without a build: one that went on regardless
	// would show up here a moment later.
	time.Sleep(2 * time.Second)
	if n := building(); n != 0 || indexThere() {
		t.Errorf("two seconds on: %d build(s) running, index there = %v", n, indexThere())
	}

	// Run again, to the end.
	t1 := time.Now()
	res, err := ApplySchemaUpdate(context.Background(), conn, SchemaUpdateOptions{Host: "test-host", By: "test", Logf: t.Logf})
	if err != nil {
		t.Fatalf("the run after the cancelled one: %v", err)
	}
	t.Logf("built in %s", time.Since(t1).Round(time.Millisecond))
	if len(res.Applied) != 2 || !indexThere() {
		t.Errorf("applied = %v, index there = %v; want both migrations and the index", res.Applied, indexThere())
	}
	if pending, err := PendingMigrations(conn); err != nil || len(pending) != 0 {
		t.Errorf("pending after the run = %v (err %v), want none", pending, err)
	}
}

// TestMariaDB_RunLock: on a shared MariaDB a run holds a named lock on its
// own connection.  Every node sees it, whatever the record's host id says;
// it goes when the run's connection goes -- the node died, the process was
// killed -- so a record left saying "running" does not keep the other nodes
// from running the update.
func TestMariaDB_RunLock(t *testing.T) {
	cfg := mariadbSettingsFromEnv(t)
	nodeA, err := Open(cfg)
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	t.Cleanup(func() { nodeA.Close() })
	if err := Migrate(nodeA); err != nil {
		t.Fatal(err)
	}
	nodeB, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nodeB.Close() })
	ctx := context.Background()
	now := time.Now()
	running := SchemaUpdateRecord{State: SchemaUpdateRunning, Host: "node-a", PID: 4242, By: "alice", StartedAt: now.Add(-10 * time.Minute).Unix()}

	if nodeB.SchemaUpdateAlive(ctx, running, now) {
		t.Error("no run holds the lock: a record that says running counted as going")
	}
	lock, err := nodeA.LockSchemaRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !nodeB.SchemaUpdateAlive(ctx, running, now) {
		t.Error("node A's run holds the lock: node B does not see it going")
	}
	if _, err := nodeB.LockSchemaRun(ctx); !errors.Is(err, ErrSchemaUpdateRunning) {
		t.Errorf("a second run on node B while A's holds the lock: %v, want ErrSchemaUpdateRunning", err)
	}
	lock.Release()
	if nodeB.SchemaUpdateAlive(ctx, running, now) {
		t.Error("the lock was released: still counted as going")
	}

	// A node that dies with the lock: its connection goes, and the lock with
	// it.  What the server sees of a killed process -- its connection gone --
	// is made here by killing that connection from another.
	nodeC, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nodeC.Close() })
	if _, err := nodeC.LockSchemaRun(ctx); err != nil {
		t.Fatal(err)
	}
	if !nodeB.SchemaUpdateAlive(ctx, running, now) {
		t.Error("node C holds the lock: not seen")
	}
	var holder int64
	if err := nodeB.QueryRowContext(ctx, "SELECT IS_USED_LOCK("+schemaRunLockNameSQL+")").Scan(&holder); err != nil {
		t.Fatal(err)
	}
	if _, err := nodeB.ExecContext(ctx, "KILL "+strconv.FormatInt(holder, 10)); err != nil {
		t.Fatal(err)
	}
	gone := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if !nodeB.SchemaUpdateAlive(ctx, running, now) {
			gone = true
			break
		}
	}
	if !gone {
		t.Error("the node holding the lock went away and the lock did not")
	}
	// And a lock taken and released is gone for the next run too.
	again, err := nodeB.LockSchemaRun(ctx)
	if err != nil {
		t.Fatalf("a run after the dead node's: %v", err)
	}
	again.Release()
}
