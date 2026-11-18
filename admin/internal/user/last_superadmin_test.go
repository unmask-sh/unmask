package user

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// lastSuperadminRace: two superadmins, and at the same moment one request
// that takes the first away and one that takes the second.  Whatever pair of
// changes it is -- a removal, a demotion, a suspension -- one of them has to
// be refused, and an enabled superadmin has to remain.  The guard counted
// the other superadmins and then wrote, two steps, so each request counted
// the other's account as the one that would remain and both went through:
// roughly one time in ten on SQLite, and the install had nobody left who
// could administer it.
func lastSuperadminRace(t *testing.T, d *db.DB, rounds int) {
	t.Helper()
	r := New(d)
	ctx := context.Background()
	hash, err := HashPassword("pw-long-enough-1")
	if err != nil {
		t.Fatal(err)
	}
	var existing int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_user WHERE role = ? AND disabled = 0`, RoleSuperadmin).Scan(&existing); err != nil {
		t.Fatal(err)
	}
	if existing != 0 {
		t.Skipf("the database already holds %d enabled superadmin(s): the guard would never be the last line here", existing)
	}
	type change struct {
		name string
		do   func(id int64) error
	}
	changes := []change{
		{"delete", func(id int64) error { return r.Delete(ctx, id) }},
		{"demote", func(id int64) error { return r.SetRole(ctx, id, RoleViewer) }},
		{"suspend", func(id int64) error { return r.SetDisabled(ctx, id, true) }},
	}
	tag := "race" + strconv.Itoa(os.Getpid()) + "-"
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM unmask_user WHERE username LIKE ?`, tag+"%") })
	refused := 0
	for i := 0; i < rounds; i++ {
		ca, cb := changes[i%len(changes)], changes[(i/len(changes))%len(changes)]
		a, err := r.CreateWithHash(ctx, fmt.Sprintf("%sa%d", tag, i), hash, RoleSuperadmin)
		if err != nil {
			t.Fatal(err)
		}
		b, err := r.CreateWithHash(ctx, fmt.Sprintf("%sb%d", tag, i), hash, RoleSuperadmin)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, 2)
		wg.Add(2)
		go func() { defer wg.Done(); <-start; errs[0] = ca.do(a.ID) }()
		go func() { defer wg.Done(); <-start; errs[1] = cb.do(b.ID) }()
		close(start)
		wg.Wait()
		var left int
		if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_user WHERE role = ? AND disabled = 0`, RoleSuperadmin).Scan(&left); err != nil {
			t.Fatal(err)
		}
		if left != 1 {
			t.Fatalf("round %d (%s the first, %s the second, at once): %d enabled superadmins remain, want 1 (errors: %v / %v)", i, ca.name, cb.name, left, errs[0], errs[1])
		}
		// Exactly one went through, and the other was told why.
		ok, last := 0, 0
		for _, e := range errs {
			switch {
			case e == nil:
				ok++
			case errors.Is(e, ErrLastSuperadmin):
				last++
			default:
				t.Fatalf("round %d (%s / %s): %v", i, ca.name, cb.name, e)
			}
		}
		if ok != 1 || last != 1 {
			t.Fatalf("round %d (%s / %s): %d went through and %d were refused as the last superadmin, want one of each", i, ca.name, cb.name, ok, last)
		}
		refused += last
		if _, err := d.ExecContext(ctx, `DELETE FROM unmask_user WHERE username LIKE ?`, tag+"%"); err != nil {
			t.Fatal(err)
		}
	}
	if refused != rounds {
		t.Errorf("%d of %d rounds refused a change", refused, rounds)
	}
}

func TestLastSuperadminSurvivesTwoChangesAtOnce(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "r.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	lastSuperadminRace(t, d, 180)
}

// The same on MariaDB, where the lock is on the superadmins' rows.  Runs
// under `make test-mariadb` (UNMASK_TEST_MARIADB_HOST); skips without it.
func TestMariaDB_LastSuperadminSurvivesTwoChangesAtOnce(t *testing.T) {
	host := os.Getenv("UNMASK_TEST_MARIADB_HOST")
	if host == "" {
		t.Skip("UNMASK_TEST_MARIADB_HOST not set; run `make test-mariadb` for a containerized MariaDB")
	}
	port := 3306
	if p := os.Getenv("UNMASK_TEST_MARIADB_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	envOr := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	d, err := db.Open(settings.DB{
		Driver: string(db.DriverMariaDB),
		MariaDB: settings.MariaDB{
			Host: host, Port: port,
			User:     envOr("UNMASK_TEST_MARIADB_USER", "root"),
			Password: os.Getenv("UNMASK_TEST_MARIADB_PASSWORD"),
			Database: envOr("UNMASK_TEST_MARIADB_DATABASE", "unmask_test"),
		},
	})
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	lastSuperadminRace(t, d, 90)
}

// An account and its profile are one row or none.  With an email address
// another account holds, the account was created first and the profile's
// update then failed: the account stayed, without the address, and the
// operator's second attempt was told the name was taken.
func TestCreateWithProfileIsOneRowOrNone(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "p.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	r := New(d)
	ctx := context.Background()
	const pw = "pw-long-enough-1"

	first, err := r.CreateWithProfile(ctx, "first", pw, RoleAdmin, "  ops@example.com ", true)
	if err != nil {
		t.Fatal(err)
	}
	if first.Email.String != "ops@example.com" || !first.AlertOptOut || first.Role != RoleAdmin {
		t.Errorf("first: email %q opt-out %v role %q", first.Email.String, first.AlertOptOut, first.Role)
	}
	if err := CheckPassword(first.PasswordHash, pw); err != nil {
		t.Errorf("first's stored hash does not take the password it was created with: %v", err)
	}

	// The address is taken: no account at all, and the error says which.
	if _, err := r.CreateWithProfile(ctx, "second", pw, RoleViewer, "ops@example.com", false); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("an address another account holds: err %v, want ErrEmailTaken", err)
	}
	if _, err := r.GetByUsername(ctx, "second"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the refused account exists all the same (lookup: %v)", err)
	}
	// So the same name can be tried again with another address.
	second, err := r.CreateWithProfile(ctx, "second", pw, RoleViewer, "second@example.com", false)
	if err != nil || second.Email.String != "second@example.com" || second.AlertOptOut {
		t.Fatalf("the second attempt: %+v, err %v", second, err)
	}
	// A name that is taken is still said to be the name.
	if _, err := r.CreateWithProfile(ctx, "first", pw, RoleViewer, "other@example.com", false); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("a name that is taken: err %v, want ErrUsernameTaken", err)
	}
	// No address: none stored, and any number of accounts may have none.
	for _, name := range []string{"plain1", "plain2"} {
		u, err := r.CreateWithProfile(ctx, name, pw, RoleViewer, "", false)
		if err != nil || u.Email.Valid {
			t.Errorf("%s without an address: %+v, err %v", name, u, err)
		}
	}
	var nulls int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_user WHERE email IS NULL`).Scan(&nulls); err != nil || nulls != 2 {
		t.Errorf("accounts without an address stored as NULL: %d, err %v, want 2", nulls, err)
	}
}
