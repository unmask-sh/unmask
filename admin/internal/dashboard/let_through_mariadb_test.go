package dashboard

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// TestMariaDB_LetThroughPage: the two queries behind BAN > Let through, on
// MariaDB.  What differs there from SQLite is what they lean on: the address
// is a VARBINARY that IN (...) has to match byte for byte, the first and last
// times are DATETIME(3) read back as text, and the event lookup names its
// index the MariaDB way.
func TestMariaDB_LetThroughPage(t *testing.T) {
	cfg := mariadbSettingsFromEnv(t)
	d, err := db.Open(cfg)
	if err != nil {
		t.Fatalf("open mariadb: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// The container's database is shared across the TestMariaDB_* suite:
	// start from none of the rows the two cases read, and leave none.
	clear := func() {
		for _, q := range []string{
			`DELETE FROM unmask_let_hourly`,
			`DELETE FROM unmask_let_ip_hourly`,
			`DELETE FROM unmask_event`,
			`DELETE FROM unmask_pass_ip_day`,
		} {
			if _, err := d.Exec(q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
	}
	clear()
	t.Cleanup(clear)
	t.Run("reasons", func(t *testing.T) { letReasonsCase(t, d) })
	t.Run("addresses", func(t *testing.T) { letAddressesCase(t, d) })
}
