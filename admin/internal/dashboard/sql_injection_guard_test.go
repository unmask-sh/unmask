package dashboard

import (
	"context"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The aggregate layer builds its SQL by hand -- that is a deliberate choice
// (CRUD goes through the ORM; the dashboard's GROUP BY / window queries do not,
// because the ORM forms are unreadable and this is a hot path).  The site and
// host filters arrive from the query string, so what keeps that safe is the
// charset guard in siteCond / hostCond / SetDisabledHosts: a value that is not
// [A-Za-z0-9._:-]+ is dropped rather than escaped.
//
// CodeQL flags all 32 of these queries (go/sql-injection) because it cannot see
// a regexp allowlist as a sanitiser.  Reading the guard and agreeing with it is
// not evidence; this drives the real functions against a real database with the
// payloads that would matter, so the claim is checked rather than asserted --
// and so that removing the guard later fails here instead of in production.
func TestFilterValuesCannotReachSQL(t *testing.T) {
	hostile := []string{
		`x' OR '1'='1`,
		`'; DROP TABLE unmask_event; --`,
		`x'--`,
		`x' UNION SELECT 1,2,3 --`,
		`x") OR 1=1 --`,
		"x'\n--",
		`x\'`,
		`x'/*`,
	}

	t.Run("the guards drop hostile values instead of quoting them", func(t *testing.T) {
		for _, v := range hostile {
			if got := siteCond(v); got != "" {
				t.Errorf("siteCond(%q) emitted %q; a value failing the charset guard must be dropped", v, got)
			}
			if got := hostCond([]string{v}); strings.Contains(got, "'"+v) {
				t.Errorf("hostCond(%q) emitted %q; the value reached the SQL", v, got)
			}
		}
	})

	t.Run("SetDisabledHosts drops them too", func(t *testing.T) {
		t.Cleanup(func() { SetDisabledHosts(nil) })
		SetDisabledHosts(hostile)
		if got := hostCond(nil); got != "" {
			t.Errorf("hostCond emitted %q from a hostile disabled-host list", got)
		}
	})

	// A legitimate value must still filter, or the guard would be "safe" by
	// doing nothing -- the failure mode a charset check invites.
	t.Run("a legitimate value still filters", func(t *testing.T) {
		if got := siteCond("shop.example.com"); !strings.Contains(got, "site = 'shop.example.com'") {
			t.Errorf("siteCond dropped a legitimate site: %q", got)
		}
		if got := hostCond([]string{"web1-jp"}); !strings.Contains(got, "'web1-jp'") {
			t.Errorf("hostCond dropped a legitimate host: %q", got)
		}
	})

	// And the whole way through: run the real queries against a real database.
	// A payload that escaped the quoting would either be a syntax error (the
	// query returns an error) or would execute -- the DROP is there so that
	// second case cannot pass quietly.
	t.Run("the real queries survive hostile filters", func(t *testing.T) {
		d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		if err := db.Migrate(d); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()

		type call struct {
			name string
			run  func(site string, hosts []string) error
		}
		calls := []call{
			{"VerdictDistribution", func(s string, h []string) error {
				_, err := VerdictDistribution(ctx, d, s, h, 24)
				return err
			}},
			{"CookieStatus", func(s string, h []string) error {
				_, err := CookieStatus(ctx, d, s, h, 24)
				return err
			}},
			{"FlagsDistribution", func(s string, h []string) error {
				_, err := FlagsDistribution(ctx, d, s, h, 24)
				return err
			}},
			{"CaptchaForceBreakdown", func(s string, h []string) error {
				_, err := CaptchaForceBreakdown(ctx, d, s, h, 24)
				return err
			}},
			{"ReloadLoops", func(s string, h []string) error {
				_, err := ReloadLoops(ctx, d, s, h, 24)
				return err
			}},
			{"HasRateLimited", func(s string, h []string) error {
				_, err := HasRateLimited(ctx, d, s, h, 24)
				return err
			}},
			{"CaptchaPassVerdictCounts", func(s string, h []string) error {
				_, err := CaptchaPassVerdictCounts(ctx, d, s, h, 24)
				return err
			}},
			{"ObserveOnlyWouldBlock", func(s string, h []string) error {
				_, err := ObserveOnlyWouldBlock(ctx, d, s, h, 24)
				return err
			}},
		}

		for _, v := range hostile {
			for _, c := range calls {
				if err := c.run(v, []string{v}); err != nil {
					t.Errorf("%s(site=%q) returned %v -- the payload reached the SQL text", c.name, v, err)
				}
			}
		}

		// The table the DROP payload names must still be there.
		var n int
		if err := d.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='unmask_event'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatal("unmask_event is gone: a DROP TABLE payload executed")
		}
	})
}
