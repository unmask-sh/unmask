package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The admin-host allowlist widget shows an exact/contains/regex mode toggle,
// like every other rule list.  Until hostMatchesPattern existed the toggle was
// inert: the matcher did plain string equality, so only a literal hostname
// matched and "exact:"/"contains:" markers were compared including the prefix
// (which also self-locked the operator out on save).  This pins all three
// modes -- and the one rule unique to an allow list: its regex is anchored.
func TestHostAllowedHonorsPatternModes(t *testing.T) {
	cases := []struct {
		name  string
		entry string
		host  string
		want  bool
	}{
		{"plain literal still matches", "tool1-jp", "tool1-jp", true},
		{"plain literal is case-insensitive", "Tool1-JP", "tool1-jp", true},
		{"exact marker matches its value", "exact:tool1-jp", "tool1-jp", true},
		{"exact marker does not substring-match", "exact:tool1", "tool1-jp", false},
		// A legacy "contains:" entry (the mode is no longer offered in the UI)
		// is read as exact, not substring: a substring allowlist would admit
		// uic.jp.attacker.com, so it fails closed.
		{"legacy contains is read as exact", "contains:tool1", "tool1-jp", false},
		{"legacy contains matches only the whole value", "contains:tool1-jp", "tool1-jp", true},
		// Subdomain: the apex host and any child, end-anchored so a suffix
		// cannot be smuggled in.
		{"subdomain matches the apex", "subdomain:example.com", "example.com", true},
		{"subdomain matches a child", "subdomain:example.com", "admin.example.com", true},
		{"subdomain matches a deep child", "subdomain:example.com", "a.b.example.com", true},
		{"subdomain is case-insensitive", "subdomain:Example.COM", "admin.example.com", true},
		{"subdomain does NOT match an appended domain", "subdomain:example.com", "example.com.attacker.com", false},
		{"subdomain does NOT match a lookalike apex", "subdomain:example.com", "notexample.com", false},
		{"regex matches the fleet", `tool\d+-[a-z]+`, "tool1-jp", true},
		{"regex matches another fleet node", `tool\d+-[a-z]+`, "tool2-us", true},
		// The security property: an allow-list regex is anchored, so it cannot
		// be smuggled past by appending an attacker-controlled suffix.
		{"regex does NOT match an appended domain", `tool\d+-[a-z]+`, "tool1-jp.attacker.com", false},
		{"regex does NOT match a prepended label", `tool\d+-[a-z]+`, "x.tool1-jp", false},
		// A pattern that cannot compile matches nothing (fail closed).
		{"uncompilable regex matches nothing", `tool(`, "tool1-jp", false},
	}
	for _, c := range cases {
		if got := hostAllowed(c.host, []string{c.entry}); got != c.want {
			t.Errorf("%s: hostAllowed(%q, [%q]) = %v, want %v", c.name, c.host, c.entry, got, c.want)
		}
	}
	// Empty list is still "allow all".
	if !hostAllowed("anything", nil) {
		t.Error("an empty allowlist must allow all (no lockout on first install)")
	}
}

// The save path is where the field lost data: a regex value (backslashes) was
// silently dropped, the list saved empty, and a green "saved" banner claimed
// success while the gate fell open.  This drives the real handler function.
func TestApplyNetworkFormAdminHosts(t *testing.T) {
	save := func(val string) (stored []string, err error) {
		f := url.Values{}
		f.Set("admin_allowed_hosts", val)
		f.Set("admin_allowed_hosts_enabled", "1")
		r := httptest.NewRequest("POST", "/x", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if e := r.ParseForm(); e != nil {
			t.Fatal(e)
		}
		n := &settings.Nginx{}
		err = applyNetworkForm(n, r, i18n.LangEN, "127.0.0.1", "tool1-jp")
		return n.AdminAllowedHosts, err
	}

	t.Run("a regex value is stored, not dropped", func(t *testing.T) {
		stored, err := save(`tool\d+-[a-z]+`)
		if err != nil {
			t.Fatalf("a valid regex covering the operator's host was rejected: %v", err)
		}
		if len(stored) != 1 || stored[0] != `tool\d+-[a-z]+` {
			t.Fatalf("regex not stored verbatim: %#v", stored)
		}
	})

	t.Run("exact: marker no longer self-locks", func(t *testing.T) {
		stored, err := save("exact:tool1-jp")
		if err != nil {
			t.Fatalf("exact:tool1-jp from host tool1-jp must not lock out: %v", err)
		}
		if len(stored) != 1 {
			t.Fatalf("exact entry not stored: %#v", stored)
		}
	})

	t.Run("a lockout is still refused (not silently emptied)", func(t *testing.T) {
		stored, err := save("exact:other.example.com")
		if err == nil {
			t.Fatal("a list excluding the operator's host must be rejected")
		}
		if stored != nil {
			t.Fatalf("a rejected save must not mutate the list: %#v", stored)
		}
	})

	t.Run("a broken regex is named, not vanished", func(t *testing.T) {
		_, err := save(`tool(`)
		if err == nil {
			t.Fatal("an uncompilable regex must be rejected with an error")
		}
		if !strings.Contains(err.Error(), "tool(") {
			t.Errorf("the error should name the offending value, got: %v", err)
		}
		// The message has two %s (the value, and the exact: suggestion echoing
		// it); both must be filled -- a MISSING marker reached the UI once.
		if strings.Contains(err.Error(), "MISSING") || strings.Contains(err.Error(), "%!") {
			t.Errorf("the error message has an unfilled format verb: %v", err)
		}
	})
}
