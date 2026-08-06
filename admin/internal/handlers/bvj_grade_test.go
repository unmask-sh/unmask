package handlers

import "testing"

// A lineage has to be able to say what its solve actually proved.
//
// Every path signed "captcha" into the credential, including the transparent
// proof-of-work -- so a policy of "a CAPTCHA or nothing for this UA" had
// nothing to read, and the only way to enforce one would have been to
// re-challenge every holder.  Nothing consumes the field yet; stamping it
// truthfully is what makes that policy possible later.
func TestStrongerGrade(t *testing.T) {
	cases := []struct{ prior, now, want string }{
		// A CAPTCHA holder re-solving the transparent challenge on a new
		// transport (h2 -> h3 changes the fingerprint) must not be demoted to
		// pow: it has already proven the harder thing.
		{"captcha", "pow", "captcha"},
		// ...and the reverse is an upgrade: the client just proved more.
		{"pow", "captcha", "captcha"},
		{"pow", "pow", "pow"},
		{"captcha", "captcha", "captcha"},
		// An older credential predating the stamp carries no grade; the
		// current solve decides rather than inventing one.
		{"", "pow", "pow"},
		// Nothing known either way -- writeBVJ's own default applies.
		{"", "", ""},
	}
	for _, c := range cases {
		if got := strongerGrade(c.prior, c.now); got != c.want {
			t.Errorf("strongerGrade(%q, %q) = %q, want %q", c.prior, c.now, got, c.want)
		}
	}
}
