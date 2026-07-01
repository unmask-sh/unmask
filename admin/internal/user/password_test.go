// password_test.go: argon2id hash roundtrip.
package user

import (
	"strings"
	"testing"
)

func TestHashPasswordRoundtrip(t *testing.T) {
	const pw = "correct horse battery staple"
	enc, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(enc, "$argon2id$") {
		t.Fatalf("expected argon2id PHC string, got %q", enc)
	}
	if err := CheckPassword(enc, pw); err != nil {
		t.Fatalf("CheckPassword: %v", err)
	}
	if err := CheckPassword(enc, pw+"x"); err == nil {
		t.Fatalf("CheckPassword should reject the wrong password")
	}
}

func TestHashPasswordRejectsEmpty(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("empty password must be rejected")
	}
}

func TestHashPasswordRejectsTooLong(t *testing.T) {
	if _, err := HashPassword(strings.Repeat("x", MaxPasswordLen+1)); err == nil {
		t.Fatalf("password longer than %d bytes must be rejected", MaxPasswordLen)
	}
}

func TestHashPasswordReturnsDistinctSalts(t *testing.T) {
	const pw = "the-same-password"
	a, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword#1: %v", err)
	}
	b, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword#2: %v", err)
	}
	if a == b {
		t.Fatalf("two HashPassword calls returned the same hash (= salt not randomised)")
	}
}

func TestNeedsRehash(t *testing.T) {
	// A hash freshly produced with the current defaults must not need rehashing.
	cur, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if NeedsRehash(cur) {
		t.Error("current-parameter hash should not need rehash")
	}
	// A hash carrying weaker cost parameters (here: half the memory) must be
	// flagged so a successful login can transparently upgrade it (AUTH-6).
	weak := "$argon2id$v=19$m=32768,t=2,p=1$YWJjZGVmZ2hpamts$aGFzaGhhc2hoYXNo"
	if !NeedsRehash(weak) {
		t.Error("weaker-parameter hash should need rehash")
	}
	// Unparseable / legacy formats are upgraded on next login.
	for _, bad := range []string{"", "not-a-hash", "$2y$10$abcdef", "$argon2id$v=19$broken"} {
		if !NeedsRehash(bad) {
			t.Errorf("malformed hash %q should need rehash", bad)
		}
	}
}
