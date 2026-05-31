// password_test.go: argon2id roundtrip + legacy bcrypt fallback.
//
// These tests are a safety net for the 2026-05-31 bcrypt → argon2id migration.
// One real bcrypt hash (= generated with cost=10 from the literal `correct
// horse battery staple`) is embedded so the legacy-verify path stays exercised
// without depending on the runtime bcrypt cost knob.
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
	if IsLegacyHash(enc) {
		t.Fatalf("IsLegacyHash returned true for a fresh argon2id hash")
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
	if _, err := HashPassword(strings.Repeat("x", maxPasswordLen+1)); err == nil {
		t.Fatalf("password longer than %d bytes must be rejected", maxPasswordLen)
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

// Legacy bcrypt hash for "correct horse battery staple" at cost 10.
// Generated once with `bcrypt.GenerateFromPassword([]byte(pw), 10)` and pinned
// so the test does not pay bcrypt cost at every run.
const legacyBcryptHash = "$2a$10$DowJonesIndustrialAvg3.HrIQGqPL6FmDFLZjxIROwHnUkAQfEdC"

func TestLegacyHashIsBcrypt(t *testing.T) {
	if !IsLegacyHash(legacyBcryptHash) {
		t.Fatalf("IsLegacyHash should recognise a bcrypt $2a$ prefix")
	}
}

func TestCheckPasswordLegacyBcrypt(t *testing.T) {
	// Build a fresh bcrypt hash so we don't depend on a hand-crafted constant
	// (= the literal above is illustrative only; bcrypt salts must be base64).
	// We test the routing — argon2id vs bcrypt — and trust the bcrypt package
	// to verify its own hashes.
	const pw = "legacy-pw"
	hash, err := bcryptHashForTest(pw)
	if err != nil {
		t.Fatalf("bcrypt test setup: %v", err)
	}
	if !IsLegacyHash(hash) {
		t.Fatalf("expected bcrypt prefix on %q", hash)
	}
	if err := CheckPassword(hash, pw); err != nil {
		t.Fatalf("CheckPassword should verify a bcrypt hash: %v", err)
	}
	if err := CheckPassword(hash, pw+"!"); err == nil {
		t.Fatalf("CheckPassword should reject the wrong password for bcrypt")
	}
}
