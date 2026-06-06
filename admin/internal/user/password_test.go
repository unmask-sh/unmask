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
