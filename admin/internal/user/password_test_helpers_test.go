// password_test_helpers_test.go: bcrypt helper isolated from production code
// so that production callers cannot accidentally use it.
package user

import "golang.org/x/crypto/bcrypt"

// bcryptHashForTest: minimum-cost bcrypt hash for the legacy-verify path.
// cost=4 (the lowest the bcrypt package accepts) keeps test runtime negligible.
func bcryptHashForTest(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
