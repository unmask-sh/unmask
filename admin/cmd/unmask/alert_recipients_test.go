package main

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/user"
)

// An alert raised while the daemon has no database (the fail-safe watch runs
// without one) asks for the accounts' addresses in the mail's own goroutine:
// with no repository there are none, where the nil one used to be
// dereferenced and the process ended.
func TestAlertRecipientsWithoutDatabase(t *testing.T) {
	if got := alertRecipients(nil)(); got != nil {
		t.Errorf("recipients with no database: %v, want none", got)
	}
	var repo *user.Repository
	if got := alertRecipients(repo)(); got != nil {
		t.Errorf("recipients with a nil repository: %v, want none", got)
	}
}
