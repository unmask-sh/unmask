package events

import (
	"context"
	"errors"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// A daemon that runs without its database (the start could not open it)
// goes on serving the challenge page, whose beacon is written through
// Insert: the event goes unrecorded with db.ErrNoDatabase, as InsertAsync
// lets it go, where the nil handle used to be dereferenced on every beacon.
// The hook is not told of an event nothing will hold.
func TestInsertWithoutDatabase(t *testing.T) {
	seen := 0
	OnInsert = func(*Event) { seen++ }
	t.Cleanup(func() { OnInsert = nil })

	e := &Event{IPPacked: PackIP("192.0.2.1"), Phase: "load"}
	if err := Insert(context.Background(), nil, e); !errors.Is(err, db.ErrNoDatabase) {
		t.Fatalf("Insert on no database = %v, want db.ErrNoDatabase", err)
	}
	InsertAsync(nil, e) // returns at once; nothing to wait for
	if seen != 0 {
		t.Errorf("the hook saw %d event(s) of a daemon with no database", seen)
	}
}
