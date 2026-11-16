package handlers

import (
	"context"
	"testing"
)

// TestTailPollMovesPastRowsItsFilterSkips: a poll whose filter matches
// nothing still moves the live tail's anchor to the table's last row, so the
// next poll reads only what arrived after it.  The anchor used to move only
// with a row returned: a quiet site picked on a busy install left it where
// the page opened, and every poll read every row written since.  A poll cut
// short by the row limit goes on from its last row.
func TestTailPollMovesPastRowsItsFilterSkips(t *testing.T) {
	h := installedHandler(t)
	ctx := context.Background()
	insert := func(site string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, user_agent, phase, payload_json) VALUES (?, 'h', x'cb007101', 'UA', 'serve', '{}')`, site); err != nil {
				t.Fatal(err)
			}
		}
	}

	insert("busy.example", 5)
	rows, next, err := tailPoll(ctx, h.DB, 0, "quiet.example", "", nil)
	if err != nil || len(rows) != 0 || next != 5 {
		t.Fatalf("nothing matched in ids 1-5: %d rows, next anchor %d, err %v; want 0 rows and 5", len(rows), next, err)
	}

	insert("quiet.example", 3)
	rows, next, err = tailPoll(ctx, h.DB, next, "quiet.example", "", nil)
	if err != nil || len(rows) != 3 || rows[0].ID != 6 || next != 8 {
		t.Fatalf("three matches in ids 6-8: %d rows, next anchor %d, err %v", len(rows), next, err)
	}

	rows, next, err = tailPoll(ctx, h.DB, next, "quiet.example", "", nil)
	if err != nil || len(rows) != 0 || next != 8 {
		t.Fatalf("nothing new: %d rows, next anchor %d, err %v; want 0 rows and 8", len(rows), next, err)
	}

	insert("quiet.example", tailPollRows+20)
	rows, next, err = tailPoll(ctx, h.DB, next, "quiet.example", "", nil)
	if err != nil || len(rows) != tailPollRows || next != rows[len(rows)-1].ID {
		t.Fatalf("a poll cut at the limit: %d rows, next anchor %d, err %v", len(rows), next, err)
	}
	rows, next, err = tailPoll(ctx, h.DB, next, "quiet.example", "", nil)
	if err != nil || len(rows) != 20 || next != 8+tailPollRows+20 {
		t.Fatalf("the rest after the limit: %d rows, next anchor %d, err %v", len(rows), next, err)
	}
}
