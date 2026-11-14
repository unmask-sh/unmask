package nginxlog

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

// A stop while a run from the shell still holds the database's writes leaves
// the minute buckets of the hold unwritten.  They are not carried over, but
// the loss is said in the log, with how much it is (review finding S5).
func TestStopUnderAHoldSaysWhatIsNotWritten(t *testing.T) {
	d := handoverDB(t)
	r := Start("", d)
	defer r.Close()
	for i := 0; i < 5; i++ {
		r.onLine(lineWith("held.example", ""))
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(distinctSites(r)) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	var out bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prev) })
	d.HoldWrites(true)
	r.flushOnce(true)
	d.HoldWrites(false)
	log.SetOutput(prev)
	if !strings.Contains(out.String(), "still held at the stop") || !strings.Contains(out.String(), "5 request(s)") {
		t.Errorf("the stop did not say what it leaves unwritten: %q", out.String())
	}
}
