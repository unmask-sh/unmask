package advisor

import (
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// A content block's index sizes the slice the message is built in, and the
// index is the provider's number.  One event naming block two billion had
// the daemon allocate tens of gigabytes; the stream is refused instead.
func TestStreamRefusesABlockIndexPastTheBound(t *testing.T) {
	var m streamedMessage
	if _, err := m.apply([]byte(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)); err != nil {
		t.Fatalf("an ordinary first block: %v", err)
	}
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	_, err := m.apply([]byte(`{"type":"content_block_start","index":2000000000,"content_block":{"type":"text","text":""}}`))
	runtime.ReadMemStats(&m1)
	if err == nil || !strings.Contains(err.Error(), "block 2000000000") {
		t.Fatalf("block 2000000000 was not refused: %v", err)
	}
	if mib := (m1.TotalAlloc - m0.TotalAlloc) >> 20; mib > 1 {
		t.Errorf("refusing it allocated %d MiB", mib)
	}
	if len(m.blocks) != 1 {
		t.Errorf("the message holds %d blocks after the refusal, want the 1 it had", len(m.blocks))
	}

	// The last index inside the bound is a block like any other.
	var ok streamedMessage
	for i := 0; i < maxStreamBlocks; i++ {
		ev := `{"type":"content_block_start","index":` + strconv.Itoa(i) + `,"content_block":{"type":"text","text":""}}`
		if _, err := ok.apply([]byte(ev)); err != nil {
			t.Fatalf("block %d of %d: %v", i, maxStreamBlocks, err)
		}
	}
	if _, err := ok.apply([]byte(`{"type":"content_block_start","index":` + strconv.Itoa(maxStreamBlocks) + `,"content_block":{"type":"text","text":""}}`)); err == nil {
		t.Errorf("block %d, one past the bound, was accepted", maxStreamBlocks)
	}
}
