package user

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every argon2id run holds 64 MiB, and the login lockout counts a failure only
// after its run: a burst of parallel login POSTs from one address used to have
// the daemon hold the burst's size times 64 MiB at once.  The runs share
// hashSlots now.  This stands in for the key derivation and watches how many
// callers are inside it at the same time.
func TestPasswordHashingRunsAreBounded(t *testing.T) {
	orig := argon2Key
	t.Cleanup(func() { argon2Key = orig })
	var inFlight, peak atomic.Int32
	argon2Key = func(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		// Long enough for the callers behind to pile up on the slots.
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		return make([]byte, keyLen)
	}
	// A parseable stored hash; the stub's key never matches it, and the
	// mismatch is not what is under test.
	hash := "$argon2id$v=19$m=65536,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	const workers = 24
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// All three entry points draw on the same slots.
			var err error
			switch i % 3 {
			case 0:
				err = CheckPassword(hash, "pw")
			case 1:
				err = DummyCheckPassword("pw")
			default:
				_, err = HashPassword("pw")
			}
			if errors.Is(err, ErrBusy) {
				t.Errorf("worker %d: busy with %d slots and a %v wait", i, cap(hashSlots), hashWait)
			}
		}(i)
	}
	wg.Wait()
	if got := peak.Load(); got > int32(cap(hashSlots)) {
		t.Fatalf("%d hash runs in flight at once, slots allow %d", got, cap(hashSlots))
	}
	if inFlight.Load() != 0 {
		t.Fatalf("%d runs still counted in flight after all returned", inFlight.Load())
	}
	if len(hashSlots) != 0 {
		t.Fatalf("%d slots still taken after all returned", len(hashSlots))
	}
}

// With every slot taken for longer than hashWait, a check reports ErrBusy
// rather than wait on: the login answers 503 and counts no failure.  The
// user-not-found path (DummyCheckPassword) and hashing a new password say
// the same, so a busy daemon answers every path alike.
func TestPasswordCheckReportsBusyWhenSlotsStayTaken(t *testing.T) {
	origWait := hashWait
	hashWait = 20 * time.Millisecond
	t.Cleanup(func() { hashWait = origWait })

	for i := 0; i < cap(hashSlots); i++ {
		hashSlots <- struct{}{}
	}
	drained := false
	drain := func() {
		if drained {
			return
		}
		drained = true
		for i := 0; i < cap(hashSlots); i++ {
			<-hashSlots
		}
	}
	t.Cleanup(drain)

	if err := CheckPassword(dummyHash, "pw"); !errors.Is(err, ErrBusy) {
		t.Errorf("CheckPassword with every slot taken: err=%v, want ErrBusy", err)
	}
	if err := DummyCheckPassword("pw"); !errors.Is(err, ErrBusy) {
		t.Errorf("DummyCheckPassword with every slot taken: err=%v, want ErrBusy", err)
	}
	if _, err := HashPassword("pw"); !errors.Is(err, ErrBusy) {
		t.Errorf("HashPassword with every slot taken: err=%v, want ErrBusy", err)
	}

	// Slots given back: the checks run again, and a real mismatch is still a
	// mismatch, not ErrBusy.
	drain()
	if err := CheckPassword(dummyHash, "unmask-login-timing-equalizer"); err != nil {
		t.Errorf("CheckPassword after the slots were freed: %v", err)
	}
	if err := CheckPassword(dummyHash, "wrong"); err == nil || errors.Is(err, ErrBusy) {
		t.Errorf("a wrong password after the slots were freed: err=%v, want a mismatch", err)
	}
	if err := DummyCheckPassword("wrong"); err != nil {
		t.Errorf("DummyCheckPassword after the slots were freed: %v (a mismatch is discarded)", err)
	}
}
