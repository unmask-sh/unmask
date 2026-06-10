package cookies

import (
	"strconv"
	"strings"
	"testing"
)

// A "~"-joined _bv list must verify for EVERY IP that has an entry (any-match),
// so a roaming client stays passed on each network it solved on, but must still
// reject an IP it never verified on.
func TestVerifyMultiIPAnyMatch(t *testing.T) {
	const secret, host = "s3cr3t", "example.com"
	const powValid, captchaValid, powDiff = 604800, 1209600, 18

	a := IssueValue(secret, "1.1.1.1", host, "captcha") // 5G
	b := IssueValue(secret, "2.2.2.2", host, "captcha") // wifi
	list := AppendEntry(AppendEntry("", a), b)          // [b, a]

	if !Verify(list, secret, "1.1.1.1", host, powValid, captchaValid, powDiff) {
		t.Error("list must verify for IP 1.1.1.1 (entry a)")
	}
	if !Verify(list, secret, "2.2.2.2", host, powValid, captchaValid, powDiff) {
		t.Error("list must verify for IP 2.2.2.2 (entry b)")
	}
	if Verify(list, secret, "3.3.3.3", host, powValid, captchaValid, powDiff) {
		t.Error("list must NOT verify for an IP with no entry (no cross-IP grant)")
	}
	// host binding still holds across the list.
	if Verify(list, secret, "1.1.1.1", "other.com", powValid, captchaValid, powDiff) {
		t.Error("list must NOT verify for a different host")
	}
}

func TestAppendEntryCapAndDedup(t *testing.T) {
	list := ""
	for i := 0; i < 12; i++ {
		list = AppendEntry(list, "e"+strconv.Itoa(i))
	}
	parts := strings.Split(list, "~")
	if len(parts) != MaxBVEntries {
		t.Fatalf("list must cap at %d entries, got %d (%q)", MaxBVEntries, len(parts), list)
	}
	if parts[0] != "e11" {
		t.Errorf("newest entry must be first, got %q", parts[0])
	}

	// re-appending the current front entry must not duplicate it.
	again := AppendEntry(list, "e11")
	cnt := 0
	for _, p := range strings.Split(again, "~") {
		if p == "e11" {
			cnt++
		}
	}
	if cnt != 1 {
		t.Errorf("appending an existing entry must not duplicate it: %q", again)
	}
	// empty entry is a no-op.
	if AppendEntry(list, "  ") != list {
		t.Error("appending a blank entry must be a no-op")
	}
}
