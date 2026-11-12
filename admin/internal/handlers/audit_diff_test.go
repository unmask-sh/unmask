package handlers

import (
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"testing"
)

// lcsLen is the textbook table, kept here as the reference the diff is held
// to: the number of lines two texts share, in order.
func lcsLen(a, b []string) int {
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	return dp[len(a)][len(b)]
}

// The diff of two texts is minimal (as many lines as a longest common
// subsequence leaves over) and exact (taking the "-" lines out of the first
// text and putting the "+" lines in gives the second, as bags of lines),
// with the shared start and end set aside or not.
func TestUnifiedDiffIsMinimalAndExact(t *testing.T) {
	rng := rand.New(rand.NewSource(20261112))
	words := []string{"a", "b", "c", "d", "e", "  - x", "  - y", "key: 1", "key: 2", ""}
	text := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = words[rng.Intn(len(words))]
		}
		return out
	}
	for round := 0; round < 400; round++ {
		head, tail := text(rng.Intn(6)), text(rng.Intn(6))
		a := append(append(append([]string{}, head...), text(rng.Intn(12))...), tail...)
		b := append(append(append([]string{}, head...), text(rng.Intn(12))...), tail...)
		if len(a) == 0 || len(b) == 0 {
			continue
		}
		got := UnifiedDiff(strings.Join(a, "\n")+"\n", strings.Join(b, "\n")+"\n")
		var minus, plus []string
		if got != "(no changes)" {
			for _, l := range strings.Split(got, "\n") {
				switch {
				case strings.HasPrefix(l, "- "):
					minus = append(minus, l[2:])
				case strings.HasPrefix(l, "+ "):
					plus = append(plus, l[2:])
				default:
					t.Fatalf("round %d: unexpected line %q in\n%s", round, l, got)
				}
			}
		}
		// TrimRight in UnifiedDiff drops trailing empty lines, as it always did.
		for len(a) > 1 && a[len(a)-1] == "" {
			a = a[:len(a)-1]
		}
		for len(b) > 1 && b[len(b)-1] == "" {
			b = b[:len(b)-1]
		}
		if want := len(a) + len(b) - 2*lcsLen(a, b); len(minus)+len(plus) != want {
			t.Fatalf("round %d: %d changed lines, a minimal diff has %d\n--- a\n%s\n--- b\n%s\n--- diff\n%s", round, len(minus)+len(plus), want, strings.Join(a, "\n"), strings.Join(b, "\n"), got)
		}
		bag := map[string]int{}
		for _, l := range a {
			bag[l]++
		}
		for _, l := range minus {
			bag[l]--
		}
		for _, l := range plus {
			bag[l]++
		}
		for _, l := range b {
			bag[l]--
		}
		for l, c := range bag {
			if c != 0 {
				t.Fatalf("round %d: the diff does not turn a into b (line %q off by %d)\n%s", round, l, c, got)
			}
		}
	}
}

// One changed line in a settings snapshot of an install with long lists.
// The table used to cover both snapshots whole -- 10,000 lines against
// 10,000 is most of a gigabyte -- for a diff of two lines.
func TestUnifiedDiffOfOneLineDoesNotBuildTheWholeTable(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(&sb, "    - entry-%d\n", i)
	}
	before := sb.String()
	after := strings.Replace(before, "    - entry-5000\n", "    - entry-5000-edited\n", 1)

	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	got := UnifiedDiff(before, after)
	runtime.ReadMemStats(&m1)
	if want := "-     - entry-5000\n+     - entry-5000-edited"; got != want {
		t.Errorf("diff = %q, want %q", got, want)
	}
	if mib := float64(m1.TotalAlloc-m0.TotalAlloc) / (1 << 20); mib > 8 {
		t.Errorf("a one-line diff of two 10,000-line snapshots allocated %.0f MiB", mib)
	}
}

// A list pasted over wholesale is past what the table may cover: the diff
// gives up line order, not itself -- what left and what came -- within the
// same bound of memory and of lines kept.
func TestUnifiedDiffOfAWholesaleChange(t *testing.T) {
	var a, b strings.Builder
	a.WriteString("list:\n")
	b.WriteString("list:\n")
	for i := 0; i < 6000; i++ {
		fmt.Fprintf(&a, "  - old-%d\n", i)
		fmt.Fprintf(&b, "  - new-%d\n", i)
	}
	a.WriteString("  - kept\nend: true\n")
	b.WriteString("  - kept\nend: true\n")

	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	got := UnifiedDiff(a.String(), b.String())
	runtime.ReadMemStats(&m1)
	if mib := float64(m1.TotalAlloc-m0.TotalAlloc) / (1 << 20); mib > 32 {
		t.Errorf("allocated %.0f MiB", mib)
	}
	lines := strings.Split(got, "\n")
	if len(lines) != diffMaxLines+1 || lines[len(lines)-1] != "  ... (diff truncated)" {
		t.Fatalf("%d lines, last %q; want %d and the truncation mark", len(lines), lines[len(lines)-1], diffMaxLines+1)
	}
	if !strings.Contains(lines[0], "6000 lines became 6000") {
		t.Errorf("the first line does not say the order was given up: %q", lines[0])
	}
	if lines[1] != "-   - old-0" {
		t.Errorf("line 2 = %q", lines[1])
	}
	for _, l := range lines {
		if strings.Contains(l, "kept") || strings.Contains(l, "end: true") || strings.Contains(l, "list:") {
			t.Errorf("an unchanged line is in the diff: %q", l)
		}
	}

	// The same lines in another order, past the table's bound: said so, in
	// two lines.
	var fwd, back strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&fwd, "  - row-%d\n", i)
		fmt.Fprintf(&back, "  - row-%d\n", 2999-i)
	}
	if got := UnifiedDiff(fwd.String(), back.String()); strings.Count(got, "\n") != 1 || !strings.Contains(got, "in a different order") {
		t.Errorf("a reordered list: %q", got)
	}
	if got := UnifiedDiff("same\n", "same\n"); got != "(no changes)" {
		t.Errorf("equal texts: %q", got)
	}
}
