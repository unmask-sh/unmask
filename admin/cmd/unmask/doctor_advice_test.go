package main

import "testing"

// Advice a reader cannot act on is worse than no advice: they follow it, land
// in the same place, and conclude the check is broken.
//
// `doctor` is not on privDropExempt, so a root invocation drops to the daemon
// account before any check runs.  The nginx -t check therefore ALWAYS sees a
// non-root euid, and its old text ("re-run `sudo unmask doctor`") named the
// exact command that had just failed to help -- observed across a 7-node fleet,
// where running it under sudo changed nothing.
func TestDoctorNeverTellsTheOperatorToSudoItself(t *testing.T) {
	if privDropExempt["doctor"] {
		t.Skip("doctor is exempt from the privilege drop; the advice below is reachable again")
	}
	// Simulate the state a root invocation leaves behind.
	saved := droppedFromRoot
	droppedFromRoot = "unmask"
	defer func() { droppedFromRoot = saved }()

	got := nginxTestPermissionAdvice("cannot load certificate ...")
	if containsFold(got, "sudo unmask doctor") {
		t.Errorf("doctor tells the operator to re-run itself under sudo, which cannot help: %q", got)
	}
	if !containsFold(got, "sudo nginx -t") {
		t.Errorf("the advice should name a command that works (sudo nginx -t), got %q", got)
	}
	if !containsFold(got, "unmask") {
		t.Errorf("the advice should name the account that ran the test, got %q", got)
	}

	// With no drop (a genuinely unprivileged invocation) the advice is simply
	// to use root -- still not "sudo unmask doctor", which would be circular.
	droppedFromRoot = ""
	if plain := nginxTestPermissionAdvice("x"); containsFold(plain, "sudo unmask doctor") {
		t.Errorf("unprivileged advice is circular too: %q", plain)
	}
}

func containsFold(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
