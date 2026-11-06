package reexec

import (
	"errors"
	"os"
	"slices"
	"testing"
)

// Self starts the running binary again with the arguments and environment
// it was started with, and hands back the failure when there is one: the
// caller then goes on (the wizard names a manual restart, the database wait
// tries again), so a failure must not be swallowed here.  The exec itself is
// swapped out: under `go test` it would start the test binary over.
func TestSelfExecsTheRunningBinaryWithItsArguments(t *testing.T) {
	prev := execFn
	t.Cleanup(func() { execFn = prev })

	var gotExe string
	var gotArgs, gotEnv []string
	execFn = func(exe string, args, env []string) error {
		gotExe, gotArgs, gotEnv = exe, args, env
		return nil
	}
	if err := Self(); err != nil {
		t.Fatalf("Self: %v", err)
	}
	want, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if gotExe != want || gotExe != Executable() {
		t.Errorf("exec of %q, want the running binary %q", gotExe, want)
	}
	if !slices.Equal(gotArgs, os.Args) {
		t.Errorf("arguments %v, want the process's own %v", gotArgs, os.Args)
	}
	if !slices.Equal(gotEnv, os.Environ()) {
		t.Errorf("environment differs from the process's own")
	}

	gone := errors.New("no such file or directory")
	execFn = func(string, []string, []string) error { return gone }
	if err := Self(); !errors.Is(err, gone) {
		t.Errorf("Self = %v, want the exec's failure", err)
	}
}
