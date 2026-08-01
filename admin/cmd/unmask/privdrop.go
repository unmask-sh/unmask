package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// Privilege drop for root-invoked CLI runs.
//
// Every documented management command is run with sudo (`sudo unmask
// install-ipgeo`, `sudo unmask render-nginx`, `sudo unmask migrate`), and each
// one writes into the daemon's own directories.  Running them as root leaves
// root-owned files behind that the daemon -- which runs as its unprivileged
// service user -- can then no longer write, and in the mmdb case could no
// longer even read: geo lookups went silent across the fleet while `doctor`
// still reported the file as present and current, because doctor was reading
// it with root's privileges rather than the daemon's.
//
// Chowning after each write was the obvious patch and the wrong one: it has to
// be remembered at every new write site, and it cannot cover SQLite at all --
// the -wal and -shm files are recreated on every open, so a root-run `migrate`
// or `user` re-creates the problem no matter how carefully the .sqlite file
// itself is fixed up afterwards.
//
// So the process drops to the daemon's identity before doing any work.
// Whatever a command writes is then owned correctly by construction, including
// files created by libraries we do not control.
const noPrivDropEnv = "UNMASK_NO_PRIVDROP"

// dataDirForOwner is the directory whose ownership names the identity the
// daemon runs as.  Deliberately not a hardcoded "unmask" lookup: an operator
// who runs the service under a different account (or a container image that
// numbers it differently) still gets the right answer, and an install whose
// directory is root-owned -- a legitimate single-user setup -- yields root and
// no drop at all.
var dataDirForOwner = "/var/lib/unmask"

// dropPrivilegesIfRoot switches the process to the owner of the daemon's data
// directory when running as root.  A no-op when not root, when the directory
// is root-owned (nothing to drop to), or when the operator sets
// UNMASK_NO_PRIVDROP=1.
//
// Returns a human-readable note describing what happened, for verbose output;
// an error means the drop was attempted and failed, and the caller must abort
// rather than continue with full privileges: silently proceeding as root is
// what produced the mess this exists to prevent.
func dropPrivilegesIfRoot() (string, error) {
	if os.Geteuid() != 0 {
		return "", nil
	}
	if v := os.Getenv(noPrivDropEnv); v != "" && v != "0" {
		return fmt.Sprintf("running as root (%s set); files it creates will be root-owned", noPrivDropEnv), nil
	}
	uid, gid, name, err := daemonIdentity()
	if err != nil {
		// No data directory yet (a fresh install running config-init) is not
		// an error: there is nothing to own incorrectly.
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	if uid == 0 {
		return "", nil // data dir is root's; the daemon runs as root too
	}
	// Order matters: setgid first, because after setuid the process can no
	// longer change its group.
	if err := syscall.Setgid(gid); err != nil {
		return "", fmt.Errorf("drop privileges to %s: setgid(%d): %w", name, gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return "", fmt.Errorf("drop privileges to %s: setuid(%d): %w", name, uid, err)
	}
	return fmt.Sprintf("dropped privileges to %s (uid %d) -- files this command creates belong to the daemon", name, uid), nil
}

// daemonIdentity reads the uid/gid off the data directory and resolves a name
// for it (falling back to the numeric uid when the account has no passwd
// entry, which is normal in containers).
func daemonIdentity() (uid, gid int, name string, err error) {
	st, err := os.Stat(dataDirForOwner)
	if err != nil {
		return 0, 0, "", err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, "", fmt.Errorf("cannot read ownership of %s on this platform", dataDirForOwner)
	}
	uid, gid = int(sys.Uid), int(sys.Gid)
	name = strconv.Itoa(uid)
	if u, uerr := user.LookupId(name); uerr == nil && u.Username != "" {
		name = u.Username
	}
	return uid, gid, name, nil
}

// privDropExempt lists the sub-commands that must keep root.  Empty today:
// every command writes into the daemon's own directories, and the paths that
// genuinely need root (placing the nginx module, editing the web server's
// config) live in the packages' shell scripts, not in this binary.  Kept as
// the explicit place to record an exception -- with its reason -- rather than
// having one appear as a scattered euid check.
var privDropExempt = map[string]bool{}

// serve is exempt in practice rather than by listing: the service manager
// starts it as the daemon user already, so the drop is a no-op.  Leaving it on
// the same path means a hand-started `sudo unmask serve` also stops writing
// root-owned state.

// applyPrivDrop is the main() entry point: drops for the given sub-command
// unless it is exempt, and reports the outcome on stderr so an operator
// debugging a permission problem can see which identity did the work.
func applyPrivDrop(cmd string, verbose bool) error {
	if privDropExempt[cmd] {
		return nil
	}
	note, err := dropPrivilegesIfRoot()
	if err != nil {
		return err
	}
	if note != "" && verbose {
		fmt.Fprintln(os.Stderr, "unmask: "+note)
	}
	return nil
}

// ownershipProblems reports files under the daemon's directories that its
// service user cannot write, which is the residue of past root-run commands.
// Used by doctor; returns paths, not a verdict, so the caller words it.
func ownershipProblems(dirs []string, uid, gid int) []string {
	var bad []string
	for _, dir := range dirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil //nolint:nilerr // an unreadable subtree is its own report elsewhere
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			if int(st.Uid) == uid {
				return nil // owner: mode bits are the owner's own business
			}
			mode := info.Mode().Perm()
			if int(st.Gid) == gid && mode&0o020 != 0 {
				return nil // group-writable and we are in the group
			}
			if mode&0o002 != 0 {
				return nil // world-writable
			}
			bad = append(bad, path)
			return nil
		})
	}
	return bad
}
