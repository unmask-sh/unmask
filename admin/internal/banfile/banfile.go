// Package banfile answers one question about the ban list: can nginx's
// worker read it?
//
// The daemon writes the list (ban.Manager) and the module reads it on every
// request -- a stat() for a change, then the file -- from nginx's WORKER,
// which runs as nginx.conf's `user` (nginx, www-data, http), not as the
// daemon.  The worker needs to pass through every directory on the path (x)
// and read the file (r).  Through 0.1.53-rc12 the package made
// /var/lib/unmask 0750 unmask:unmask, so on every install whose worker is
// another user -- nearly all of them -- the stat() failed with EACCES and the
// module enforced no ban, and said nothing about it until rc11's warning
// (kanagawa, 2026-10-24).  The package now makes the directory 0751 and the
// daemon keeps it passable; this package is how the doctor, the admin's
// notice bar and the install scripts tell whether the worker gets through,
// by the same rules the kernel applies: owner, group (with the supplementary
// groups), other, and a POSIX ACL where one is set.
package banfile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Verdict: whether the worker user reads the ban list, and if not, which
// path component stops it.
type Verdict struct {
	OK bool
	// User: the worker user the verdict is about; Source says where the
	// name came from ("nginx.conf", "nginx -V", "default").
	User   string
	Source string
	// Blocker: the directory the worker cannot pass through, or the file
	// it cannot read; Need is "x" or "r" accordingly.  Empty when OK.
	Blocker string
	Need    string
	// Err: the question could not be answered -- the file is absent, the
	// user is unknown to the system -- and the verdict says nothing.
	Err error
}

// ErrNoNginx: neither nginx.conf nor an nginx binary is here (an admin-only
// box, the admin container), so there is no worker to ask about.
var ErrNoNginx = errors.New("no nginx on this host")

// userDirectiveRE: `user NAME [GROUP];` at the top of nginx.conf.  A
// commented line is dropped before matching.
var userDirectiveRE = regexp.MustCompile(`^\s*user\s+([^\s;]+)`)

// WorkerUser: the user nginx's workers run as.  nginx.conf's `user`
// directive when it has one, else the `--user=` the binary was built with
// (nginx -V), else nginx's own default, nobody.  confPath "" means
// /etc/nginx/nginx.conf.  ErrNoNginx when there is neither a conf nor a
// binary to ask.
func WorkerUser(confPath string) (name, source string, err error) {
	if strings.TrimSpace(confPath) == "" {
		confPath = "/etc/nginx/nginx.conf"
	}
	b, rerr := os.ReadFile(confPath)
	if rerr == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			if m := userDirectiveRE.FindStringSubmatch(line); m != nil {
				return m[1], "nginx.conf", nil
			}
		}
	}
	bin, lerr := exec.LookPath("nginx")
	if lerr != nil {
		if rerr != nil {
			return "", "", ErrNoNginx
		}
		return "nobody", "default", nil
	}
	ctx, cancel := contextWithTimeout(3 * time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "-V").CombinedOutput()
	for _, f := range strings.Fields(string(out)) {
		if strings.HasPrefix(f, "--user=") {
			if u := strings.TrimPrefix(f, "--user="); u != "" {
				return u, "nginx -V", nil
			}
		}
	}
	return "nobody", "default", nil
}

// Check: the verdict for the ban list at path, read by nginx's worker.
func Check(path, confPath string) Verdict {
	name, source, err := WorkerUser(confPath)
	if err != nil {
		return Verdict{Err: err}
	}
	v := Verdict{User: name, Source: source}
	u, lerr := user.Lookup(name)
	if lerr != nil {
		v.Err = fmt.Errorf("nginx's worker user %q is not an account on this host", name)
		return v
	}
	uid, gids, gerr := ids(u)
	if gerr != nil {
		v.Err = gerr
		return v
	}
	blocker, need, aerr := AccessAs(path, uid, gids)
	if aerr != nil {
		v.Err = aerr
		return v
	}
	v.OK = blocker == ""
	v.Blocker, v.Need = blocker, need
	return v
}

// ids: the uid and every gid (primary and supplementary) of u.
func ids(u *user.User) (uint32, []uint32, error) {
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, nil, fmt.Errorf("uid of %s: %w", u.Username, err)
	}
	var gids []uint32
	if g, err := strconv.ParseUint(u.Gid, 10, 32); err == nil {
		gids = append(gids, uint32(g))
	}
	if more, err := u.GroupIds(); err == nil {
		for _, s := range more {
			if g, err := strconv.ParseUint(s, 10, 32); err == nil {
				gids = append(gids, uint32(g))
			}
		}
	}
	return uint32(uid64), gids, nil
}

// AccessAs: whether a process running as uid with groups gids can read the
// file at path: x on every directory from the root down, r on the file.
// Returns the first component that refuses, and "x" or "r"; both empty
// when the file is readable.  An error means a component could not be
// looked at (absent, or unreadable by this process itself).
func AccessAs(path string, uid uint32, gids []uint32) (blocker, need string, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	// Every directory above the file, root first.
	var dirs []string
	for d := filepath.Dir(abs); ; d = filepath.Dir(d) {
		dirs = append([]string{d}, dirs...)
		if d == filepath.Dir(d) {
			break
		}
	}
	for _, d := range dirs {
		ok, err := allows(d, uid, gids, permX)
		if err != nil {
			return "", "", err
		}
		if !ok {
			return d, "x", nil
		}
	}
	ok, err := allows(abs, uid, gids, permR)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return abs, "r", nil
	}
	return "", "", nil
}

const (
	permR = 4
	permX = 1
)

// allows: the kernel's answer for one permission bit on one path, from the
// mode and, when the file carries one, its access ACL.  Root passes.
func allows(path string, uid uint32, gids []uint32, bit uint32) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if uid == 0 {
		return true, nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("%s: no owner information", path)
	}
	mode := uint32(fi.Mode().Perm())
	if acl := readACL(path); acl != nil {
		return aclAllows(acl, st.Uid, st.Gid, uid, gids, bit), nil
	}
	switch {
	case uid == st.Uid:
		return mode>>6&bit != 0, nil
	case hasGID(gids, st.Gid):
		return mode>>3&bit != 0, nil
	default:
		return mode&bit != 0, nil
	}
}

func hasGID(gids []uint32, g uint32) bool {
	for _, x := range gids {
		if x == g {
			return true
		}
	}
	return false
}

// A POSIX access ACL, as the system.posix_acl_access extended attribute
// stores it: a 4-byte version (2) and 8-byte entries of tag, perm and id.
const (
	aclVersion   = 2
	aclUserObj   = 0x01
	aclUser      = 0x02
	aclGroupObj  = 0x04
	aclGroup     = 0x08
	aclMask      = 0x10
	aclOther     = 0x20
	aclXattrName = "system.posix_acl_access"
)

type aclEntry struct {
	tag  uint16
	perm uint16
	id   uint32
}

// readACL: the access ACL of path, nil when it has none (or the attribute
// cannot be read, which the mode bits then answer for).
func readACL(path string) []aclEntry {
	buf := make([]byte, 1024)
	n, err := syscall.Getxattr(path, aclXattrName, buf)
	if err != nil || n <= 0 {
		return nil
	}
	return parseACL(buf[:n])
}

// parseACL: the entries of an ACL blob; nil for a version or length it
// does not understand.
func parseACL(b []byte) []aclEntry {
	if len(b) < 4 || binary.LittleEndian.Uint32(b[:4]) != aclVersion || (len(b)-4)%8 != 0 {
		return nil
	}
	var out []aclEntry
	for p := 4; p+8 <= len(b); p += 8 {
		out = append(out, aclEntry{
			tag:  binary.LittleEndian.Uint16(b[p:]),
			perm: binary.LittleEndian.Uint16(b[p+2:]),
			id:   binary.LittleEndian.Uint32(b[p+4:]),
		})
	}
	return out
}

// aclAllows: the POSIX ACL algorithm (acl(5)): the owner's entry, else a
// matching named user, else any matching group entry (the owning group's
// or a named one) that grants the bit, else the other entry.  The mask
// caps every entry but the owner's and other's.
func aclAllows(acl []aclEntry, owner, ownerGroup, uid uint32, gids []uint32, bit uint32) bool {
	mask := uint32(7)
	for _, e := range acl {
		if e.tag == aclMask {
			mask = uint32(e.perm)
		}
	}
	for _, e := range acl {
		if e.tag == aclUserObj && uid == owner {
			return uint32(e.perm)&bit != 0
		}
	}
	for _, e := range acl {
		if e.tag == aclUser && e.id == uid {
			return uint32(e.perm)&mask&bit != 0
		}
	}
	groupMatched := false
	for _, e := range acl {
		switch e.tag {
		case aclGroupObj:
			if hasGID(gids, ownerGroup) {
				groupMatched = true
				if uint32(e.perm)&mask&bit != 0 {
					return true
				}
			}
		case aclGroup:
			if hasGID(gids, e.id) {
				groupMatched = true
				if uint32(e.perm)&mask&bit != 0 {
					return true
				}
			}
		}
	}
	if groupMatched {
		return false
	}
	for _, e := range acl {
		if e.tag == aclOther {
			return uint32(e.perm)&bit != 0
		}
	}
	return false
}

// FixCommands: what to run so the worker gets through, for the verdict's
// blocker: pass-through (x for others, nothing else changes) on a
// directory, read for others on the file.
func FixCommands(v Verdict) []string {
	if v.OK || v.Blocker == "" {
		return nil
	}
	if v.Need == "x" {
		return []string{"sudo chmod o+x " + v.Blocker}
	}
	return []string{"sudo chmod o+r " + v.Blocker}
}

// Describe: one English sentence for logs and the doctor: who cannot do
// what, where.
func Describe(v Verdict) string {
	if v.Err != nil {
		return v.Err.Error()
	}
	if v.OK {
		return fmt.Sprintf("nginx's worker user %s (%s) reads the ban list", v.User, v.Source)
	}
	what := "pass through " + v.Blocker + " (no x for others)"
	if v.Need == "r" {
		what = "read " + v.Blocker + " (no r for others)"
	}
	return fmt.Sprintf("nginx's worker user %s (%s) cannot %s, so nginx enforces no ban", v.User, v.Source, what)
}
