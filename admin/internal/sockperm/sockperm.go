// Package sockperm sets the mode and the group owner of a unix socket the
// daemon binds for the web server to reach: the admin listener (server.bind
// unix:...) that nginx proxies to, and the access-log socket nginx's worker
// writes its lines into -- and of the directory they are bound in
// (ShareDir), which the worker has to pass through and which, shared by
// the same group, no other local user needs to.
//
// The worker runs as the web server's user, not the daemon's, so the socket
// is shared by group: mode 0660 and a group the worker belongs to.  That
// group differs by web server and distribution (nginx, apache, www-data,
// http); the operator may name it, and otherwise the first that exists on
// the host is taken.  When no such group can be applied -- none exists, or
// the daemon may not chown to it -- the socket would be unreachable at
// 0660.  The admin listener then stays at 0660 and says so (nginx's
// "connection refused" is loud and found at once); the log socket is
// instead opened to everyone (0666), because a log line that cannot be
// written is lost silently, and the operator is told to name the group
// (unmask doctor repeats it).
package sockperm

import (
	"fmt"
	"os"
	osuser "os/user"
	"strconv"
	"strings"
	"syscall"
)

// Spec is what the operator asked for: the mode as an octal string and the
// group's name, each "" for the default.
type Spec struct {
	Mode  string
	Group string
}

// Result is what Apply did.
type Result struct {
	// Mode the socket ended with.
	Mode os.FileMode
	// Group the socket is owned by, "" when no chown was applied.
	Group string
	// Notes are what the daemon log should carry: a group that could not
	// be applied, a choice between several.
	Notes []string
}

// WorldWritable reports whether the socket is writable by any local user.
func (r Result) WorldWritable() bool { return r.Mode&0o002 != 0 }

// WebServerGroups are the group names probed, in the order they are taken:
// nginx wins where several exist.
var WebServerGroups = []string{"nginx", "apache", "www-data", "http", "www"}

// DetectWebServerGroup probes the common web server groups and returns the
// first that exists plus all that do ("", nil when none).
func DetectWebServerGroup() (string, []string) {
	var found []string
	for _, cand := range WebServerGroups {
		if _, err := osuser.LookupGroup(cand); err == nil {
			found = append(found, cand)
		}
	}
	if len(found) == 0 {
		return "", nil
	}
	return found[0], found
}

// ParseFileMode reads an octal mode such as "0660" (the leading 0 is
// optional); "" is the fallback, anything else that does not parse is an
// error.
func ParseFileMode(s string, fallback os.FileMode) (os.FileMode, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback, nil
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return fallback, fmt.Errorf("mode %q is not octal (write it as 0660)", s)
	}
	return os.FileMode(v), nil
}

// Apply sets the socket at path to the mode and group spec asks for, the
// fallback mode when it names none.  loosen says what to do when the group
// cannot be applied to a group-shared mode: true opens the socket to
// everyone (0666) so the worker can still reach it, false keeps the mode.
// An error is the chmod failing; everything else is a note.
func Apply(path string, spec Spec, fallback os.FileMode, loosen bool) (Result, error) {
	var res Result
	mode, err := ParseFileMode(spec.Mode, fallback)
	if err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("%v; using %#o", err, fallback))
	}
	// A world-writable mode makes the group moot: no probe, no chown
	// unless a group was named (harmless then).
	group := strings.TrimSpace(spec.Group)
	if group == "" && mode&0o002 == 0 {
		g, all := DetectWebServerGroup()
		switch {
		case g == "" && loosen:
			res.Notes = append(res.Notes, fmt.Sprintf("no web server group found on this host (%s); %s is open to every local user (0666) so the worker can reach it -- name the worker's group to share it by group instead", strings.Join(WebServerGroups, ", "), path))
			mode = 0o666
		case g == "":
			group = "nginx" // none found; the lookup below says so
		default:
			group = g
			if len(all) > 1 {
				res.Notes = append(res.Notes, fmt.Sprintf("several web server groups exist (%s); %s is shared with %q -- name the group explicitly if the front-end runs as another", strings.Join(all, ", "), path, g))
			}
		}
	}
	if group != "" {
		gid, lookupErr := lookupGID(group)
		var chownErr error
		if lookupErr == nil {
			chownErr = os.Chown(path, -1, gid)
		}
		switch {
		case lookupErr == nil && chownErr == nil:
			res.Group = group
		case loosen && mode&0o002 == 0:
			cause := lookupErr
			if cause == nil {
				cause = chownErr
			}
			res.Notes = append(res.Notes, fmt.Sprintf("cannot give %s to group %q (%v); it is open to every local user (0666) so the worker can reach it -- fix the group (the daemon must be a member of it) to share it by group instead", path, group, cause))
			mode = 0o666
		case lookupErr != nil:
			res.Notes = append(res.Notes, fmt.Sprintf("socket group %q lookup failed: %v (chown skipped; the web server worker may not be able to reach %s -- change the group or run groupadd)", group, lookupErr, path))
		default:
			res.Notes = append(res.Notes, fmt.Sprintf("socket chown :%s failed: %v (insufficient permission?  %s stays with the daemon's group)", group, chownErr, path))
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		return res, fmt.Errorf("chmod %s: %w", path, err)
	}
	res.Mode = mode
	return res, nil
}

// ShareDir sets the directory a shared socket is bound in so that the
// worker passes through it and other local users do not: 0750, owned by
// the socket's group (the one Apply gave it).  The daemon owns the
// directory (the service manager makes it so: RuntimeDirectory=unmask) and
// may give it to a group it is a member of, which the worker's group is.
// With no group to share with -- the socket is open to every local user, or
// no group could be applied -- the directory is 0755 instead, since the
// worker still has to pass through it; and a directory the daemon does not
// own (a socket under /tmp in development) is left as it is.  The mode the
// directory ended with, and what the log should say.
func ShareDir(dir, group string) (os.FileMode, []string) {
	dir = strings.TrimSpace(dir)
	if dir == "" || dir == "." {
		return 0, nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, []string{fmt.Sprintf("%s: %v (the socket's directory is left as it is)", dir, err)}
	}
	if !ownedByMe(fi) {
		return fi.Mode().Perm(), nil
	}
	var notes []string
	if group != "" {
		gid, err := lookupGID(group)
		if err == nil {
			err = os.Chown(dir, -1, gid)
		}
		if err == nil {
			if err := os.Chmod(dir, 0o750); err != nil {
				return fi.Mode().Perm(), []string{fmt.Sprintf("chmod %s: %v", dir, err)}
			}
			return 0o750, nil
		}
		notes = append(notes, fmt.Sprintf("cannot give %s to group %q (%v); it is 0755 so the worker can pass through it (every local user can)", dir, group, err))
	} else {
		notes = append(notes, fmt.Sprintf("%s is 0755 so the worker can pass through it (every local user can): the socket in it is not shared by group", dir))
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return fi.Mode().Perm(), append(notes, fmt.Sprintf("chmod %s: %v", dir, err))
	}
	return 0o755, notes
}

// ownedByMe reports whether the file belongs to this process's user.
func ownedByMe(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Getuid())
}

func lookupGID(group string) (int, error) {
	g, err := osuser.LookupGroup(group)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("group %q has gid %q", group, g.Gid)
	}
	return gid, nil
}
