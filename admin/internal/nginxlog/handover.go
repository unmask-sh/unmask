package nginxlog

// The log socket across a restart of the daemon.
//
// nginx's workers log through a connected datagram socket: each connects to
// the socket path once and sends on that connection.  A daemon that binds a
// new socket on every start leaves them connected to the old one, which went
// with the old process: each worker's next line is refused and lost (nginx
// logs "send() failed (111: Connection refused) while logging to syslog",
// closes its end and connects afresh on the line after), and so is every
// line logged while the daemon is down.
//
// Under systemd the socket outlives the process instead.  The daemon hands
// it to the service manager's file descriptor store (sd_notify FDSTORE=1),
// systemd keeps the directory it is bound in over a restart
// (RuntimeDirectoryPreserve=restart), and the next start gets it back
// (LISTEN_FDS / LISTEN_FDNAMES) and reads on: nginx's connections hold, and
// what is logged meanwhile waits in the socket's queue -- a few hundred
// lines: each worker's send buffer holds about two hundred, and the socket
// takes net.unix.max_dgram_qlen in all (512 under systemd).  Past that nginx
// drops the line and keeps its connection (it says so at warn level, below
// what error_log shows by default).  A stop still ends it: systemd discards
// the store and removes the directory.
//
// The one thing that must never happen is a kept socket nobody reads: it
// stays alive in the store, nginx's workers stay connected to it, and every
// line they log is lost without an error anywhere.  So a kept socket is only
// ever left to a reader:
//
//   - systemd hands it only to a binary that takes it.  The drop-in runs a
//     check before every start: when the binary about to start does not
//     carry the marker below -- a version from before this, put in this
//     one's place -- the socket is taken out of the store first, and that
//     binary binds its own, as it always did.  This holds however the
//     daemon before it ended;
//   - on its way out the daemon does the same at once rather than at the
//     next start: for a successor without the marker it shuts the socket
//     down, so nginx's workers find out on their next line;
//   - a socket this daemon lets go of -- it binds afresh, or has no log
//     receiver -- is shut down and removed from the store.  Shut down, it
//     takes no more: a sender gets an error and connects afresh, and
//     systemd drops its copy when it sees the hang-up;
//   - a kept socket whose path no longer leads to a live socket (another
//     process bound the same path and went away) is let go, and the path
//     bound afresh: taking it back would leave new connections refused over
//     every restart;
//   - whatever else the service manager hands over under another name is
//     closed and taken out of the store;
//   - a daemon that is handed nothing and binds nothing takes its name out
//     of the store all the same: what it stored before it re-executed itself
//     (the setup wizard's last step) is not handed back to it.  So does a
//     start that ends on a config it cannot load (cmdServe).
//
// The package turns this on with a unit drop-in, and only where systemd is
// 236 or later (rpm/scripts/postinstall.sh): FDSTOREREMOVE, which replaces a
// stored socket in step with the messages around it, is that recent, and so
// nearly are RuntimeDirectoryPreserve= and NotifyAccess=exec, which lets the
// check before the start speak (235).  The drop-in sets HandoverEnv;
// without it -- an older systemd, OpenRC, SysV, the container -- nothing is
// stored, and the socket is bound afresh on every start and removed on stop,
// as before.

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	// HandoverEnv is set by the unit drop-in that keeps the socket over a
	// restart.  The name is also the marker by which a binary is known to
	// take a kept socket back: the drop-in's check before every start,
	// successorTakesOver here, and the package's postremove.sh look for it
	// in the binary on disk.  Do not rename it.
	HandoverEnv = "UNMASK_LOG_HANDOVER"
	// fdStoreName names the socket in the service manager's store.  A
	// socket handed back under any other name -- one a version with another
	// name left there -- is not taken; it is closed and removed from the
	// store (handedBack).
	fdStoreName = "nginxlog"
)

// listenFDsStart is SD_LISTEN_FDS_START, the first descriptor systemd passes;
// a variable so that a test can hand over a descriptor it opened itself.
var listenFDsStart = 3

// successorPath is where the next start finds its binary: the path this
// process was started with -- systemd's ExecStart -- and not the running
// image's present name, which follows the file when it is renamed out of the
// way for another to take its place.  A variable so that a test can put
// another binary there.
var successorPath = func() (string, error) {
	if filepath.IsAbs(os.Args[0]) {
		return os.Args[0], nil
	}
	return os.Executable()
}

var errNoServiceManager = errors.New("no service manager to hand the socket to")

// handoverOn reports whether the socket is to be kept in the service
// manager's store: the drop-in asked for it, and there is a manager to tell.
func handoverOn() bool {
	return os.Getenv(HandoverEnv) == "1" && os.Getenv("NOTIFY_SOCKET") != ""
}

// handedBack returns the descriptor systemd passed under name, or nil.  The
// LISTEN_* variables describe this process alone and are cleared once read:
// a process this daemon starts -- or the setup wizard's re-exec, which keeps
// the PID but not the descriptors -- must not take them for its own.
//
// Every other descriptor passed is closed, and its name taken out of the
// store: a socket kept under a name this version does not know would
// otherwise stay alive there, and in this process, with nobody reading it.
func handedBack(name string) *os.File {
	pid, count, names := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"), os.Getenv("LISTEN_FDNAMES")
	for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(k)
	}
	if pid != strconv.Itoa(os.Getpid()) {
		return nil
	}
	n, err := strconv.Atoi(count)
	if err != nil || n <= 0 {
		return nil
	}
	list := strings.Split(names, ":")
	var found *os.File
	for i := 0; i < n; i++ {
		fd := listenFDsStart + i
		if found == nil && i < len(list) && list[i] == name {
			// Passed without close-on-exec; nothing this daemon starts
			// is to inherit it.
			syscall.CloseOnExec(fd)
			found = os.NewFile(uintptr(fd), name)
			continue
		}
		_ = syscall.Shutdown(fd, syscall.SHUT_RDWR)
		_ = syscall.Close(fd)
		if i < len(list) && list[i] != "" && list[i] != name {
			_ = notify("FDSTOREREMOVE=1\nFDNAME="+list[i], -1)
		}
	}
	return found
}

// adopt takes back the socket the service manager kept, when it is still the
// datagram socket bound at path and the path still leads to a live socket.
// Anything else -- the path changed, its directory went with a stop, another
// process bound the path and left a dead file there -- is let go, and the
// caller binds afresh.
func adopt(path string) *net.UnixConn {
	f := handedBack(fdStoreName)
	if f == nil {
		return nil
	}
	defer f.Close()
	pc, err := net.FilePacketConn(f)
	if err != nil {
		letGo(f)
		return nil
	}
	uc, _ := pc.(*net.UnixConn)
	var bound string
	if uc != nil {
		if la, _ := uc.LocalAddr().(*net.UnixAddr); la != nil && la.Net == "unixgram" {
			bound = la.Name
		}
	}
	if fi, err := os.Lstat(path); bound == "" || bound != path || err != nil || fi.Mode()&os.ModeSocket == 0 || !reachable(path) {
		letGo(f)
		_ = pc.Close()
		// The file it was bound to leads nowhere now.
		if bound != "" && bound != path {
			removeSocketFile(bound)
		}
		return nil
	}
	return uc
}

// reachable reports whether a sender connecting to path now would reach a
// live socket.  The kept socket is alive by definition, so a refusal means
// the file at path is not its own any more: a second daemon started on the
// same config bound the path, and died without removing its file.  (One still
// running there answers, and is not told apart from the kept socket: two
// daemons on one path were never right.)  No line is sent.
func reachable(path string) bool {
	s, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return true // cannot tell: as before
	}
	defer func() { _ = syscall.Close(s) }()
	err = syscall.Connect(s, &syscall.SockaddrUnix{Name: path})
	return err == nil || !(errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT))
}

// Release lets go of a socket the service manager kept over the restart, for
// a daemon that starts without a log receiver (no database yet): nginx must
// not go on logging into a socket nobody reads.  Its file goes too, as when
// no receiver ever bound one.
func Release() {
	f := handedBack(fdStoreName)
	if f == nil {
		forget()
		return
	}
	var bound string
	if rc, err := f.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			if sa, err := syscall.Getsockname(int(fd)); err == nil {
				if u, ok := sa.(*syscall.SockaddrUnix); ok {
					bound = u.Name
				}
			}
		})
	}
	letGo(f)
	_ = f.Close()
	if bound != "" {
		removeSocketFile(bound)
	}
}

// letGo ends a kept socket for good.  Shutting it down is what counts: it
// acts on the socket itself, whoever holds a descriptor for it, so it takes
// no more lines -- a sender gets an error on its next one and connects
// afresh -- and systemd drops its copy when it sees the hang-up.  The removal
// from the store is said as well, so that a socket stored next finds the
// place free.
func letGo(f syscall.Conn) {
	if rc, err := f.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) { _ = syscall.Shutdown(int(fd), syscall.SHUT_RDWR) })
	}
	_ = notify("FDSTOREREMOVE=1\nFDNAME="+fdStoreName, -1)
}

// forget takes whatever the store holds under this daemon's name out of it,
// for a daemon that was handed nothing and stores nothing.  A daemon that
// re-executes itself -- the setup wizard's last step -- keeps its process id
// and loses its descriptors: the socket it stored stays in the store, alive,
// and is not handed to the new image.  One that binds again replaces it
// (store); one that does not must not leave it there for nginx to log into.
func forget() {
	if handoverOn() {
		_ = notify("FDSTOREREMOVE=1\nFDNAME="+fdStoreName, -1)
	}
}

// removeSocketFile removes path when it is a socket, and nothing else.
func removeSocketFile(path string) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
}

// store hands conn to the service manager, replacing whatever it held under
// the same name.  The descriptor is passed through SyscallConn: File() or
// Fd() would put the shared socket into blocking mode, and the read deadline
// Close relies on would stop working.
func store(conn *net.UnixConn) error {
	if err := notify("FDSTOREREMOVE=1\nFDNAME="+fdStoreName, -1); err != nil {
		return err
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = notify("FDSTORE=1\nFDNAME="+fdStoreName, int(fd))
	}); err != nil {
		return err
	}
	return serr
}

// successorTakesOver reports whether the binary the next start runs will take
// a kept socket back: this one, still in its place, or another that carries
// the marker.  A binary from before the handover would be handed the socket
// by systemd, ignore it and bind its own beside it -- leaving nginx's workers
// on the kept one, unread.  When it cannot be told, the answer is no: a
// socket not kept costs each worker one line, a socket kept for nobody costs
// them all.
func successorTakesOver() bool {
	exe, err := successorPath()
	if err != nil {
		return false
	}
	next, err := os.Stat(exe)
	if err != nil {
		return false
	}
	if running, err := os.Stat("/proc/self/exe"); err == nil && os.SameFile(running, next) {
		return true
	}
	return fileHas(exe, []byte(HandoverEnv))
}

// fileHas reports whether the file at path contains marker.
func fileHas(path string, marker []byte) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	kept := 0 // bytes carried over from the read before, so a marker across two reads is found
	for {
		n, err := f.Read(buf[kept:])
		if n > 0 {
			have := kept + n
			if bytes.Contains(buf[:have], marker) {
				return true
			}
			kept = len(marker) - 1
			if kept > have {
				kept = have
			}
			copy(buf, buf[have-kept:have])
		}
		if err != nil {
			return false
		}
	}
}

// notify sends state to the service manager (sd_notify), with the
// descriptor fd when it is not -1.  A plain sendmsg on an unconnected socket:
// net's connected datagram conns refuse WriteMsgUnix.  A NOTIFY_SOCKET that
// starts with "@" is an abstract address, which SockaddrUnix maps itself.
func notify(state string, fd int) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return errNoServiceManager
	}
	s, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(s) }()
	var oob []byte
	if fd >= 0 {
		oob = syscall.UnixRights(fd)
	}
	return syscall.Sendmsg(s, []byte(state), oob, &syscall.SockaddrUnix{Name: addr}, 0)
}
