package nginxlog

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// fakeManager stands in for systemd's notification socket: it collects what
// the daemon sends, with the descriptors passed along.
type fakeManager struct{ conn *net.UnixConn }

func newFakeManager(t *testing.T) *fakeManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	t.Setenv("NOTIFY_SOCKET", path)
	return &fakeManager{conn: c}
}

// next returns the next message and the descriptor passed with it (nil when
// none), or "" when nothing comes within a short wait.
func (m *fakeManager) next(t *testing.T) (string, *os.File) {
	t.Helper()
	buf, oob := make([]byte, 512), make([]byte, syscall.CmsgSpace(4*4))
	_ = m.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	n, oobn, _, _, err := m.conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return "", nil
	}
	var f *os.File
	if msgs, err := syscall.ParseSocketControlMessage(oob[:oobn]); err == nil {
		for _, msg := range msgs {
			if fds, err := syscall.ParseUnixRights(&msg); err == nil && len(fds) > 0 {
				f = os.NewFile(uintptr(fds[0]), "stored")
			}
		}
	}
	return string(buf[:n]), f
}

func handoverDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	return d
}

// A unix socket path short enough for sun_path wherever the test runs.
func sockPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nlh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func boundPath(t *testing.T, f *os.File) string {
	t.Helper()
	pc, err := net.FilePacketConn(f)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if a, ok := pc.LocalAddr().(*net.UnixAddr); ok {
		return a.Name
	}
	return ""
}

func totals(t *testing.T, d *db.DB) int {
	t.Helper()
	var n int
	if err := d.QueryRowContext(context.Background(),
		`SELECT COALESCE(SUM(cnt),0) FROM unmask_cookie_minute WHERE kind = 'total'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

const handoverLine = "<190>Oct  1 00:00:00 h nginx: 1759276800.000 site=s kind= fc=0 hp=0 ip=192.0.2.7 ja4=- hpuri=- ua=Mozilla/5.0\n"

// Where the unit asks for it, the daemon hands its socket to the service
// manager -- after dropping whatever was stored before -- and leaves the
// socket file in place when it stops.  The manager's copy keeps the socket
// alive: nginx's connection is not refused while the daemon is gone.
func TestHandsTheSocketToTheServiceManager(t *testing.T) {
	m := newFakeManager(t)
	t.Setenv(HandoverEnv, "1")
	path := sockPath(t, "log.sock")
	r := Start(path, handoverDB(t))

	if msg, f := m.next(t); msg != "FDSTOREREMOVE=1\nFDNAME=nginxlog" || f != nil {
		t.Fatalf("first message = %q (fd %v), want the old socket dropped", msg, f != nil)
	}
	msg, stored := m.next(t)
	if msg != "FDSTORE=1\nFDNAME=nginxlog" || stored == nil {
		t.Fatalf("second message = %q (fd %v), want the socket stored", msg, stored != nil)
	}
	defer stored.Close()
	if got := boundPath(t, stored); got != path {
		t.Fatalf("the stored socket is bound at %q, want %q", got, path)
	}

	nginx, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nginx.Close()
	r.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("the socket file went with the daemon: %v", err)
	}
	if _, err := nginx.Write([]byte(handoverLine)); err != nil {
		t.Errorf("nginx's line was refused while the daemon was down: %v", err)
	}
}

// The next start takes the socket back: the connection nginx made before the
// restart still delivers, and what it logged meanwhile is read and counted.
// Nothing new is stored, and the LISTEN_* variables are not passed on.
func TestTakesTheSocketBackOverARestart(t *testing.T) {
	m := newFakeManager(t)
	t.Setenv(HandoverEnv, "1")
	path := sockPath(t, "log.sock")
	d := handoverDB(t)

	// The socket as the manager holds it after the old process went.
	old, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	keep, err := old.File()
	if err != nil {
		t.Fatal(err)
	}
	defer keep.Close()
	old.Close()
	nginx, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nginx.Close()
	if _, err := nginx.Write([]byte(handoverLine)); err != nil {
		t.Fatalf("a line during the restart: %v", err)
	}

	// Handed back as systemd does: LISTEN_FDS descriptors from listenFDsStart.
	fd, err := syscall.Dup(int(keep.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer func(v int) { listenFDsStart = v }(listenFDsStart)
	listenFDsStart = fd
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", fdStoreName)

	r := Start(path, d)
	if msg, _ := m.next(t); msg != "" {
		t.Errorf("a socket taken back was stored again: %q", msg)
	}
	for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		if v, ok := os.LookupEnv(k); ok {
			t.Errorf("%s=%q is left for whatever this process starts", k, v)
		}
	}
	// The descriptor systemd passed is this process's alone, and gone once
	// the socket has been taken over from it.
	if _, err := fcntlGetFD(fd); err == nil {
		t.Errorf("the passed descriptor %d is still open after the socket was taken back", fd)
	}
	if _, err := nginx.Write([]byte(handoverLine)); err != nil {
		t.Fatalf("the connection from before the restart was refused: %v", err)
	}
	// Nothing is read before the callbacks are in place: the line logged
	// during the restart is still in the socket, and is handled with them.
	time.Sleep(150 * time.Millisecond)
	r.mu.Lock()
	early := len(r.buckets)
	r.mu.Unlock()
	if early != 0 {
		t.Errorf("%d bucket(s) before Receive: a line was read without the callbacks", early)
	}
	var classified int32
	r.SetCrawlerClassifier(func(string) string { atomic.AddInt32(&classified, 1); return "" })
	r.Receive()
	time.Sleep(200 * time.Millisecond)
	r.Close()
	if n := totals(t, d); n != 2 {
		t.Errorf("counted %d lines, want 2 (one logged during the restart, one after)", n)
	}
	// The classifier is asked more than once a line; what matters is that
	// both lines went through it alike.
	if got := atomic.LoadInt32(&classified); got == 0 || got%2 != 0 {
		t.Errorf("the classifier registered before Receive was asked %d times for two lines: one of them went without it", got)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("the socket file went with the daemon: %v", err)
	}
}

// A socket handed back that is no longer the one at the configured path -- the
// path changed, or a stop removed its directory -- is dropped from the store,
// and a socket bound afresh takes its place.
func TestDropsAStaleSocketAndStoresTheNewOne(t *testing.T) {
	m := newFakeManager(t)
	t.Setenv(HandoverEnv, "1")
	oldPath, path := sockPath(t, "old.sock"), sockPath(t, "log.sock")

	old, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: oldPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	keep, err := old.File()
	if err != nil {
		t.Fatal(err)
	}
	defer keep.Close()
	defer old.Close()
	// nginx, still connected to the old socket -- which the manager's copy
	// (keep, here) holds alive.
	nginx, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: oldPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nginx.Close()
	fd, err := syscall.Dup(int(keep.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer func(v int) { listenFDsStart = v }(listenFDsStart)
	listenFDsStart = fd
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", fdStoreName)

	r := Start(path, handoverDB(t))
	defer r.Close()
	// The old socket is dead for its senders at once, whatever still holds a
	// descriptor for it: nginx fails on its next line and connects afresh.
	if _, err := nginx.Write([]byte(handoverLine)); !errors.Is(err, syscall.EPIPE) {
		t.Errorf("a line into the socket let go: err = %v, want EPIPE (shut down)", err)
	}
	if _, err := os.Lstat(oldPath); !os.IsNotExist(err) {
		t.Errorf("the file of the socket let go is still there: %v", err)
	}
	var got []string
	var stored *os.File
	for {
		msg, f := m.next(t)
		if msg == "" {
			break
		}
		got = append(got, strings.ReplaceAll(msg, "\n", " "))
		if f != nil {
			stored = f
		}
	}
	want := []string{"FDSTOREREMOVE=1 FDNAME=nginxlog", "FDSTOREREMOVE=1 FDNAME=nginxlog", "FDSTORE=1 FDNAME=nginxlog"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("messages = %q, want %q", got, want)
	}
	if stored == nil {
		t.Fatal("no socket stored")
	}
	defer stored.Close()
	if p := boundPath(t, stored); p != path {
		t.Errorf("the stored socket is bound at %q, want the configured %q", p, path)
	}
}

// Without the unit's drop-in -- an older systemd, OpenRC, SysV, the container
// -- nothing is stored and the socket file goes with the daemon, as before.
func TestNoHandoverWithoutTheDropIn(t *testing.T) {
	m := newFakeManager(t)
	t.Setenv(HandoverEnv, "")
	path := sockPath(t, "log.sock")
	r := Start(path, handoverDB(t))
	if msg, _ := m.next(t); msg != "" {
		t.Errorf("sent %q to the service manager without the drop-in", msg)
	}
	r.Close()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("the socket file outlived the daemon without the drop-in: %v", err)
	}
}

// otherBinary puts a file of the given content where the daemon's own binary
// would be found at the next start.
func otherBinary(t *testing.T, content []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "unmask")
	if err := os.WriteFile(p, content, 0o755); err != nil {
		t.Fatal(err)
	}
	prev := successorPath
	successorPath = func() (string, error) { return p, nil }
	t.Cleanup(func() { successorPath = prev })
}

// On its way out the daemon keeps the socket only for a binary that will take
// it back.  A version from before the handover, put in this one's place,
// would be handed the socket, ignore it and bind its own -- leaving nginx on
// the kept one, unread.  So that socket is shut down (nginx fails at once and
// connects afresh), taken out of the store, and its file removed, as a daemon
// without the handover always did.
func TestLetsGoOfTheSocketWhenTheSuccessorDoesNotTakeIt(t *testing.T) {
	m := newFakeManager(t)
	t.Setenv(HandoverEnv, "1")
	otherBinary(t, bytes.Repeat([]byte("an unmask from before the handover\n"), 4096))
	path := sockPath(t, "log.sock")
	r := Start(path, handoverDB(t))
	m.next(t) // the remove before the store
	_, stored := m.next(t)
	if stored == nil {
		t.Fatal("the socket was not stored")
	}
	defer stored.Close() // the manager's copy: it keeps the socket alive
	nginx, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nginx.Close()

	r.Close()
	if msg, _ := m.next(t); msg != "FDSTOREREMOVE=1\nFDNAME=nginxlog" {
		t.Errorf("message at close = %q, want the socket taken out of the store", msg)
	}
	if _, err := nginx.Write([]byte(handoverLine)); !errors.Is(err, syscall.EPIPE) {
		t.Errorf("a line after close: err = %v, want EPIPE (the kept socket is shut down)", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("the socket file is left for a successor that binds its own: %v", err)
	}
}

// A newer build in this one's place -- an upgrade -- carries the marker: the
// socket stays for it.
func TestKeepsTheSocketForASuccessorThatCarriesTheMarker(t *testing.T) {
	m := newFakeManager(t)
	t.Setenv(HandoverEnv, "1")
	otherBinary(t, append(bytes.Repeat([]byte{0x7f}, 3<<20), []byte("...os.Getenv(\""+HandoverEnv+"\")...")...))
	path := sockPath(t, "log.sock")
	r := Start(path, handoverDB(t))
	m.next(t)
	_, stored := m.next(t)
	if stored == nil {
		t.Fatal("the socket was not stored")
	}
	defer stored.Close()
	nginx, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nginx.Close()

	r.Close()
	if msg, _ := m.next(t); msg != "" {
		t.Errorf("message at close = %q, want none", msg)
	}
	if _, err := nginx.Write([]byte(handoverLine)); err != nil {
		t.Errorf("a line during the restart was refused: %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("the socket file went: %v", err)
	}
}

// A daemon that starts without a log receiver (no database yet) lets a kept
// socket go rather than leave nginx logging into it.
func TestReleaseLetsAKeptSocketGo(t *testing.T) {
	m := newFakeManager(t)
	path := sockPath(t, "log.sock")
	old, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	keep, err := old.File()
	if err != nil {
		t.Fatal(err)
	}
	defer keep.Close()
	nginx, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nginx.Close()
	fd, err := syscall.Dup(int(keep.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer func(v int) { listenFDsStart = v }(listenFDsStart)
	listenFDsStart = fd
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", fdStoreName)

	Release()
	if msg, _ := m.next(t); msg != "FDSTOREREMOVE=1\nFDNAME=nginxlog" {
		t.Errorf("message = %q, want the socket taken out of the store", msg)
	}
	if _, err := nginx.Write([]byte(handoverLine)); !errors.Is(err, syscall.EPIPE) {
		t.Errorf("a line into the released socket: err = %v, want EPIPE", err)
	}
	// Nothing handed back: nothing said.
	Release()
	if msg, _ := m.next(t); msg != "" {
		t.Errorf("a second release said %q", msg)
	}
}

// Whether a binary takes the socket over is read off its bytes: this one
// (the same file) does, one that cannot be found or read does not, and the
// marker is found wherever it lies -- across two reads too.
func TestSuccessorTakesOver(t *testing.T) {
	if !successorTakesOver() {
		t.Error("the running binary, still in place, is its own successor")
	}
	prev := successorPath
	defer func() { successorPath = prev }()
	// The successor is whatever lies at the path this process was started
	// with -- not the running image under its present name.  The running
	// binary renamed aside and an older one copied into its place is exactly
	// the case to catch: os.Executable follows the rename.
	if got, err := prev(); err != nil || got != os.Args[0] || !filepath.IsAbs(got) {
		t.Errorf("successorPath() = (%q, %v), want the path this process was started with, %q", got, err, os.Args[0])
	}
	args0 := os.Args[0]
	defer func() { os.Args[0] = args0 }()
	older := filepath.Join(t.TempDir(), "unmask")
	if err := os.WriteFile(older, []byte("an unmask from before the handover"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Args[0] = older // what lies at the start path now is another, older file
	if got, _ := prev(); got != older {
		t.Errorf("successorPath() = %q, want the start path %q whatever the running image is called now", got, older)
	}
	if successorTakesOver() {
		t.Error("an older binary at the start path takes the socket over: the running image was mistaken for its successor")
	}
	os.Args[0] = "unmask" // started through $PATH: no path to go by
	if got, err := prev(); err != nil || !filepath.IsAbs(got) {
		t.Errorf("successorPath() with a bare name = (%q, %v), want the running image's path", got, err)
	}
	os.Args[0] = args0
	successorPath = func() (string, error) { return "", errors.New("no path") }
	if successorTakesOver() {
		t.Error("a successor that cannot be found takes nothing over")
	}
	successorPath = func() (string, error) { return filepath.Join(t.TempDir(), "gone"), nil }
	if successorTakesOver() {
		t.Error("a missing binary takes nothing over")
	}

	marker := []byte(HandoverEnv)
	dir := t.TempDir()
	for name, c := range map[string]struct {
		content []byte
		want    bool
	}{
		"empty":            {nil, false},
		"short without":    {[]byte("ELF"), false},
		"short with":       {marker, true},
		"across two reads": {append(append(bytes.Repeat([]byte{'x'}, 1<<20-5), marker...), bytes.Repeat([]byte{'y'}, 100)...), true},
		"at the very end":  {append(bytes.Repeat([]byte{'x'}, 2<<20+17), marker...), true},
		"cut short":        {append(bytes.Repeat([]byte{'x'}, 1<<20-5), marker[:len(marker)-1]...), false},
		"large without":    {bytes.Repeat([]byte("UNMASK_LOG_HANDOVE "), 150000), false},
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, c.content, 0o644); err != nil {
			t.Fatal(err)
		}
		if got := fileHas(p, marker); got != c.want {
			t.Errorf("fileHas(%s) = %v, want %v", name, got, c.want)
		}
	}
}

// The marker and the socket's name in the store are a contract with the
// package's scripts: the drop-in sets the variable, its check before every
// start looks for the marker in the binary and removes the socket from the
// store by its name, and the downgrade hook looks for the marker too.
func TestHandoverMarkerMatchesThePackageScripts(t *testing.T) {
	if HandoverEnv != "UNMASK_LOG_HANDOVER" {
		t.Fatalf("HandoverEnv = %q: binaries already out are recognised by the old name", HandoverEnv)
	}
	for _, c := range []struct{ file, want string }{
		{"postinstall.sh", `echo "Environment=` + HandoverEnv + `=1"`},
		{"postinstall.sh", `grep -q ` + HandoverEnv + ` /usr/sbin/unmask || exec systemd-notify FDSTOREREMOVE=1 FDNAME=` + fdStoreName + `'`},
		{"postremove.sh", `grep -q ` + HandoverEnv + ` /usr/sbin/unmask`},
	} {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "rpm", "scripts", c.file))
		if err != nil {
			t.Skipf("the package scripts are not next to this source tree: %v", err)
		}
		if !bytes.Contains(b, []byte(c.want)) {
			t.Errorf("rpm/scripts/%s no longer has %q", c.file, c.want)
		}
	}
}

// fcntlGetFD reads a descriptor's flags; it fails with EBADF when fd is closed.
func fcntlGetFD(fd int) (int, error) {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(flags), nil
}

// passFD hands fd over the way systemd does -- LISTEN_FDS descriptors from
// listenFDsStart, non-blocking as a stored socket is -- under the given names.
func passFD(t *testing.T, f *os.File, pid int, names string) int {
	t.Helper()
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = syscall.SetNonblock(fd, true)
	var passed syscall.Stat_t
	if err := syscall.Fstat(fd, &passed); err != nil {
		t.Fatal(err)
	}
	prev := listenFDsStart
	listenFDsStart = fd
	t.Cleanup(func() {
		listenFDsStart = prev
		// The code under test closes what it is handed; the number may be
		// another file's by now, and is closed only while it is still ours.
		var now syscall.Stat_t
		if syscall.Fstat(fd, &now) == nil && now.Dev == passed.Dev && now.Ino == passed.Ino {
			_ = syscall.Close(fd)
		}
	})
	t.Setenv("LISTEN_PID", strconv.Itoa(pid))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", names)
	return fd
}

// keptSocket is a socket as the service manager holds it: bound at path, the
// process that bound it gone.  keep is the manager's copy.
func keptSocket(t *testing.T, path string) (keep *os.File) {
	t.Helper()
	old, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	keep, err = old.File()
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	t.Cleanup(func() { keep.Close() })
	return keep
}

// hungUp reports whether the socket behind f shows a hang-up to a poller
// that asks for no event at all -- which is how systemd watches the sockets
// in its store, and what makes it drop one.  Only a socket shut down in both
// directions does.
func hungUp(t *testing.T, f *os.File) bool {
	t.Helper()
	ep, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(ep)
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.EpollCtl(ep, syscall.EPOLL_CTL_ADD, fd, &syscall.EpollEvent{Events: 0, Fd: int32(fd)}); err != nil {
		t.Fatal(err)
	}
	evs := make([]syscall.EpollEvent, 1)
	n, err := syscall.EpollWait(ep, evs, 200)
	return err == nil && n == 1 && evs[0].Events&syscall.EPOLLHUP != 0
}

// The LISTEN_* variables are for the process they name.  Inherited by another
// -- the PID does not match -- they say nothing about its descriptors, which
// are left alone, and nothing is taken or let go.
func TestDescriptorsMeantForAnotherProcessAreLeftAlone(t *testing.T) {
	m := newFakeManager(t)
	path := sockPath(t, "log.sock")
	keep := keptSocket(t, path)
	fd := passFD(t, keep, os.Getpid()+1, fdStoreName)
	if conn := adopt(path); conn != nil {
		conn.Close()
		t.Fatal("took a socket the variables named for another process")
	}
	if _, err := fcntlGetFD(fd); err != nil {
		t.Errorf("a descriptor not ours to touch was closed: %v", err)
	}
	if msg, _ := m.next(t); msg != "" {
		t.Errorf("said %q to the service manager", msg)
	}
	if hungUp(t, keep) {
		t.Error("the socket was shut down")
	}
}

// A descriptor handed over is not for the processes this daemon starts: it is
// marked close-on-exec before anything else.
func TestHandedDescriptorIsCloseOnExec(t *testing.T) {
	newFakeManager(t)
	path := sockPath(t, "log.sock")
	keep := keptSocket(t, path)
	fd := passFD(t, keep, os.Getpid(), fdStoreName)
	f := handedBack(fdStoreName)
	if f == nil {
		t.Fatal("the socket was not handed back")
	}
	defer f.Close()
	if flags, err := fcntlGetFD(fd); err != nil || flags&syscall.FD_CLOEXEC == 0 {
		t.Errorf("descriptor %d: flags=%#x err=%v, want close-on-exec set", fd, flags, err)
	}
}

// A socket kept under a name this version does not use is nobody's to read:
// it is shut down, closed and taken out of the store by that name.
func TestSocketUnderAnotherNameIsLetGo(t *testing.T) {
	m := newFakeManager(t)
	path := sockPath(t, "log.sock")
	keep := keptSocket(t, path)
	nginx, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nginx.Close()
	fd := passFD(t, keep, os.Getpid(), "accesslog")
	if f := handedBack(fdStoreName); f != nil {
		f.Close()
		t.Fatal("took a socket kept under another name")
	}
	if msg, _ := m.next(t); msg != "FDSTOREREMOVE=1\nFDNAME=accesslog" {
		t.Errorf("message = %q, want that name taken out of the store", msg)
	}
	if _, err := fcntlGetFD(fd); err == nil {
		t.Errorf("descriptor %d is still open", fd)
	}
	if _, err := nginx.Write([]byte(handoverLine)); !errors.Is(err, syscall.EPIPE) {
		t.Errorf("a line into it: err = %v, want EPIPE", err)
	}
}

// The directory the kept socket was bound in went with a stop (or its file
// was removed): the path leads nowhere, so the socket is not taken -- it is
// shut down in both directions, which is what makes systemd drop its copy,
// and a new one is bound.
func TestAKeptSocketWhoseFileIsGoneIsNotTaken(t *testing.T) {
	m := newFakeManager(t)
	t.Setenv(HandoverEnv, "1")
	path := sockPath(t, "log.sock")
	keep := keptSocket(t, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	passFD(t, keep, os.Getpid(), fdStoreName)

	r := Start(path, handoverDB(t))
	defer r.Close()
	if !hungUp(t, keep) {
		t.Error("the socket not taken was not shut down in both directions; systemd would keep it")
	}
	var stored *os.File
	for {
		msg, f := m.next(t)
		if msg == "" {
			break
		}
		if f != nil {
			stored = f
		}
	}
	if stored == nil {
		t.Fatal("no new socket was stored")
	}
	defer stored.Close()
	if hungUp(t, stored) {
		t.Error("the new socket is shut down")
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("no socket at the path after the start: %v", err)
	}
}

// A daemon without a log receiver (nginx_log off) lets a kept socket go as it
// starts, and leaves no file behind.
func TestStartWithoutASocketReleasesAKeptOne(t *testing.T) {
	m := newFakeManager(t)
	path := sockPath(t, "log.sock")
	keep := keptSocket(t, path)
	passFD(t, keep, os.Getpid(), fdStoreName)
	r := Start("", handoverDB(t))
	defer r.Close()
	if msg, _ := m.next(t); msg != "FDSTOREREMOVE=1\nFDNAME=nginxlog" {
		t.Errorf("message = %q, want the socket taken out of the store", msg)
	}
	if !hungUp(t, keep) {
		t.Error("the kept socket was not shut down")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("the socket file is left behind: %v", err)
	}
}

// A daemon that re-executes itself (the setup wizard's last step) keeps its
// process id and loses its descriptors: the socket it stored is still in the
// store, and is not handed to the new image.  Starting without a receiver, or
// failing to bind one, it takes its name out of the store -- a socket alive
// there with nobody reading is the one thing that must not be.  Without the
// drop-in nothing was ever stored, and nothing is said.
func TestForgetsAStoredSocketItWasNotHandedBack(t *testing.T) {
	m := newFakeManager(t)
	for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		t.Setenv(k, "")
	}
	const remove = "FDSTOREREMOVE=1\nFDNAME=nginxlog"

	t.Setenv(HandoverEnv, "1")
	Release()
	if msg, f := m.next(t); msg != remove || f != nil {
		t.Errorf("no receiver, nothing handed back: said %q, want the name taken out of the store", msg)
	}

	// No receiver configured.
	r := Start("", handoverDB(t))
	if msg, _ := m.next(t); msg != remove {
		t.Errorf("started without a socket path: said %q, want the name taken out of the store", msg)
	}
	r.Close()

	// A bind that fails: a path longer than a socket address holds.
	long := filepath.Join(t.TempDir(), strings.Repeat("x", 120))
	r = Start(long, handoverDB(t))
	if msg, _ := m.next(t); msg != remove {
		t.Errorf("bind failed: said %q, want the name taken out of the store", msg)
	}
	if msg, _ := m.next(t); msg != "" {
		t.Errorf("bind failed: also said %q, want nothing stored", msg)
	}
	r.Close()

	t.Setenv(HandoverEnv, "")
	Release()
	r = Start(long, handoverDB(t))
	r.Close()
	if msg, _ := m.next(t); msg != "" {
		t.Errorf("without the drop-in: said %q, want nothing", msg)
	}
}

// A daemon that stops before its callbacks were registered -- it failed to
// start, or was stopped in its first moments -- has read nothing, and stops
// all the same: the receive loop waits for Receive or for the stop.
func TestStopsBeforeItWasLetToReceive(t *testing.T) {
	path := sockPath(t, "log.sock")
	d := handoverDB(t)
	r := Start(path, d)
	nginx, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nginx.Close()
	if _, err := nginx.Write([]byte(handoverLine)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return for a reader that was never let to receive")
	}
	if n := totals(t, d); n != 0 {
		t.Errorf("%d lines counted by a reader that was never let to receive", n)
	}
	r.Receive() // after the stop: nothing to wake, nothing to break
}

// Another process that binds the same path -- a second daemon started on the
// same config -- takes the name away from the kept socket, and one that dies
// without removing its file leaves a name that leads nowhere: new connections
// are refused while the kept socket lives on behind it.  Taking that socket
// back would keep it so over every restart; it is let go, and the path bound
// afresh, as a restart always did.
func TestAKeptSocketWhoseNameLeadsNowhereIsLetGo(t *testing.T) {
	m := newFakeManager(t)
	t.Setenv(HandoverEnv, "1")
	path := sockPath(t, "log.sock")
	keep := keptSocket(t, path)
	nginx, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer nginx.Close()
	// The other daemon: it removes the file, binds the path, and is killed.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	other, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(other, &syscall.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Close(other) // the file stays, bound to nothing
	if reachable(path) {
		t.Fatal("a path whose socket is gone counted as reachable")
	}

	passFD(t, keep, os.Getpid(), fdStoreName)
	d := handoverDB(t)
	r := Start(path, d)
	if msg, _ := m.next(t); msg != "FDSTOREREMOVE=1\nFDNAME=nginxlog" {
		t.Errorf("first message = %q, want the kept socket taken out of the store", msg)
	}
	if !hungUp(t, keep) {
		t.Error("the kept socket was not shut down")
	}
	m.next(t) // the remove before the store
	msg, stored := m.next(t)
	if msg != "FDSTORE=1\nFDNAME=nginxlog" || stored == nil {
		t.Fatalf("message = %q (fd %v), want a socket bound afresh stored", msg, stored != nil)
	}
	stored.Close()
	if _, err := nginx.Write([]byte(handoverLine)); !errors.Is(err, syscall.EPIPE) {
		t.Errorf("a line on the old connection: err = %v, want EPIPE (nginx then connects afresh)", err)
	}
	fresh, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("a new connection to the path is refused: %v", err)
	}
	defer fresh.Close()
	r.Receive()
	if _, err := fresh.Write([]byte(handoverLine)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	r.Close()
	if n := totals(t, d); n != 1 {
		t.Errorf("counted %d lines, want the 1 sent to the path after the start", n)
	}
}

// reachable: a live socket at the path answers, a dead file and a missing
// one do not.
func TestReachable(t *testing.T) {
	path := sockPath(t, "log.sock")
	if reachable(path) {
		t.Error("a path with no file counted as reachable")
	}
	keep := keptSocket(t, path)
	if !reachable(path) {
		t.Error("the kept socket's own path counted as unreachable")
	}
	if hungUp(t, keep) {
		t.Error("asking shut the socket down")
	}
}
