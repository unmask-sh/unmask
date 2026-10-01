// Package selabel gives the sockets the web server talks to an SELinux label
// the web server is allowed to reach.
//
// A socket carries the label of the process that created it.  The daemon runs
// as unconfined_service_t (a service started by systemd from an ordinary
// binary), and the targeted policy lets the web server's domain, httpd_t, send
// to sockets of its own type and of a few named services -- not to those of an
// unconfined service.  So with SELinux enforcing, every access-log line nginx
// sends to the daemon's log socket is refused ("connect() failed (13:
// Permission denied) while logging to syslog"), whatever the label of the
// socket file: the file label covers the write to the path, a second check
// covers the socket behind it.
//
// Rather than widen the policy for the web server, the daemon labels the one
// socket: it sets the calling thread's socket-creation context to its own
// context with the type swapped for the web server's, creates the socket, and
// lets the thread end.  Stock policy then lets nginx send to it.
//
// The socket's file is labelled in the same step (the file-creation context),
// with the type the policy gives the web server's own runtime files: a file
// in /run/unmask is var_run_t by default, which httpd_t may not write.  The
// package also arranges that from outside -- a file-context rule, or a
// relabel after each start -- but a file labelled as it is made needs
// neither, and is right from the first moment.
//
// Without SELinux nothing changes.  Where the policy does not allow the
// labels -- a daemon confined to a domain of its own, a container on an
// SELinux host -- the socket is made again without them, as it always was:
// the labels are an extra, never a condition.
package selabel

import (
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const (
	// WebServerType is the SELinux type nginx and Apache run as in the
	// reference policy and Red Hat's.
	WebServerType = "httpd_t"
	// webServerFileType is the type of the web server's runtime files there.
	webServerFileType = "httpd_var_run_t"
)

// ForWebServer runs create -- which makes the socket the web server is to
// reach -- with the creation contexts set for it, and reports whether the
// socket got the web server's label.  Should create fail with a label set,
// it is run once more without: a policy may let the contexts be set and then
// refuse the socket or its file.  create must therefore be able to run twice;
// the error returned is the last run's.
//
// The contexts belong to the thread, so create runs on a thread of its own
// that is not handed back: a thread returned to the scheduler with a context
// still set would label whatever it made next.
func ForWebServer(create func() error) (labelled bool, err error) {
	type result struct {
		labelled bool
		err      error
	}
	done := make(chan result, 1)
	go func() {
		// Locked and never unlocked: the thread ends with this goroutine.
		runtime.LockOSThread()
		attr := threadAttrDir()
		sock, file := setContexts(attr)
		err := create()
		// A zero-length write puts the default back.
		if sock {
			_ = writeAttr(attr+"/sockcreate", nil)
		}
		if file {
			_ = writeAttr(attr+"/fscreate", nil)
		}
		if err != nil && (sock || file) {
			// Said, so that a socket left without the label has its
			// reason on record.
			log.Printf("selabel: creating the socket under the web server's SELinux label failed (%v); creating it without", err)
			sock = false
			err = create()
		}
		done <- result{sock, err}
	}()
	r := <-done
	return r.labelled, r.err
}

// setContexts is setCreateContexts; a variable so that a test can stand in
// for a kernel that takes the contexts.
var setContexts = setCreateContexts

// threadAttrDir is the calling thread's /proc attribute directory.
// /proc/thread-self is from Linux 3.17; before it, the thread is named.
func threadAttrDir() string {
	if _, err := os.Stat("/proc/thread-self/attr"); err == nil {
		return "/proc/thread-self/attr"
	}
	return "/proc/self/task/" + strconv.Itoa(syscall.Gettid()) + "/attr"
}

// setCreateContexts sets the thread's socket- and file-creation contexts for
// the web server, and reports which were set: neither when there is no
// SELinux context to start from, and not the one the kernel refuses -- each
// on its own account, as one may be allowed without the other.
func setCreateContexts(attr string) (sock, file bool) {
	cur, err := os.ReadFile(attr + "/current")
	if err != nil {
		return false, false
	}
	sockCtx, fileCtx, ok := webServerContexts(strings.TrimRight(string(cur), "\x00\n"))
	if !ok {
		return false, false
	}
	sock = writeAttr(attr+"/sockcreate", []byte(sockCtx)) == nil
	file = writeAttr(attr+"/fscreate", []byte(fileCtx)) == nil
	return sock, file
}

// webServerContexts derives, from this process's SELinux context --
// user:role:type[:range] -- the context for a socket the web server may reach
// (the same with the web server's type) and for that socket's file (an object
// of the web server's runtime-file type, under the same user and at the low
// end of the range: a file has one level, and one above the web server's
// would shut it out).  ok is false for anything that is not an SELinux
// context: the same files hold an AppArmor profile name where AppArmor is the
// module.  It is false too for a container's domain, where there is nothing to
// label for.
func webServerContexts(cur string) (sock, file string, ok bool) {
	f := strings.SplitN(cur, ":", 4) // the range may hold colons of its own
	if len(f) < 3 || f[0] == "" || f[1] == "" || f[2] == "" {
		return "", "", false
	}
	// In a container the web server is next to the daemon, in the same
	// domain, and reaches the socket as it is; the policy lets a container
	// set neither context, and each try would be a denial in the host's
	// audit log.
	if strings.HasPrefix(f[2], "container_") {
		return "", "", false
	}
	sock = f[0] + ":" + f[1] + ":" + WebServerType
	file = f[0] + ":object_r:" + webServerFileType
	if len(f) == 4 {
		sock += ":" + f[3]
		low, _, _ := strings.Cut(f[3], "-")
		file += ":" + low
	}
	return sock, file, true
}

// writeAttr writes b to a /proc attribute file in one write, which is how the
// kernel wants it; an empty b is written too (os.File.Write would skip it).
func writeAttr(path string, b []byte) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	_, err = syscall.Write(fd, b)
	return err
}
