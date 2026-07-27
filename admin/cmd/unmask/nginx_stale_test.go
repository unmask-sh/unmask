package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeProc builds a /proc-shaped fixture tree with one nginx master and points
// procRoot at it for the duration of the test.
func fakeProc(t *testing.T, pid, cmdline, maps string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Real /proc separates argv with NUL bytes.
	if err := os.WriteFile(filepath.Join(dir, "cmdline"),
		[]byte(strings.ReplaceAll(cmdline, " ", "\x00")+"\x00"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "maps"), []byte(maps), 0o644); err != nil {
		t.Fatalf("write maps: %v", err)
	}
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

// The exact shape captured from the tool1-sg incident (2026-07-27): a
// sssd-client upgrade replaced libnss_sss.so.2 under an nginx that was only
// ever reloaded afterwards, and its workers segfaulted for two days.  The
// benign deleted mappings a healthy nginx always carries sit right next to the
// real signal here, which is the whole reason the filter is an allowlist.
const sgIncidentMaps = `7f8536492000-7f8536e92000 rw-s 00000000 00:01 223815                     /dev/zero (deleted)
7f8538a29000-7f8538b9e000 r-xp 00029000 08:02 34315198                   /usr/lib64/libc.so.6
7f8538c0e000-7f8538c10000 r--p 00000000 08:02 33692932                   /usr/lib64/libnss_sss.so.2 (deleted)
7f8538c10000-7f8538c18000 r-xp 00002000 08:02 33692932                   /usr/lib64/libnss_sss.so.2 (deleted)
7f8538c18000-7f8538c1a000 r--p 0000a000 08:02 33692932                   /usr/lib64/libnss_sss.so.2 (deleted)
7f8538c1a000-7f8538c1b000 r--p 0000b000 08:02 33692932                   /usr/lib64/libnss_sss.so.2 (deleted)
7f8538c1b000-7f8538c1c000 rw-p 0000c000 08:02 33692932                   /usr/lib64/libnss_sss.so.2 (deleted)
7f8538c2a000-7f8538c2b000 rw-s 00000000 00:11 319529269                  /[aio] (deleted)
7f8538c2d000-7f8538c30000 r--p 00000000 08:02 33688340                   /usr/lib64/libz.so.1.2.11
7f8538f67000-7f8538f68000 rw-s 00000000 00:01 223816                     /dev/zero (deleted)
`

func TestStaleNginxLibsDetectsReplacedLibrary(t *testing.T) {
	fakeProc(t, "438467", "nginx: master process /usr/sbin/nginx", sgIncidentMaps)

	paths, checked := staleNginxLibs()
	if !checked {
		t.Fatal("checked=false with a readable maps file")
	}
	// Five mapping segments of one library must collapse to one finding.
	if len(paths) != 1 || paths[0] != "/usr/lib64/libnss_sss.so.2" {
		t.Fatalf("want [/usr/lib64/libnss_sss.so.2], got %v", paths)
	}
}

// /dev/zero (shared-memory zones) and /[aio] (the AIO ring) are deleted in
// every healthy nginx.  Warning on those would fire on every install and burn
// the check's credibility, so they must never be reported.
func TestStaleNginxLibsIgnoresBenignDeletedMappings(t *testing.T) {
	benign := `7f8536492000-7f8536e92000 rw-s 00000000 00:01 223815                     /dev/zero (deleted)
7f8538c2a000-7f8538c2b000 rw-s 00000000 00:11 319529269                  /[aio] (deleted)
7f0000000000-7f0000001000 rw-s 00000000 00:01 111111                     /memfd:pulseaudio (deleted)
7f0000002000-7f0000003000 rw-s 00000000 00:05 222222                     /SYSV00000000 (deleted)
7f8538a29000-7f8538b9e000 r-xp 00029000 08:02 34315198                   /usr/lib64/libc.so.6
`
	fakeProc(t, "1234", "nginx: master process /usr/sbin/nginx", benign)

	paths, checked := staleNginxLibs()
	if !checked {
		t.Fatal("checked=false with a readable maps file")
	}
	if len(paths) != 0 {
		t.Fatalf("benign deleted mappings must not be reported, got %v", paths)
	}
}

// The other trap the check covers: unmask's own plugin package places a new
// .so while nginx runs, and the nginx binary itself can be replaced by a host
// nginx upgrade.  Both need a restart, not a reload.
func TestStaleNginxLibsDetectsPluginAndBinary(t *testing.T) {
	maps := `55a000000000-55a000001000 r-xp 00000000 08:02 1                          /usr/sbin/nginx (deleted)
7f8538c10000-7f8538c18000 r-xp 00002000 08:02 2                          /usr/lib64/nginx/modules/ngx_http_unmask_module.so (deleted)
7f8538c20000-7f8538c28000 r-xp 00002000 08:02 3                          /usr/lib64/nginx/modules/ngx_http_lua_module.so (deleted)
7f8538c30000-7f8538c38000 r-xp 00002000 08:02 4                          /usr/lib64/libssl.so.3 (deleted)
`
	fakeProc(t, "999", "nginx: master process /usr/sbin/nginx", maps)

	paths, checked := staleNginxLibs()
	if !checked {
		t.Fatal("checked=false with a readable maps file")
	}
	if len(paths) != 4 {
		t.Fatalf("want 4 findings, got %d: %v", len(paths), paths)
	}
	// Sorted output keeps the doctor message stable across runs.
	want := []string{
		"/usr/lib64/libssl.so.3",
		"/usr/lib64/nginx/modules/ngx_http_lua_module.so",
		"/usr/lib64/nginx/modules/ngx_http_unmask_module.so",
		"/usr/sbin/nginx",
	}
	for i, w := range want {
		if paths[i] != w {
			t.Errorf("paths[%d] = %q, want %q", i, paths[i], w)
		}
	}
}

// An unreadable / absent maps file proves nothing -- callers must be able to
// tell "clean" from "could not look", so a non-root doctor stays silent
// instead of declaring the install healthy.
func TestStaleNginxLibsUncheckedWhenNoNginx(t *testing.T) {
	fakeProc(t, "555", "/usr/bin/postgres -D /var/lib/pgsql", "")

	if paths, checked := staleNginxLibs(); checked || len(paths) != 0 {
		t.Fatalf("want (nil,false) when no nginx master is present, got (%v,%v)", paths, checked)
	}
}

// contentFixture builds a fake /proc where one deleted .so mapping can be
// compared against a real file: <lib> is what sits on disk now, and the
// map_files entry is what the process still executes.  Returns the on-disk path
// so the caller can assert on it.
func contentFixture(t *testing.T, running, onDisk string) string {
	t.Helper()
	dir := t.TempDir()
	lib := filepath.Join(dir, "libexample.so.1")
	if err := os.WriteFile(lib, []byte(onDisk), 0o644); err != nil {
		t.Fatalf("write lib: %v", err)
	}
	const addr = "7f8538c10000-7f8538c18000"
	root := t.TempDir()
	proc := filepath.Join(root, "4242")
	if err := os.MkdirAll(filepath.Join(proc, "map_files"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(proc, "map_files", addr), []byte(running), 0o644); err != nil {
		t.Fatalf("write map_files: %v", err)
	}
	if err := os.WriteFile(filepath.Join(proc, "cmdline"),
		[]byte("nginx:\x00master\x00process\x00"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	maps := addr + " r-xp 00002000 08:02 33692932   " + lib + " (deleted)\n"
	if err := os.WriteFile(filepath.Join(proc, "maps"), []byte(maps), 0o644); err != nil {
		t.Fatalf("write maps: %v", err)
	}
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
	return lib
}

// Replacing a file with byte-identical content (a reinstall of the same build)
// leaves the same deleted mapping, but nothing is actually out of date.  On the
// fleet this was 4 of 7 hosts, so reporting it would light a permanent warning
// on healthy installs.
func TestStaleNginxLibsIgnoresIdenticalReplacement(t *testing.T) {
	contentFixture(t, "same-bytes", "same-bytes")

	paths, checked := staleNginxLibs()
	if !checked {
		t.Fatal("checked=false with a readable maps file")
	}
	if len(paths) != 0 {
		t.Fatalf("identical replacement must not be reported, got %v", paths)
	}
}

// The case that matters: the file on disk really did change, so the running
// nginx is executing code that no longer exists anywhere but its own memory.
func TestStaleNginxLibsReportsChangedContent(t *testing.T) {
	lib := contentFixture(t, "old-build", "new-build")

	paths, checked := staleNginxLibs()
	if !checked {
		t.Fatal("checked=false with a readable maps file")
	}
	if len(paths) != 1 || paths[0] != lib {
		t.Fatalf("want [%s], got %v", lib, paths)
	}
}

// When the comparison cannot be made (map_files needs CAP_SYS_ADMIN, or the
// path is gone) the finding is KEPT: an unverifiable difference must not be
// silently dismissed, and the fix is a restart either way.  The incident
// fixture exercises this -- its paths do not exist on the test machine.
func TestStaleNginxLibsKeepsUnverifiableFindings(t *testing.T) {
	fakeProc(t, "438467", "nginx: master process /usr/sbin/nginx", sgIncidentMaps)

	paths, checked := staleNginxLibs()
	if !checked || len(paths) != 1 {
		t.Fatalf("unverifiable finding must be kept, got (%v,%v)", paths, checked)
	}
}

func TestStaleNginxLibsListTruncates(t *testing.T) {
	got := staleNginxLibsList([]string{
		"/usr/lib64/liba.so.1", "/usr/lib64/libb.so.2",
		"/usr/lib64/libc.so.3", "/usr/lib64/libd.so.4", "/usr/lib64/libe.so.5",
	})
	const want = "liba.so.1, libb.so.2, libc.so.3, +2 more"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The doctor check is an alarm: silent when clean, and it must name the fix
// (restart) unambiguously when it fires.
func TestCheckNginxStaleLibsWarnsOnlyWhenStale(t *testing.T) {
	fakeProc(t, "1234", "nginx: master process /usr/sbin/nginx",
		"7f8536492000-7f8536e92000 rw-s 00000000 00:01 223815    /dev/zero (deleted)\n")
	fired := false
	checkNginxStaleLibs(func(string, string) { fired = true })
	if fired {
		t.Fatal("check must stay silent when only benign mappings are deleted")
	}

	fakeProc(t, "438467", "nginx: master process /usr/sbin/nginx", sgIncidentMaps)
	var title, msg string
	checkNginxStaleLibs(func(t2, m string) { title, msg = t2, m })
	if title == "" {
		t.Fatal("check did not fire on the sg incident fixture")
	}
	if !strings.Contains(msg, "libnss_sss.so.2") {
		t.Errorf("message should name the replaced file, got: %s", msg)
	}
	if !strings.Contains(msg, "restart nginx") {
		t.Errorf("message must point at a restart, got: %s", msg)
	}
}
