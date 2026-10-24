package banfile

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The data directory as the package shipped it (0750) stops a worker that
// is another user at the directory; 0751 lets it through to a 0644 file;
// a 0640 file stops it at the file.  Checked for a uid that owns nothing
// here and sits in no group of these files, like nginx's worker.
func TestAccessAsOtherUser(t *testing.T) {
	// Not t.TempDir(): its parent is 0700, which would stop the stranger
	// before the directories under test.
	root, err := os.MkdirTemp("", "banfile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	data := filepath.Join(root, "unmask")
	nginx := filepath.Join(data, "nginx")
	if err := os.MkdirAll(nginx, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(nginx, "banned.txt")
	if err := os.WriteFile(file, []byte("# list\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil { // MkdirTemp is 0700
		t.Fatal(err)
	}
	const stranger = 65534
	var noGroups []uint32

	if err := os.Chmod(data, 0o750); err != nil {
		t.Fatal(err)
	}
	blocker, need, err := AccessAs(file, stranger, noGroups)
	if err != nil {
		t.Fatal(err)
	}
	if blocker != data || need != "x" {
		t.Errorf("0750 data dir: blocker %q need %q, want the data dir and x", blocker, need)
	}

	if err := os.Chmod(data, 0o751); err != nil {
		t.Fatal(err)
	}
	blocker, need, err = AccessAs(file, stranger, noGroups)
	if err != nil {
		t.Fatal(err)
	}
	if blocker != "" || need != "" {
		t.Errorf("0751 data dir, 0644 file: blocker %q need %q, want none", blocker, need)
	}

	if err := os.Chmod(file, 0o640); err != nil {
		t.Fatal(err)
	}
	blocker, need, err = AccessAs(file, stranger, noGroups)
	if err != nil {
		t.Fatal(err)
	}
	if blocker != file || need != "r" {
		t.Errorf("0640 file: blocker %q need %q, want the file and r", blocker, need)
	}

	// The owner reads its own 0640 file; root reads anything.
	blocker, _, err = AccessAs(file, uint32(os.Getuid()), []uint32{uint32(os.Getgid())})
	if err != nil || blocker != "" {
		t.Errorf("owner: blocker %q err %v, want none", blocker, err)
	}
	blocker, _, err = AccessAs(file, 0, nil)
	if err != nil || blocker != "" {
		t.Errorf("root: blocker %q err %v, want none", blocker, err)
	}

	// An absent file is an error, not a verdict.
	if _, _, err := AccessAs(filepath.Join(nginx, "none.txt"), stranger, noGroups); err == nil {
		t.Error("an absent file must be an error")
	}
}

func aclBlob(entries ...aclEntry) []byte {
	b := make([]byte, 4, 4+8*len(entries))
	binary.LittleEndian.PutUint32(b, aclVersion)
	for _, e := range entries {
		var row [8]byte
		binary.LittleEndian.PutUint16(row[0:], e.tag)
		binary.LittleEndian.PutUint16(row[2:], e.perm)
		binary.LittleEndian.PutUint32(row[4:], e.id)
		b = append(b, row[:]...)
	}
	return b
}

// An ACL that grants nginx pass-through alone (setfacl -m u:nginx:x) on a
// 0750 directory -- the operator's own way around -- is read as the kernel
// reads it: the named user passes, another user does not, the mask caps a
// named entry, the owner keeps its own bits.
func TestACL(t *testing.T) {
	const owner, ownerGroup, nginx, other = 1000, 1000, 996, 65534
	acl := parseACL(aclBlob(
		aclEntry{tag: aclUserObj, perm: 7},
		aclEntry{tag: aclUser, perm: 1, id: nginx},
		aclEntry{tag: aclGroupObj, perm: 5},
		aclEntry{tag: aclMask, perm: 5},
		aclEntry{tag: aclOther, perm: 0},
	))
	if len(acl) != 5 {
		t.Fatalf("parsed %d entries, want 5", len(acl))
	}
	if !aclAllows(acl, owner, ownerGroup, nginx, nil, permX) {
		t.Error("the named user must pass through")
	}
	if aclAllows(acl, owner, ownerGroup, nginx, nil, permR) {
		t.Error("the named user was given x alone, not r")
	}
	if aclAllows(acl, owner, ownerGroup, other, nil, permX) {
		t.Error("another user has no entry and other grants nothing")
	}
	if !aclAllows(acl, owner, ownerGroup, owner, nil, permR) {
		t.Error("the owner keeps its own bits")
	}
	if !aclAllows(acl, owner, ownerGroup, other, []uint32{ownerGroup}, permX) {
		t.Error("the owning group passes through by its entry")
	}
	// A mask of --- caps the named entry.
	capped := parseACL(aclBlob(
		aclEntry{tag: aclUserObj, perm: 7},
		aclEntry{tag: aclUser, perm: 1, id: nginx},
		aclEntry{tag: aclGroupObj, perm: 0},
		aclEntry{tag: aclMask, perm: 0},
		aclEntry{tag: aclOther, perm: 0},
	))
	if aclAllows(capped, owner, ownerGroup, nginx, nil, permX) {
		t.Error("the mask must cap the named user's entry")
	}
	if parseACL([]byte{1, 2, 3}) != nil || parseACL(aclBlob()[:3]) != nil {
		t.Error("a short or foreign blob parses to nothing")
	}
}

// The worker user comes from nginx.conf's `user` directive, a commented
// one not counting; a conf without one falls back.
func TestWorkerUserFromConf(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("# user nobody;\nworker_processes auto;\nuser  www-data www-data;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	name, source, err := WorkerUser(conf)
	if err != nil || name != "www-data" || source != "nginx.conf" {
		t.Errorf("got %q %q %v, want www-data from nginx.conf", name, source, err)
	}
	if err := os.WriteFile(conf, []byte("worker_processes auto;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	name, source, err = WorkerUser(conf)
	if err != nil {
		t.Fatalf("a conf without the directive: %v", err)
	}
	if source == "nginx.conf" || name == "" {
		t.Errorf("got %q from %q, want the binary's default or nobody", name, source)
	}
}

func TestDescribeAndFix(t *testing.T) {
	v := Verdict{User: "nginx", Source: "nginx.conf", Blocker: "/var/lib/unmask", Need: "x"}
	if d := Describe(v); !strings.Contains(d, "cannot pass through /var/lib/unmask") || !strings.Contains(d, "no ban") {
		t.Errorf("describe: %s", d)
	}
	if fix := FixCommands(v); len(fix) != 1 || fix[0] != "sudo chmod o+x /var/lib/unmask" {
		t.Errorf("fix: %v", fix)
	}
	v.Blocker, v.Need = "/var/lib/unmask/nginx/banned.txt", "r"
	if fix := FixCommands(v); len(fix) != 1 || fix[0] != "sudo chmod o+r /var/lib/unmask/nginx/banned.txt" {
		t.Errorf("fix r: %v", fix)
	}
	if fix := FixCommands(Verdict{OK: true}); fix != nil {
		t.Errorf("an OK verdict needs no fix: %v", fix)
	}
}
