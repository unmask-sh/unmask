package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// entrypointConfig runs docker/entrypoint.sh the way the image does on its
// first start (entrypointRun) and returns the config.yml it wrote as the
// daemon loads it.
func entrypointConfig(t *testing.T, env ...string) (settings.Settings, error) {
	t.Helper()
	return settings.Load(filepath.Join(entrypointRun(t, nil, env...), "etc", "unmask", "config.yml"))
}

// entrypointRun runs docker/entrypoint.sh the way the image does on its
// first start -- no config.yml yet -- under a throwaway root (its absolute
// paths pointed into a temporary directory, `unmask` and `id` stood in for,
// and whatever stubs names beside them), and returns that root.
func entrypointRun(t *testing.T, stubs map[string]string, env ...string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "docker", "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, d := range []string{"etc/unmask", "var/lib/unmask", "run/unmask", "bin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script := strings.NewReplacer(
		"/usr/local/bin/unmask", filepath.Join(root, "bin", "unmask"),
		"/etc/unmask", filepath.Join(root, "etc", "unmask"),
		"/var/lib/unmask", filepath.Join(root, "var", "lib", "unmask"),
		"/run/unmask", filepath.Join(root, "run", "unmask"),
	).Replace(string(src))
	path := filepath.Join(root, "entrypoint.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// The daemon the script execs at its end, and an `id` that is not root
	// (so the chown of the volumes is skipped).
	all := map[string]string{"unmask": "#!/bin/sh\nexit 0\n", "id": "#!/bin/sh\necho 1000\n"}
	for name, body := range stubs {
		all[name] = body
	}
	for name, body := range all {
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", path, "version")
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + ":" + os.Getenv("PATH")}, env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("entrypoint: %v\n%s", err, out)
	}
	return root
}

// The config.yml the first start writes holds bv_secret, captcha_secret_base
// and admin_secret, and a bind mount puts it on the host's file system.  It
// was written under the default umask and made private by a chmod at the end
// of the block: readable by every user of the host in between, and for good
// if the script stopped there.  It is private from its first byte -- shown
// here by taking the chmod away.
func TestDockerEntrypointWritesConfigPrivate(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	root := entrypointRun(t, map[string]string{"chmod": "#!/bin/sh\nexit 0\n"}, "UNMASK_GATEWAY=1", "UNMASK_SERVER_NAME=shop.example.com")
	cfg := filepath.Join(root, "etc", "unmask", "config.yml")
	st, err := os.Stat(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Errorf("config.yml was created %04o, want 0600 without the chmod's help", mode)
	}
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "admin_secret:") || !strings.Contains(string(b), "gateway:") {
		t.Errorf("the file is not the whole config.yml (the gateway section is appended after the secrets):\n%s", b)
	}
	// The umask is the script's again afterwards: what the daemon it execs
	// creates is not made 0600 by a leftover of this block.
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "docker", "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `umask "$cfg_umask"`) {
		t.Error("the entrypoint does not put the umask back after writing config.yml")
	}
}

// The container's first start writes config.yml from its environment.  The
// values went in bare, and YAML read them: a wildcard host name is an alias,
// a bracketed IPv6 address a list.  The daemon then refused the file the
// script had just written and the container restarted in a loop.  Each value
// is written as a quoted string and arrives as it was given.
func TestDockerEntrypointQuotesWhatTheEnvironmentGives(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	s, err := entrypointConfig(t,
		"UNMASK_GATEWAY=1",
		"UNMASK_SERVER_NAME=*.example.com shop.example.com",
		"UNMASK_UPSTREAM=http://[2001:db8::10]:8080",
		"UNMASK_DAEMON_ADDR=[::1]:9477",
		"UNMASK_ACME_EMAIL=ops@example.com",
		`UNMASK_ACME_DIRECTORY=https://acme.example.com/dir?a="b": c\d`,
	)
	if err != nil {
		t.Fatalf("the daemon does not load the config.yml the entrypoint wrote: %v", err)
	}
	if got := s.Gateway.Hostnames.Names; got != "*.example.com shop.example.com" {
		t.Errorf("gateway.hostnames.names = %q", got)
	}
	if got := s.Gateway.Upstream; got != "http://[2001:db8::10]:8080" {
		t.Errorf("gateway.upstream = %q", got)
	}
	if got := s.Nginx.UpstreamAddr; got != "[::1]:9477" {
		t.Errorf("nginx.upstream_addr = %q", got)
	}
	if got := s.Gateway.ACMEEmail; got != "ops@example.com" {
		t.Errorf("gateway.acme_email = %q", got)
	}
	if got := s.Gateway.ACMEDirectory; got != `https://acme.example.com/dir?a="b": c\d` {
		t.Errorf("gateway.acme_directory = %q", got)
	}
	if len(s.Gateway.Certificates) != 1 || s.Gateway.Certificates[0].Domains != "*.example.com shop.example.com" {
		t.Errorf("gateway.certificates = %+v", s.Gateway.Certificates)
	}

	// With nothing given: the defaults, as before.
	s, err = entrypointConfig(t)
	if err != nil {
		t.Fatalf("the plain first start: %v", err)
	}
	if got := s.Nginx.UpstreamAddr; got != "127.0.0.1:9477" {
		t.Errorf("default nginx.upstream_addr = %q", got)
	}
	if s.Secret.BVSecret == "" || s.Secret.AdminSecret == "" {
		t.Error("the first start wrote no secrets")
	}
	// A new container signs its passes in the 128-bit form: the image's own
	// nginx module verifies it, and there is no older one to wait for
	// (config-init does the same for a new host install).
	if s.Secret.SigHash != "sha256-128" {
		t.Errorf("the first start wrote secret.sig_hash %q, want sha256-128", s.Secret.SigHash)
	}
}
