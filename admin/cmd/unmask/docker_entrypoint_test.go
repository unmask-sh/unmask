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
// first start -- no config.yml yet -- under a throwaway root (its absolute
// paths pointed into a temporary directory, `unmask` and `id` stood in for),
// and returns the config.yml it wrote as the daemon loads it.
func entrypointConfig(t *testing.T, env ...string) (settings.Settings, error) {
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
	for name, body := range map[string]string{"unmask": "#!/bin/sh\nexit 0\n", "id": "#!/bin/sh\necho 1000\n"} {
		if err := os.WriteFile(filepath.Join(root, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", path, "version")
	cmd.Env = append([]string{"PATH=" + filepath.Join(root, "bin") + ":" + os.Getenv("PATH")}, env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("entrypoint: %v\n%s", err, out)
	}
	return settings.Load(filepath.Join(root, "etc", "unmask", "config.yml"))
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
}
