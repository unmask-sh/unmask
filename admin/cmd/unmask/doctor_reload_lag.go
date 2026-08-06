package main

// Detection of "the conf is rendered but nginx has not loaded it".
//
// Saving settings in the admin UI renders the nginx conf immediately -- and
// deliberately does not reload nginx (the operator owns that step).  Between
// the two, doctor's freshness check reads as healthy: config.yml matches the
// rendered .inc, which is true, while the running nginx still enforces the
// previous render.  A field report measured the gap directly: http.inc
// written at 12:24:56, workers started 11:17:21, twelve minutes of "the
// setting is saved and not live" with every check green.
//
// The reload moment is recoverable from /proc: a reload re-forks every worker
// (the master survives, so the master's start time says nothing), which makes
// the newest worker's start time the last time nginx actually read its
// config.  A config change after that means the running nginx predates it.
// Same trap family as the stale-libs check, opposite direction: that one
// catches files replaced UNDER a running nginx, this one catches nginx never
// picking the new files up.
//
// "A config change" is the marker Render writes, not the .inc mtimes -- see
// lastSubstantiveRender for why the obvious signal is the wrong one.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// lastSubstantiveRender: when the rendered config last actually changed, from
// the marker Render writes.  Zero when there is none.
//
// Deliberately NOT the newest .inc mtime.  Every render rewrites every file,
// and a package upgrade renders on install, so mtimes answer "when did a
// render run" -- which after any upgrade is "just now" on a config that did
// not move. Measured: against mtimes this check called all seven fleet nodes
// stale minutes after an upgrade that changed nothing, and a warning that is
// always lit is a warning nobody reads. The marker only advances when a file's
// content changed, which is the only thing that can make nginx out of date.
func lastSubstantiveRender(dir string) time.Time {
	fi, err := os.Stat(filepath.Join(dir, nginxconf.SubstantiveRenderMarker))
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// procBootTime: the kernel boot moment (epoch sec), from /proc/stat's btime.
func procBootTime() int64 {
	b, err := os.ReadFile(filepath.Join(procRoot, "stat"))
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(ln, "btime "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}

// procStartTime: when pid started, as epoch seconds.  Field 22 of
// /proc/<pid>/stat counts clock ticks since boot; USER_HZ is 100 on every
// Linux ABI (the constant the proc(5) fields are defined against, independent
// of the kernel's actual HZ).
func procStartTime(pid int, btime int64) time.Time {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return time.Time{}
	}
	// comm (field 2) may contain spaces; fields count from after its ')'.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return time.Time{}
	}
	f := strings.Fields(s[i+1:])
	// f[0] is field 3 (state); starttime is field 22 -> f[19].
	if len(f) < 20 {
		return time.Time{}
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil || btime == 0 {
		return time.Time{}
	}
	return time.Unix(btime+ticks/100, 0)
}

// nginxLastReload: when the running nginx last read its config = the newest
// worker's start.  ok=false when no worker can be inspected -- not running,
// or /proc unreadable -- and callers must stay silent then, not report fresh.
func nginxLastReload() (time.Time, bool) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return time.Time{}, false
	}
	btime := procBootTime()
	var newest time.Time
	found := false
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if !strings.Contains(procCmdline(pid), "nginx: worker process") {
			continue
		}
		if st := procStartTime(pid, btime); !st.IsZero() {
			found = true
			if st.After(newest) {
				newest = st
			}
		}
	}
	return newest, found
}

// checkNginxReloadLag: WARN when the rendered conf postdates the last reload.
func checkNginxReloadLag(s settings.Settings, addOK, addWarn func(t, m string)) {
	dir := strings.TrimSpace(s.Nginx.OutputDir)
	if dir == "" {
		return
	}
	rendered := lastSubstantiveRender(dir)
	if rendered.IsZero() {
		return // no marker (never rendered, or last rendered by an older build)
	}
	loaded, ok := nginxLastReload()
	if !ok {
		return // nginx not inspectable; other checks report it down
	}
	// A render finishing in the same second as a reload must not flap.
	if rendered.After(loaded.Add(2 * time.Second)) {
		addWarn("nginx running on an older render", fmt.Sprintf(
			"the rendered config last CHANGED %s; nginx last loaded its config %s. "+
				"Those changes are written but NOT live "+
				"(saving in the admin UI renders and deliberately does not reload). "+
				"Apply with: nginx -t && reload (systemd: systemctl reload nginx / SysVinit: service nginx reload).",
			rendered.Format("2006-01-02 15:04:05"), loaded.Format("2006-01-02 15:04:05")))
		return
	}
	addOK("nginx reload freshness", "running config is newer than the last render")
}
