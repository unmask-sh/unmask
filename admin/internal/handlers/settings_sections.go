package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The sections of the settings page whose form is read straight into the
// settings, with nothing to refuse and nothing to answer: AdminSettingsSave
// calls each from its switch, under the settings lock, like the applyXForm
// functions of the sections that validate.

// applyGlobalForm: the operating-mode tab -- monitor mode and the chain each
// kind of client meets when no rule names it.
func applyGlobalForm(cur *settings.Settings, r *http.Request) {
	// Monitor mode lives on the challenge record (it is resolved per site by
	// both deploy paths), but the operator meets it here, on the
	// operating-mode tab.
	cur.Challenge.Default.ObserveOnly = settings.BoolPtr(r.FormValue("global_observe_only") == "1")
	validBucket := func(v string) string {
		v = strings.TrimSpace(v)
		if v == "pass" || settings.IsValidRateChallengeMode(v) {
			return v
		}
		// Unset/garbage stores "" = the strict built-in default
		// (pow_only).  The old fallback was "pass", which turned a
		// malformed POST into a fail-open wave-through.
		return ""
	}
	cur.Global.KnownBrowserAction = validBucket(r.FormValue("global_known_browser_action"))
	cur.Global.UnknownUAAction = validBucket(r.FormValue("global_unknown_ua_action"))
}

// applyPerformanceForm: the performance tab -- the database's memory budget
// and connection count (read when the pool opens, so a change there needs a
// restart of the daemon, which the save detects by comparing the DB record)
// and the event writer's batch, which is applied at once.
func applyPerformanceForm(cur *settings.Settings, r *http.Request) {
	// Resource dials.  The DB knobs are baked into the DSN when the pool
	// opens, so a change there is start-only (beforeDB comparison below sets
	// the restart flag); the event-flusher knobs hot-reload.
	if v := strings.TrimSpace(r.FormValue("perf_profile")); v != "" {
		switch v {
		case settings.PerfProfileConservative, settings.PerfProfileStandard,
			settings.PerfProfileGenerous, settings.PerfProfileCustom:
			cur.DB.PerfProfile = v
		}
	}
	// Custom-only fields.  Parsed whenever present so switching profile and
	// editing the numbers in one save works, but they only take effect under
	// the custom profile (see db.sqlitePerConnBytesFor).
	if _, present := r.Form["sqlite_cache_mb"]; present {
		v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("sqlite_cache_mb")))
		if err != nil || v < 0 {
			v = 0 // blank / garbage -> fall back to the derived budget
		} else if v > 2048 {
			v = 2048
		}
		cur.DB.SQLiteCacheMB = v
	}
	if _, present := r.Form["db_max_conns"]; present {
		v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("db_max_conns")))
		if err != nil || v < 0 {
			v = 0 // blank -> derive from CPUs
		} else if v > 32 {
			v = 32
		}
		cur.DB.MaxConns = v
	}
	// events_batch_size: clamp to 1..1000.
	if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("events_batch_size"))); err == nil {
		if v < 1 {
			v = 1
		} else if v > 1000 {
			v = 1000
		}
		cur.EventsBatchSize = v
	}
	// events_batch_interval_ms: clamp to 50..60000 (= 1 min).
	if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("events_batch_interval_ms"))); err == nil {
		if v < 50 {
			v = 50
		} else if v > 60000 {
			v = 60000
		}
		cur.EventsBatchIntervalMs = v
	}
	// Hot-reload the flusher (= runs with the new values from the next cycle).
	events.GlobalFlusherSetConfig(cur.EventsBatchSize, cur.EventsBatchIntervalMs)
}

// applyRetentionForm: the retention tab -- how long events, the audit log,
// the notifications and the ask history are kept, and whether nginx's access
// log is received at all.
func applyRetentionForm(cur *settings.Settings, r *http.Request) {
	// events_retention_days: 0 = retain forever; sanity-capped at 3650 (= 10 years).
	// No need to restart the goroutine on change (= EventsRetentionDays is
	// read via h.cfg(), so the published swap takes effect from the next tick).
	if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue("events_retention_days"))); err == nil {
		if v < 0 {
			v = 0
		} else if v > 3650 {
			v = 3650
		}
		cur.EventsRetentionDays = v
	}
	// The audit log's, the notification list's and the ask history's: 0 =
	// kept, the default for all three; the same cap.
	for name, dst := range map[string]*int{
		"audit_log_retention_days":   &cur.AuditLogRetentionDays,
		"notice_retention_days":      &cur.NoticeRetentionDays,
		"ask_history_retention_days": &cur.AskHistoryRetentionDays,
	} {
		if v, err := strconv.Atoi(strings.TrimSpace(r.FormValue(name))); err == nil {
			if v < 0 {
				v = 0
			} else if v > 3650 {
				v = 3650
			}
			*dst = v
		}
	}

	// nginx_log_enabled toggle. To apply, the next render-nginx + nginx
	// reload + admin service restart (= socket bind close/reopen) is
	// required. We don't toggle this on the fly (= the recvLoop goroutine's
	// running state is not changed by design).
	cur.NginxLog.Enabled = r.FormValue("nginx_log_enabled") == "1"
}
