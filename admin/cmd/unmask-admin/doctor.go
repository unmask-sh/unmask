// `unmask-admin doctor` — self-check right after install / upgrade.
//
// Each check reports one line of [OK] / [WARN] / [ERR].  Prints a summary at
// the end; if any [ERR] is present, exits with code 1 (= machine-checkable
// from automation).
//
// Checks:
//   1. config.yml is readable / parses
//   2. nginxconf.Render() dry-run succeeds
//   3. DB pings + the major tables exist
//   4. If the GeoIP mmdb path is set, the file is readable
//   5. The dir of ban_file_path is writable
//   6. If challenge_html_path is set, the file is readable
//   7. honeypot ban_duration / cookie_days are sensible
//   8. nginx output_dir is writable
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/geoip"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

type doctorCheck struct {
	level   string // "ok" | "warn" | "err"
	title   string
	message string
}

func (c doctorCheck) String() string {
	mark := "[OK]"
	switch c.level {
	case "warn":
		mark = "[WARN]"
	case "err":
		mark = "[ERR]"
	}
	if c.message == "" {
		return fmt.Sprintf("%s  %s", mark, c.title)
	}
	return fmt.Sprintf("%s  %s — %s", mark, c.title, c.message)
}

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	configPath := fs.String("config", os.Getenv("UNMASK_CONFIG"), "path to admin.yml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	checks := []doctorCheck{}
	addOK := func(t, m string) { checks = append(checks, doctorCheck{"ok", t, m}) }
	addWarn := func(t, m string) { checks = append(checks, doctorCheck{"warn", t, m}) }
	addErr := func(t, m string) { checks = append(checks, doctorCheck{"err", t, m}) }

	resolved := settings.ResolvePath(*configPath)
	fmt.Printf("unmask-admin doctor (config: %s)\n\n", resolved)

	// 1. load + parse config
	s, err := settings.Load(resolved)
	if err != nil {
		addErr("config load", err.Error())
		printSummary(checks)
		return errors.New("doctor failed at config load")
	}
	addOK("config load", resolved)

	// 2. nginxconf render dry-run
	if err := nginxconf.Render(s, os.TempDir(), Version); err != nil {
		addErr("nginx-rendered.conf render", err.Error())
	} else {
		addOK("nginx-rendered.conf render (dry-run)", "")
	}

	// 3. DB ping + tables
	conn, err := db.Open(s.DB)
	if err != nil {
		addErr("DB connect", err.Error())
	} else {
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := conn.PingContext(ctx); err != nil {
			addErr("DB ping", err.Error())
		} else {
			addOK("DB ping", string(s.DB.Driver))
		}
		// Confirm the major tables exist (= a 1-row SELECT without error is OK).
		ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel2()
		tables := []string{"unmask_event", "unmask_ban", "unmask_user"}
		var missing []string
		for _, tn := range tables {
			row := conn.QueryRowContext(ctx2, "SELECT 1 FROM "+tn+" LIMIT 1")
			var v int
			if err := row.Scan(&v); err != nil && !strings.Contains(err.Error(), "no rows") {
				missing = append(missing, tn)
			}
		}
		if len(missing) > 0 {
			addErr("DB table check", fmt.Sprintf("missing: %s (= run unmask-admin migrate)", strings.Join(missing, ", ")))
		} else {
			addOK("DB tables", strings.Join(tables, " / "))
		}
	}

	// 4. GeoIP mmdb (= optional)
	if s.GeoIP.MMDBPath == "" && s.GeoIP.MMDBASNPath == "" {
		addWarn("GeoIP mmdb", "not set (= no per-country chart / ASN popover)")
	} else {
		r := geoip.Open(s.GeoIP.MMDBPath, s.GeoIP.MMDBASNPath)
		if s.GeoIP.MMDBPath != "" {
			if _, err := os.Stat(s.GeoIP.MMDBPath); err != nil {
				addErr("GeoIP city mmdb", err.Error())
			} else {
				addOK("GeoIP city mmdb", s.GeoIP.MMDBPath)
			}
		}
		if s.GeoIP.MMDBASNPath != "" {
			if _, err := os.Stat(s.GeoIP.MMDBASNPath); err != nil {
				addErr("GeoIP ASN mmdb", err.Error())
			} else {
				addOK("GeoIP ASN mmdb", s.GeoIP.MMDBASNPath)
			}
		}
		if r != nil {
			r.Close()
		}
	}

	// 5. ban file directory writable
	if p := s.Nginx.Honeypot.BanFilePath; p != "" {
		dir := filepath.Dir(p)
		if err := writableDir(dir); err != nil {
			addErr("ban file dir", err.Error())
		} else {
			addOK("ban file dir", dir)
		}
	} else {
		addWarn("ban file path", "not set (= honeypot persistent BAN feature disabled)")
	}

	// 6. challenge html override (= optional)
	if p := s.Challenge.ChallengeHTMLPath; p != "" {
		if _, err := os.Stat(p); err != nil {
			addErr("challenge html override", err.Error())
		} else {
			addOK("challenge html override", p)
		}
	}

	// 7. challenge settings sanity
	if s.Challenge.CookieDays <= 0 || s.Challenge.CookieDays > 365 {
		addWarn("cookie_days", fmt.Sprintf("value %d is outside the sensible range (1-365)", s.Challenge.CookieDays))
	} else {
		addOK("cookie_days", fmt.Sprintf("%d days", s.Challenge.CookieDays))
	}
	if s.Challenge.CaptchaScoreThreshold < 0 || s.Challenge.CaptchaScoreThreshold > 1 {
		addWarn("captcha_score_threshold", fmt.Sprintf("value %.2f is outside (0.0-1.0)", s.Challenge.CaptchaScoreThreshold))
	} else {
		addOK("captcha_score_threshold", fmt.Sprintf("%.2f", s.Challenge.CaptchaScoreThreshold))
	}

	// 8. nginx output_dir writable
	if p := s.Nginx.OutputDir; p != "" {
		if err := writableDir(p); err != nil {
			addErr("nginx output_dir", err.Error())
		} else {
			addOK("nginx output_dir", p)
		}
	} else {
		addWarn("nginx output_dir", "not set (= cannot save from the web UI)")
	}

	// 9. Ensure the secret is not still the default (= a weak seed lets attackers forge cookies)
	if isDefaultSecret(s.Secret.BVSecret) {
		addErr("bv_secret", "still default.  regenerate via unmask-admin config-init")
	} else if len(s.Secret.BVSecret) < 16 {
		addWarn("bv_secret", "too short (= recommend 16+ chars)")
	} else {
		addOK("bv_secret", "set (length="+fmt.Sprint(len(s.Secret.BVSecret))+")")
	}

	// 10. notifications url (= optional)
	if !s.Notifications.Disabled && s.Notifications.URL != "" {
		if !strings.HasPrefix(s.Notifications.URL, "https://") && !strings.HasPrefix(s.Notifications.URL, "http://") {
			addErr("notifications.url", "does not start with https:// or http://")
		} else {
			addOK("notifications.url", s.Notifications.Format)
		}
	}

	return printSummary(checks)
}

func writableDir(p string) error {
	if p == "" {
		return errors.New("path empty")
	}
	st, err := os.Stat(p)
	if err != nil {
		// Try the parent dir (= if a file path was passed in).
		parent := filepath.Dir(p)
		if pst, perr := os.Stat(parent); perr == nil && pst.IsDir() {
			return tryTouch(parent)
		}
		return err
	}
	if !st.IsDir() {
		return tryTouch(filepath.Dir(p))
	}
	return tryTouch(p)
}

func tryTouch(dir string) error {
	f, err := os.CreateTemp(dir, ".unmask-doctor-*")
	if err != nil {
		return fmt.Errorf("write check failed: %v", err)
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return nil
}

func isDefaultSecret(s string) bool {
	if s == "" {
		return true
	}
	for _, sample := range []string{"change_me", "CHANGE_ME", "default", "secret"} {
		if strings.EqualFold(s, sample) {
			return true
		}
	}
	return false
}

func printSummary(checks []doctorCheck) error {
	var ok, warn, errCount int
	for _, c := range checks {
		fmt.Println(c.String())
		switch c.level {
		case "ok":
			ok++
		case "warn":
			warn++
		case "err":
			errCount++
		}
	}
	fmt.Printf("\n%d ok, %d warn, %d err\n", ok, warn, errCount)
	if errCount > 0 {
		return fmt.Errorf("doctor: %d errors", errCount)
	}
	return nil
}
