// dashboard / admin endpoints.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/dashboard"
)

var (
	dashboardTmpl     *template.Template
	dashboardTmplOnce sync.Once
	dashboardTmplErr  error
)

func loadDashboardTemplate() (*template.Template, error) {
	dashboardTmplOnce.Do(func() {
		funcs := template.FuncMap{
			"hasPrefix": strings.HasPrefix,
			"percent": func(x float64) string {
				return fmt.Sprintf("%.1f%%", x*100)
			},
			"score": func(x float64) string {
				return fmt.Sprintf("%.2f", x)
			},
			"add": func(a, b int) int { return a + b },
			// 整数を 3 桁区切りで render (= 1234 → "1,234"). 本家と同じ format.
			"comma": func(n int) string {
				s := fmt.Sprintf("%d", n)
				neg := false
				if strings.HasPrefix(s, "-") {
					neg = true
					s = s[1:]
				}
				out := ""
				for i, c := range s {
					if i > 0 && (len(s)-i)%3 == 0 {
						out += ","
					}
					out += string(c)
				}
				if neg {
					out = "-" + out
				}
				return out
			},
			// 比率 formatter: load=0 (or denom=0) のときは "-".
			"rate": func(num, denom int) string {
				if denom <= 0 {
					return "-"
				}
				return fmt.Sprintf("%.1f%%", float64(num)/float64(denom)*100)
			},
		}
		sub, err := fs.Sub(assets.Templates, "templates")
		if err != nil {
			dashboardTmplErr = err
			return
		}
		dashboardTmpl, dashboardTmplErr = template.New("dashboard.html").
			Funcs(funcs).ParseFS(sub, "*.html")
	})
	return dashboardTmpl, dashboardTmplErr
}

// AuthMiddleware: admin_token が空なら無認証.
func (h *Handler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	tok := h.Settings.Server.AdminToken
	if tok == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("token")
		if got == "" {
			got = r.Header.Get("X-Unmask-Token")
		}
		if got != tok {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized\n"))
			return
		}
		next(w, r)
	}
}

// AdminSiteList: GET {base}/admin/  — 観測された site の一覧.
func (h *Handler) AdminSiteList(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	rng := r.URL.Query().Get("range")
	if rng != "7d" && rng != "30d" {
		rng = "24h"
	}
	hours := dashboard.RangeHours(rng)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sites, err := dashboard.Sites(ctx, h.DB, hours)
	if err != nil {
		log.Printf("sites: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	rangeText := fmt.Sprintf("直近 %s (%s〜)",
		rng, now.Add(-time.Duration(hours)*time.Hour).Format("2006-01-02 15:04"))
	data := map[string]any{
		"Range":     rng,
		"RangeText": rangeText,
		"Driver":    string(h.DB.Driver),
		"Sites":     sites,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "site_list.html", data); err != nil {
		log.Printf("site list render: %v", err)
	}
}

// AdminDashboard: GET {base}/admin/{site}/  — site 別 dashboard.
func (h *Handler) AdminDashboard(w http.ResponseWriter, r *http.Request) {
	site, ok := pickSite(r)
	if !ok {
		http.Error(w, "invalid site id", http.StatusBadRequest)
		return
	}
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		log.Printf("dashboard tmpl load: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	rng := r.URL.Query().Get("range")
	if rng != "7d" && rng != "30d" {
		rng = "24h"
	}
	hours := dashboard.RangeHours(rng)

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	funnel, err := dashboard.Funnel(ctx, h.DB, site, hours)
	if err != nil {
		log.Printf("funnel: %v", err)
		http.Error(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cookieRows, _ := dashboard.CookieStatus(ctx, h.DB, site, hours)
	flagsRows, _ := dashboard.FlagsDistribution(ctx, h.DB, site, hours)
	verdictDist, _ := dashboard.VerdictDistribution(ctx, h.DB, site, hours)
	hitRows, _ := dashboard.JA4HitBreakdown(ctx, h.DB, site, hours)
	loopRows, _ := dashboard.ReloadLoops(ctx, h.DB, site, hours)
	verifyNG, _ := dashboard.VerifyNGRanking(ctx, h.DB, site, hours, 30)
	cookieFails, _ := dashboard.CookieSetFails(ctx, h.DB, site, hours)
	stealth, _ := dashboard.StealthPassed(ctx, h.DB, site, hours)
	jsErrs, _ := dashboard.JSErrors(ctx, h.DB, site, hours)
	// 30 日推移は本家相当: phase='serve' を is_bot kind 別に stacked bar で出す.
	dailyKind, dailyTotal, err := dashboard.DailyServeByKind(ctx, h.DB, site, 30)
	if err != nil {
		log.Printf("daily serve by kind: %v", err)
	}

	type kindPt struct {
		Date string `json:"date"`
		Kind int    `json:"kind"`
		Req  int    `json:"req"`
	}
	kindPts := make([]kindPt, 0, len(dailyKind))
	for _, b := range dailyKind {
		kindPts = append(kindPts, kindPt{b.Date, b.Kind, b.Req})
	}
	dailyKindJSON, _ := json.Marshal(kindPts)

	now := time.Now()
	rangeText := fmt.Sprintf("直近 %s (%s〜)",
		rng, now.Add(-time.Duration(hours)*time.Hour).Format("2006-01-02 15:04"))

	data := map[string]any{
		"Site":        site,
		"Range":       rng,
		"RangeText":   rangeText,
		"Driver":      string(h.DB.Driver),
		"Funnel":      funnel,
		"CookieRows":  cookieRows,
		"FlagsRows":   flagsRows,
		"VerdictDist": verdictDist,
		"HitRows":     hitRows,
		"LoopRows":    loopRows,
		"VerifyNG":    verifyNG,
		"CookieFails": cookieFails,
		"Stealth":     stealth,
		"JSErrors":      jsErrs,
		"DailyKindJSON": template.JS(dailyKindJSON),
		"DailyTotal":    dailyTotal,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		log.Printf("dashboard render: %v", err)
	}
}

// AdminFunnelJSON: GET {base}/admin/api/funnel?site=&range=24h
func (h *Handler) AdminFunnelJSON(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if rng != "7d" && rng != "30d" {
		rng = "24h"
	}
	site := r.URL.Query().Get("site")
	if site != "" && !siteIDRE.MatchString(site) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": 0, "error": "invalid_site"})
		return
	}
	if site == "" {
		site = defaultSite
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	rows, err := dashboard.Funnel(ctx, h.DB, site, dashboard.RangeHours(rng))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1, "site": site, "range": rng, "funnel": rows})
}
