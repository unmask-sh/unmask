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

// AdminDashboard: GET {base}/admin/
func (h *Handler) AdminDashboard(w http.ResponseWriter, r *http.Request) {
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

	funnel, err := dashboard.Funnel(ctx, h.DB, hours)
	if err != nil {
		log.Printf("funnel: %v", err)
		http.Error(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cookieRows, _ := dashboard.CookieStatus(ctx, h.DB, hours)
	flagsRows, _ := dashboard.FlagsDistribution(ctx, h.DB, hours)
	verdictDist, _ := dashboard.VerdictDistribution(ctx, h.DB, hours)
	hitRows, _ := dashboard.JA4HitBreakdown(ctx, h.DB, hours)
	loopRows, _ := dashboard.ReloadLoops(ctx, h.DB, hours)
	verifyNG, _ := dashboard.VerifyNGRanking(ctx, h.DB, hours, 30)
	cookieFails, _ := dashboard.CookieSetFails(ctx, h.DB, hours)
	stealth, _ := dashboard.StealthPassed(ctx, h.DB, hours)
	jsErrs, _ := dashboard.JSErrors(ctx, h.DB, hours)
	series, _ := dashboard.DailySeries(ctx, h.DB, 30) // chart は常に 30 日

	type seriesPt struct {
		Date     string `json:"date"`
		Serve    int    `json:"serve"`
		Load     int    `json:"load"`
		PoW      int    `json:"pow"`
		Captcha  int    `json:"captcha"`
		VerifyOK int    `json:"verify_ok"`
	}
	pts := make([]seriesPt, 0, len(series))
	for _, b := range series {
		pts = append(pts, seriesPt{b.Date, b.Serve, b.Load, b.PoW, b.Captcha, b.VerifyOK})
	}
	seriesJSON, _ := json.Marshal(pts)

	now := time.Now()
	rangeText := fmt.Sprintf("直近 %s (%s〜)",
		rng, now.Add(-time.Duration(hours)*time.Hour).Format("2006-01-02 15:04"))

	data := map[string]any{
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
		"JSErrors":    jsErrs,
		"SeriesJSON":  template.JS(seriesJSON),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		log.Printf("dashboard render: %v", err)
	}
}

// AdminFunnelJSON: GET {base}/admin/api/funnel?range=24h
func (h *Handler) AdminFunnelJSON(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if rng != "7d" && rng != "30d" {
		rng = "24h"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	rows, err := dashboard.Funnel(ctx, h.DB, dashboard.RangeHours(rng))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1, "range": rng, "funnel": rows})
}
