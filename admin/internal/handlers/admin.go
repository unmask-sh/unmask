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
	"strconv"
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

// AuthMiddleware checks `admin_token` from settings if non-empty.  When token
// is empty, the handler is unauth'd (= bind 127.0.0.1 前提).
func (h *Handler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	tok := h.Settings.Server.AdminToken
	if tok == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// query string ?token= or header X-Unmask-Token
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

	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n >= 1 && n <= 60 {
			days = n
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	funnel, err := dashboard.Funnel(ctx, h.DB, days)
	if err != nil {
		log.Printf("funnel query: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	verdictDist, _ := dashboard.VerdictDistribution(ctx, h.DB, days)
	failIPs, _ := dashboard.CaptchaFailIPs(ctx, h.DB, days, 30)
	series, _ := dashboard.DailySeries(ctx, h.DB, days)

	// chart 用に JSON シリアライズ.
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
	rangeText := fmt.Sprintf("%s 〜 %s",
		now.AddDate(0, 0, -days).Format("2006-01-02"),
		now.Format("2006-01-02"))

	data := map[string]any{
		"Days":           days,
		"RangeText":      rangeText,
		"Driver":         string(h.DB.Driver),
		"Funnel":         funnel,
		"VerdictDist":    verdictDist,
		"CaptchaFailIPs": failIPs,
		"SeriesJSON":     template.JS(seriesJSON),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		log.Printf("dashboard render: %v", err)
	}
}

// AdminFunnelJSON: GET {base}/admin/api/funnel?days=7  → JSON 形式.
func (h *Handler) AdminFunnelJSON(w http.ResponseWriter, r *http.Request) {
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n >= 1 && n <= 60 {
			days = n
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rows, err := dashboard.Funnel(ctx, h.DB, days)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": 0, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": 1, "funnel": rows})
}
