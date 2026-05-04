// /admin/api/myip — 単一 IP の情報を返す.
//
// 現状は最低限: reverse DNS, 内部 IP 判定, IP family.
// Geo / ASN は外部 DB (= geoip2 mmdb 等) を後付けで足す想定だが、 RPM 配布で
// MMDB を強制すると license / 容量で面倒なので、 admin 側で
// `config.geoip.mmdb_path` を任意指定にする (未指定なら geo は空).
package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

type myipResponse struct {
	IP         string   `json:"ip"`
	Family     string   `json:"family"` // "v4" / "v6"
	IsPrivate  bool     `json:"is_private"`
	IsLoopback bool     `json:"is_loopback"`
	ReverseDNS []string `json:"reverse_dns,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// AdminMyIP: GET {base}/admin/api/myip?ip=1.2.3.4
//
// 本番運用では admin 全体に AuthMiddleware を被せる前提.
func (h *Handler) AdminMyIP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("ip")
	if q == "" {
		writeJSON(w, http.StatusBadRequest, myipResponse{Error: "ip parameter required"})
		return
	}
	ip := net.ParseIP(q)
	if ip == nil {
		writeJSON(w, http.StatusBadRequest, myipResponse{Error: "invalid ip"})
		return
	}

	resp := myipResponse{
		IP:         ip.String(),
		Family:     "v6",
		IsPrivate:  ip.IsPrivate(),
		IsLoopback: ip.IsLoopback(),
	}
	if ip.To4() != nil {
		resp.Family = "v4"
	}

	// reverse DNS lookup with timeout (= block しないため goroutine + chan).
	ctx, cancel := context.WithTimeout(r.Context(), 800*time.Millisecond)
	defer cancel()
	resolver := net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip.String())
	if err == nil {
		out := make([]string, 0, len(names))
		for _, n := range names {
			out = append(out, strings.TrimSuffix(n, "."))
		}
		resp.ReverseDNS = out
	} else if !errors.Is(err, context.DeadlineExceeded) {
		// timeout ではない実エラーのみ報告.  no-record は普通なので silent.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && !dnsErr.IsNotFound {
			resp.Error = err.Error()
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
