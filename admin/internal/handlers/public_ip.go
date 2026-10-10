package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// The server's own address as seen from outside, for the map's automatic
// position when no interface carries a global address (a host behind NAT
// or a cloud load balancer).  Asked of unmask.sh's address check -- a page
// that answers with the caller's address and nothing else -- and only when
// the operator presses the button for it (the 2026-10-10 call: no call home
// on its own, no daily refresh).  The answer is kept in a file beside the
// daemon's other state, so it survives restarts and is asked again only
// when the operator wants it.

// DefaultIPEchoURL answers {"ip": "<the caller's address>"}.
const DefaultIPEchoURL = "https://unmask.sh/api/ip"

// PublicIPPath keeps the last answer; tests point it at a temporary file.
var PublicIPPath = "/var/lib/unmask/public-ip.json"

var (
	pipMu     sync.Mutex
	pipLoaded bool
	pipAddr   string
	pipAt     time.Time
	// ipEchoURL is where the address is asked; tests point it at a stub.
	ipEchoURL = DefaultIPEchoURL
)

type publicIPRecord struct {
	IP string `json:"ip"`
	At int64  `json:"at"`
}

// publicIP returns the address last learnt and when, from memory or the
// file; empty until the operator has asked for it.
func (h *Handler) publicIP() (string, time.Time) {
	pipMu.Lock()
	defer pipMu.Unlock()
	if !pipLoaded {
		pipLoaded = true
		if b, err := os.ReadFile(PublicIPPath); err == nil {
			var rec publicIPRecord
			if json.Unmarshal(b, &rec) == nil && net.ParseIP(rec.IP) != nil {
				pipAddr, pipAt = rec.IP, time.Unix(rec.At, 0)
			}
		}
	}
	return pipAddr, pipAt
}

// ProbePublicIP asks the address check now and keeps the answer.
func (h *Handler) ProbePublicIP(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipEchoURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the address check answered %d", resp.StatusCode)
	}
	var doc struct {
		IP string `json:"ip"`
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil || json.Unmarshal(b, &doc) != nil || net.ParseIP(doc.IP) == nil {
		return "", errors.New("the address check gave no address")
	}
	setPublicIP(doc.IP, time.Now())
	return doc.IP, nil
}

func setPublicIP(ip string, at time.Time) {
	pipMu.Lock()
	pipLoaded, pipAddr, pipAt = true, ip, at
	pipMu.Unlock()
	if b, err := json.Marshal(publicIPRecord{IP: ip, At: at.Unix()}); err == nil {
		tmp := PublicIPPath + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err == nil {
			_ = os.Rename(tmp, PublicIPPath)
		}
	}
}

// setPublicIPForTest seeds the learnt address in memory only.
func setPublicIPForTest(ip string) {
	pipMu.Lock()
	pipLoaded, pipAddr, pipAt = true, ip, time.Now()
	if ip == "" {
		pipAt = time.Time{}
	}
	pipMu.Unlock()
}
