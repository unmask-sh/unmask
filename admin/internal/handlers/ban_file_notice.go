package handlers

import (
	"os"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/banfile"
)

// BanFileNotice: the bar under the header that says nginx's worker cannot
// read the ban list, so nginx enforces no ban (partial_ban_file_notice.html,
// part of header_tools like the reload notice).  The module reads the list
// from the worker, which runs as nginx.conf's `user`; through 0.1.53-rc12
// the package's 0750 data directory stopped it there, and the admin went on
// showing every ban as in force (kanagawa, 2026-10-24).  nil while the
// worker reads the list, and where there is nothing to say: no ban list
// written yet, no nginx on this host.
type BanFileNotice struct {
	User    string   // the worker user
	Path    string   // the ban list
	Blocker string   // the directory it cannot pass through, or the file it cannot read
	Need    string   // "x" or "r"
	Fix     []string // the commands that let it through
}

// banFileNoticeTTL: how long one verdict stands before the path is looked
// at again -- a few stats, but on every page render.
const banFileNoticeTTL = 30 * time.Second

// banFileNotice: the notice for this render, from a verdict at most
// banFileNoticeTTL old.
func (h *Handler) banFileNotice() *BanFileNotice {
	if h == nil {
		return nil
	}
	h.banFileMu.Lock()
	defer h.banFileMu.Unlock()
	if !h.banFileAt.IsZero() && time.Since(h.banFileAt) < banFileNoticeTTL {
		return h.banFileLast
	}
	check := h.BanFileCheck
	if check == nil {
		check = h.defaultBanFileCheck
	}
	v := check()
	var n *BanFileNotice
	if v.Err == nil && !v.OK && v.Blocker != "" {
		n = &BanFileNotice{
			User:    v.User,
			Path:    h.cfg().Nginx.Honeypot.BanFilePath,
			Blocker: v.Blocker,
			Need:    v.Need,
			Fix:     banfile.FixCommands(v),
		}
	}
	h.banFileLast, h.banFileAt = n, time.Now()
	return n
}

// defaultBanFileCheck: the verdict for this install's ban list.  OK -- no
// notice -- where there is no list to read: no path configured, no list
// written since the daemon started (a list it could not write is the
// doctor's "ban file dir"; a test instance writing nowhere has none), or
// the file absent.  banfile.Check itself answers ErrNoNginx on a host
// without nginx, which the notice treats as nothing to say.
func (h *Handler) defaultBanFileCheck() banfile.Verdict {
	s := h.cfg()
	p := s.Nginx.Honeypot.BanFilePath
	if p == "" || h.BanMgr == nil || !h.BanMgr.Flushed() {
		return banfile.Verdict{OK: true}
	}
	if _, err := os.Stat(p); err != nil {
		return banfile.Verdict{OK: true}
	}
	return banfile.Check(p, s.Nginx.ConfPath)
}
