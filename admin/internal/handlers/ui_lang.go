package handlers

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// rememberUILang records the language an account sees the admin in, when it
// differs from the one on record: its over-block alert is written in that
// language (notifier.Recipient).  The session check calls it with the account
// it has just read for the request, so the comparison costs nothing; the
// write happens only when the language changes -- picked in the header, or
// the browser's when none was picked.
//
// The write is done aside, so a request never waits on it, and once per
// account and language: while the database's writes are held (a schema update,
// a compaction) it is not tried at all, and the next request after the hold
// writes it.
func (h *Handler) rememberUILang(r *http.Request, u *user.User) {
	if h == nil || h.UserRepo == nil || u == nil {
		return
	}
	lang := string(i18n.Resolve(r))
	if lang == u.UILang {
		return
	}
	if h.DB != nil && h.DB.WritesHeld() {
		return
	}
	if prev, ok := h.uiLangWritten.Load(u.ID); ok && prev.(string) == lang {
		return // written already; the account read for this request predates it
	}
	h.uiLangWritten.Store(u.ID, lang)
	go func(id int64) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.UserRepo.SetUILang(ctx, id, lang); err != nil {
			h.uiLangWritten.Delete(id) // try again on a later request
			log.Printf("remember admin language for user %d: %v", id, err)
		}
	}(u.ID)
}

// uiLangWrites is the type of Handler.uiLangWritten (user id -> language).
type uiLangWrites = sync.Map
