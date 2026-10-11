package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/advisor"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The model and effort picks of the ask and advisor pages: the provider's
// models (the list the AI tab fetched, the configured model first), the
// efforts the provider takes, and -- so "default" does not read as a blank
// -- what each model runs at when none is picked: the configured effort,
// the model's own level, or "the model's own" when the table does not know
// it.  A model known to take no effort holds the effort pick.
//
// A page remembers its picks in two cookies, unmask_<page>_model and
// unmask_<page>_effort (the page's script writes them), read here so the
// page draws them selected; on the advisor page the picked model also
// decides which review is shown, since a review is kept per model.

type aiModelChoice struct {
	ID           string
	Label        string
	DefaultLabel string // the effort pick's "default" option with this model picked
	NoEffort     bool   // the model takes no effort
}

type aiPicksView struct {
	Page         string // "ask" or "advisor": the ids (ask-model) and the cookies
	Models       []aiModelChoice
	Model        string // the picked model
	Efforts      []string
	Effort       string // the picked effort; "" is the default
	DefaultLabel string // the default's text for the picked model
	NoEffort     bool
}

// aiModelChoices is the model pick's list: the provider's models as the AI
// tab fetched them, with the configured model added when the list does not
// carry it (or there is no list), in the pickers' order (advisor.SortModels:
// families by name, versions newest first).  The configured model sits in
// its place; it is the one drawn selected.
func (h *Handler) aiModelChoices(cfg settings.AIAdvisorConfig) []advisor.ModelInfo {
	cur := cfg.ResolvedModel()
	var out []advisor.ModelInfo
	have := false
	if c := h.loadModelCache(); c != nil {
		for _, m := range c.Models {
			have = have || m.ID == cur
			out = append(out, m)
		}
	}
	if !have {
		out = append(out, advisor.ModelInfo{ID: cur})
	}
	advisor.SortModels(out)
	return out
}

// aiModelAllowed: a pick may name any model of aiModelChoices.
func (h *Handler) aiModelAllowed(cfg settings.AIAdvisorConfig, id string) bool {
	for _, m := range h.aiModelChoices(cfg) {
		if m.ID == id {
			return true
		}
	}
	return false
}

// applyAIPick sets cfg's model and effort to a pick; "" leaves the
// configured value.  The error names a model off the list, or an effort the
// provider -- or the picked model -- does not take.
func (h *Handler) applyAIPick(cfg *settings.AIAdvisorConfig, model, effort string, lang i18n.Lang) error {
	if m := strings.TrimSpace(model); m != "" && m != cfg.ResolvedModel() {
		if !h.aiModelAllowed(*cfg, m) {
			return errors.New(i18n.T(lang, "ask.err_model"))
		}
		cfg.Model = m
	}
	if e := strings.TrimSpace(effort); e != "" && e != cfg.Effort {
		if !advisor.TakesEffort(cfg.ResolvedModel()) || !slices.Contains(advisor.EffortLevels(cfg.ResolvedProvider()), e) {
			return errors.New(i18n.T(lang, "ask.err_effort"))
		}
		cfg.Effort = e
	}
	return nil
}

// aiPickCookie reads one of a page's remembered picks ("" when unset).
func aiPickCookie(r *http.Request, page, which string) string {
	c, err := r.Cookie("unmask_" + page + "_" + which)
	if err != nil {
		return ""
	}
	v, err := url.QueryUnescape(c.Value)
	if err != nil {
		return ""
	}
	return v
}

// pickedAICfg is the AI settings with the page's remembered picks applied,
// and the effort picked ("" for the default).  A remembered pick the
// provider no longer offers is dropped, not refused: the list moves under
// a cookie.
func (h *Handler) pickedAICfg(r *http.Request, page string) (settings.AIAdvisorConfig, string) {
	cfg := h.cfg().AIAdvisor
	lang := i18n.Resolve(r)
	model, effort := aiPickCookie(r, page, "model"), aiPickCookie(r, page, "effort")
	try := cfg
	if h.applyAIPick(&try, model, effort, lang) == nil {
		if strings.TrimSpace(effort) == "" || !advisor.TakesEffort(try.ResolvedModel()) {
			effort = ""
		}
		return try, effort
	}
	try = cfg
	if h.applyAIPick(&try, model, "", lang) == nil {
		return try, ""
	}
	return cfg, ""
}

// effortDefaultLabel is the effort pick's "default" option for a model: the
// configured effort when there is one, else the model's own level, else
// "the model's own"; a model that takes none says so.
func effortDefaultLabel(configured, model string, lang i18n.Lang) (string, bool) {
	def, takes, known := advisor.EffortDefault(model)
	switch {
	case !takes:
		return i18n.T(lang, "ask.effort_none"), true
	case configured != "":
		return i18n.Tf(lang, "ask.effort_default_is", configured), false
	case known:
		return i18n.Tf(lang, "ask.effort_default_is", def), false
	}
	return i18n.T(lang, "ask.effort_default_model"), false
}

// aiPicks is the view of a page's picks.
func (h *Handler) aiPicks(r *http.Request, page string) aiPicksView {
	lang := i18n.Resolve(r)
	base := h.cfg().AIAdvisor
	cfg, effort := h.pickedAICfg(r, page)
	v := aiPicksView{Page: page, Model: cfg.ResolvedModel(), Efforts: advisor.EffortLevels(cfg.ResolvedProvider()), Effort: effort}
	for _, m := range h.aiModelChoices(base) {
		c := aiModelChoice{ID: m.ID, Label: m.Label}
		c.DefaultLabel, c.NoEffort = effortDefaultLabel(base.Effort, m.ID, lang)
		v.Models = append(v.Models, c)
	}
	v.DefaultLabel, v.NoEffort = effortDefaultLabel(base.Effort, v.Model, lang)
	return v
}
