package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The AI-advisor tab must render every field, all the way to the closing tag.
// A template error midway (the first cut of this tab read the section off the
// wrong struct) leaves a page that looks fine at a glance -- heading, intro --
// and simply has no inputs, which the wiring test above did not notice
// because the <form> tag comes before the failure point.
func TestAIAdvisorTabRendersEveryField(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/ai-advisor/", nil)
	req.SetPathValue("tab", "ai-advisor")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ai-advisor tab: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`name="ai_enabled"`, `name="ai_provider"`, `name="ai_model"`, `name="ai_endpoint"`,
		`name="ai_api_key"`, `name="ai_notify_enabled"`, `name="ai_notify_interval"`,
		`name="ai_notify_min_score"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("ai-advisor tab is missing %s", want)
		}
	}
	if !strings.Contains(body, "</html>") {
		t.Fatal("ai-advisor tab was cut short: no closing </html> (template error mid-render)")
	}
	// The key itself must never be in the page, set or not.
	if strings.Contains(body, `name="ai_api_key" value="`) && !strings.Contains(body, `name="ai_api_key" value=""`) {
		t.Error("the API key field must render empty")
	}
}
