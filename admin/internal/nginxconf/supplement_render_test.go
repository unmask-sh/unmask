package nginxconf

import "testing"

// The unmask supplement (crawler-user-agents-unmask.json) exists so that link
// previews from chat tools the upstream list lacks pass like Slackbot does; a
// Mattermost preview fetch got the challenge page until Mattermost-Bot joined
// it.  In native mode that only holds if the entries reach the rendered
// $is_search_bot whitelist with default settings: a supplement that stopped at
// the Go side would show the bots as passing in the UA-filter tab while nginx
// kept challenging them.
func TestSupplementPreviewBotsRenderIntoWhitelist(t *testing.T) {
	conf := renderHTTPInc(t, nil)
	for _, pat := range []string{`ChatWork LinkPreview`, `WebexTeams`, `NotionEmbedder`, `Mattermost-Bot`} {
		if !containsPattern(conf, pat) {
			t.Errorf("%s is not in the rendered whitelist: native mode would challenge its link previews", pat)
		}
	}
}
