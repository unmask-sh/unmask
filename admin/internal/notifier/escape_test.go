package notifier

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// The reason of a honeypot ban carries the path the visitor asked for.  In
// a Slack payload the characters mrkdwn reads commands from are entities,
// so <!channel> pages nobody and <url|label> plants no link; a Discord
// payload turns mentions off; and each is within the service's length.
func TestWebhookTextEscapesWhatTheVisitorWrote(t *testing.T) {
	reason := "wp-login: /wp-login.php?<!channel>&x=<https://evil.example|unban>@everyone <@&1234>\n• by: root"
	text := formatBanText("203.0.113.9", "t13d_x", "honeypot", untrusted(reason, reasonMax), untrusted("", fieldMax), "")

	slack, ct := buildPayload(FormatSlack, EventBanCreated, nil, text)
	if ct != "application/json" {
		t.Errorf("content type %q", ct)
	}
	var sp struct{ Text string }
	if err := json.Unmarshal(slack, &sp); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<!channel>", "<https://evil.example|unban>", "<@&1234>", "\n• by: root"} {
		if strings.Contains(sp.Text, bad) {
			t.Errorf("slack text carries %q: %s", bad, sp.Text)
		}
	}
	for _, want := range []string{"&lt;!channel&gt;", "&amp;x=&lt;https://evil.example|unban&gt;", "`203.0.113.9`"} {
		if !strings.Contains(sp.Text, want) {
			t.Errorf("slack text lacks %q: %s", want, sp.Text)
		}
	}

	discord, _ := buildPayload(FormatDiscord, EventBanCreated, nil, text)
	var dp struct {
		Content         string `json:"content"`
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}
	if err := json.Unmarshal(discord, &dp); err != nil {
		t.Fatal(err)
	}
	if dp.AllowedMentions.Parse == nil || len(dp.AllowedMentions.Parse) != 0 {
		t.Errorf("discord allowed_mentions.parse = %v, want an empty list: %s", dp.AllowedMentions.Parse, discord)
	}
	if !strings.Contains(string(discord), `"allowed_mentions":{"parse":[]}`) {
		t.Errorf("discord payload lacks the mention switch: %s", discord)
	}
	if strings.Contains(dp.Content, "\n• by: root") {
		t.Errorf("discord content carries the forged line: %s", dp.Content)
	}
}

// A reason of thousands of characters is cut before any channel, and the
// whole text stays within what Discord and Slack accept.
func TestWebhookTextIsBounded(t *testing.T) {
	long := strings.Repeat("/a", 5000)
	if got := untrusted(long, reasonMax); utf8.RuneCountInString(got) != reasonMax || !strings.HasSuffix(got, "…") {
		t.Errorf("untrusted kept %d runes", utf8.RuneCountInString(got))
	}
	if got := untrusted("a\r\nb\x00c\td", 10); got != "a  b c d" {
		t.Errorf("control characters: %q", got)
	}
	text := formatBanText("203.0.113.9", "", "honeypot", long, "", "")
	discord, _ := buildPayload(FormatDiscord, EventBanCreated, nil, text)
	var dp struct{ Content string }
	if err := json.Unmarshal(discord, &dp); err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(dp.Content); n > discordContentMax {
		t.Errorf("discord content is %d runes", n)
	}
	slack, _ := buildPayload(FormatSlack, EventBanCreated, nil, strings.Repeat("<", 5000))
	var sp struct{ Text string }
	if err := json.Unmarshal(slack, &sp); err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(sp.Text); n > slackTextMax {
		t.Errorf("slack text is %d runes", n)
	}
}

// BanCreated bounds the fields for every channel, the generic payload and
// the admin's list included.
func TestBanCreatedBoundsTheFields(t *testing.T) {
	var got map[string]any
	done := make(chan struct{}, 1)
	n := New(Config{}).WithInbox(inboxFunc(func(event string, fields map[string]any) {
		got = fields
		done <- struct{}{}
	}))
	n.BanCreated("203.0.113.9", "t13d", "honeypot", strings.Repeat("x", 1000)+"\n", "")
	<-done
	reason, _ := got["reason"].(string)
	if utf8.RuneCountInString(reason) != reasonMax || strings.Contains(reason, "\n") {
		t.Errorf("reason in the inbox: %d runes, newline %v", utf8.RuneCountInString(reason), strings.Contains(reason, "\n"))
	}
}

type inboxFunc func(event string, fields map[string]any)

func (f inboxFunc) Add(event string, fields map[string]any) { f(event, fields) }
