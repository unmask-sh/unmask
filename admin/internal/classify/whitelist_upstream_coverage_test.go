package classify

import "testing"

// Regression guard for the removed built-in whitelist presets: every brand
// operator they used to cover (Googlebot / Bingbot / GPTBot / ClaudeBot / ...)
// must stay rescued as search_ai purely through the crawler-user-agents.json
// upstream path.  If a future crawler-list update drops one, this fails before
// it can cause a ranking accident.
func TestWhitelistPresetUpstreamCoverage(t *testing.T) {
	cases := map[string]string{
		"google":  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"g-inspect": "Mozilla/5.0 (compatible; Google-InspectionTool/1.0;)",
		"mediapartners": "Mediapartners-Google",
		"adsbot": "AdsBot-Google (+http://www.google.com/adsbot.html)",
		"bing":    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"msnbot":  "msnbot/2.0b (+http://search.msn.com/msnbot.htm)",
		"bingpreview": "Mozilla/5.0 (Windows NT 6.1; WOW64) BingPreview/1.0b",
		"yahoo":   "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
		"naver":   "Mozilla/5.0 (compatible; Yeti/1.1; +http://naver.me/spd)",
		"yandex":  "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
		"yandeximg": "Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)",
		"baidu":   "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
		"sogou":   "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)",
		"duckduck": "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
		"apple":   "Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)",
		"ia":      "Mozilla/5.0 (compatible; archive.org_bot +http://archive.org/details/archive.org_bot)",
		"ia_arch": "ia_archiver (+http://www.alexa.com/site/help/webmasters)",
		"huawei":  "Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)",
		"coccoc":  "Mozilla/5.0 (compatible; coccocbot-web/1.0; +http://help.coccoc.com/searchengine)",
		"seznam":  "Mozilla/5.0 (compatible; SeznamBot/3.2; +http://napoveda.seznam.cz/en/seznambot-intro/)",
		"qwant":   "Mozilla/5.0 (compatible; Qwantify/1.0; +https://www.qwant.com/)",
		"gptbot":  "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot",
		"claudebot": "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
		"ccbot":   "CCBot/2.0 (https://commoncrawl.org/faq/)",
		"bytespider": "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)",
		"googleext": "Mozilla/5.0 (compatible; Google-Extended)",
		"chatgptuser": "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)",
		"oai-search": "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)",
		"perplexity": "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
		"mistral": "MistralAI-User/1.0",
		"youbot":  "Mozilla/5.0 (compatible; YouBot (+http://www.you.com))",
	}
	for name, ua := range cases {
		got := IsBot(ua, "ok").String()
		if got != "search_ai" {
			t.Errorf("GAP %-12s -> %q (want search_ai)\n  UA: %s", name, got, ua)
		}
	}
}
