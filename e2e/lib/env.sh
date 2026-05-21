# Shared env.  Sourced from e2e/run.sh.
#
# Unless BASE_URL is overridden, hits localhost:8443 (= a locally-built demo).
# CI can pass something like BASE_URL=https://example.com.

: "${BASE_URL:=https://localhost:8443}"

# Apache forward-auth container (= scenario 14).  Plain HTTP: the Apache mode
# cannot read TLS handshakes, so there is no JA4 and no need for TLS here.
: "${APACHE_URL:=http://localhost:8081}"

# Known UA strings
UA_BROWSER='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
UA_CURL='curl/8.0'
# Search / AI crawler UAs — all four match the embedded crawler-user-agents.json.
UA_GOOGLEBOT='Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
UA_BINGBOT='Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'
UA_GPTBOT='Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot'
UA_CLAUDEBOT='Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)'

# Short curl wrapper.  $1 = path, remainder = extra curl args.
# Echoes only the status code.  Options are written inline to avoid quote-leakage bugs.
http_get() {
    local path="$1"; shift
    curl -sk -o /dev/null -w '%{http_code}' "$@" "${BASE_URL}${path}"
}
