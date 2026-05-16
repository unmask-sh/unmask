# Shared env.  Sourced from e2e/run.sh.
#
# Unless BASE_URL is overridden, hits localhost:8443 (= a locally-built demo).
# CI can pass something like BASE_URL=https://example.com.

: "${BASE_URL:=https://localhost:8443}"

# Known UA strings
UA_BROWSER='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
UA_CURL='curl/8.0'
UA_GOOGLEBOT='Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'

# Short curl wrapper.  $1 = path, remainder = extra curl args.
# Echoes only the status code.  Options are written inline to avoid quote-leakage bugs.
http_get() {
    local path="$1"; shift
    curl -sk -o /dev/null -w '%{http_code}' "$@" "${BASE_URL}${path}"
}
