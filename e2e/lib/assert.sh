# Simple assertion / logging helpers.  Sourced from e2e/run.sh and each scenario script.
#
# Each scenario is treated as:
#   - exit 0 -> PASS
#   - exit non-zero -> FAIL
# Failures print details to stderr.

# ANSI color (= enabled when stdout is a terminal, disabled through a pipe)
if [ -t 1 ]; then
    GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; RESET='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; RESET=''
fi

log()      { printf '%b\n' "  $*"; }
log_pass() { printf '%b\n' "  ${GREEN}PASS${RESET}  $*"; }
log_fail() { _E2E_FAILS=$((${_E2E_FAILS:-0} + 1)); printf '%b\n' "  ${RED}FAIL${RESET}  $*" >&2; }
log_skip() { printf '%b\n' "  ${YELLOW}SKIP${RESET}  $*"; }

# log_note: a measurement worth seeing after the run, not just while it scrolls
# past.  Prints inline like log(), and when run.sh has set E2E_NOTES the line is
# also collected and reprinted in the summary block at the end -- a figure
# buried 50 scenarios up is a figure nobody reads.
log_note() {
    printf '%b\n' "  $*"
    [ -n "${E2E_NOTES:-}" ] && printf '%s\n' "$*" >>"$E2E_NOTES"
    return 0
}

# Exit guard: a scenario is a FAIL when ANY assertion failed, not just when
# its LAST command happened to exit non-zero.  Without this, a mid-scenario
# assert_eq failure is silently swallowed as long as the final assert passes
# (run.sh only sees the script's exit code) — a green suite that didn't
# actually hold all its assertions.  Counted via log_fail so assert_eq /
# assert_in / direct log_fail calls all register.
_E2E_FAILS=0
_e2e_exit_guard() {
    local rc=$?
    if [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ]; then
        printf '%b\n' "  ${RED}FAIL${RESET}  ${_E2E_FAILS} assertion(s) failed earlier in this scenario" >&2
        exit 1
    fi
}
trap _e2e_exit_guard EXIT

# assert_eq EXPECTED ACTUAL DESC
assert_eq() {
    local expected="$1" actual="$2" desc="$3"
    if [ "$expected" = "$actual" ]; then
        log_pass "$desc (= $actual)"
        return 0
    fi
    log_fail "$desc: expected=$expected actual=$actual"
    return 1
}

# assert_in NEEDLE HAYSTACK DESC
assert_in() {
    local needle="$1" haystack="$2" desc="$3"
    if echo "$haystack" | grep -qF -- "$needle"; then
        log_pass "$desc (= contains '$needle')"
        return 0
    fi
    log_fail "$desc: '$needle' not found in:\n$haystack"
    return 1
}

# assert_not_in NEEDLE HAYSTACK DESC -- the inverse of assert_in, for pinning a
# value that must NEVER appear (e.g. a ban rewritten as a hard deny).
assert_not_in() {
    local needle="$1" haystack="$2" desc="$3"
    if echo "$haystack" | grep -qF -- "$needle"; then
        log_fail "$desc: '$needle' unexpectedly present in:\n$haystack"
        return 1
    fi
    log_pass "$desc (= does not contain '$needle')"
    return 0
}

# captcha_page_ct <challenge page URL> [curl args...] -- the proof-of-load
# token (window.UNMASK.ct) of a challenge page fetched as a browser.  The
# daemon hands out a math question only against a page's token, and hands the
# same token back as the ct /verify consumes, so one page load buys one
# answered question; every math-CAPTCHA flow starts here.
#
# The token is bound to the client the page was served to (the address the
# curl args name, the host) and signs the chain the page ran.  A chain that
# runs the proof-of-work before the CAPTCHA (the default pow_then_captcha)
# owes that proof at /verify, so the page's seed is solved here as well
# (lib/powsolve.py, the way scenario 23 does) and kept for captcha_page_pow,
# which the caller puts in the verify body as "pow".
#
# The daemon also refuses an answer within two seconds of the token's clock
# (captcha.TokenMinAgeSeconds): a person cannot meet the card that fast, and
# neither can a script that fetches and answers in one breath -- which is
# what every caller here is.  So the wait is taken once, here, before the
# token is handed back.
captcha_page_ct() {
    local url=$1 page ct seed issued diff; shift
    page=$(curl -sk -A "$UA_BROWSER" "$@" "$url")
    ct=$(printf '%s' "$page" | grep -oE '__CT__\*/"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"/\1/')
    [ -n "$ct" ] || return 0
    seed=$(printf '%s' "$page" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
    issued=$(printf '%s' "$page" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
    diff=$(printf '%s' "$page" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
    if [ -n "$seed" ] && [ -n "$issued" ]; then
        python3 "$(dirname "${BASH_SOURCE[0]}")/powsolve.py" "$seed" "$issued" "${diff:-18}" \
            > "$(captcha_pow_file "$ct")" 2>/dev/null || true
    fi
    sleep 2.5
    printf '%s' "$ct"
}

# captcha_pow_file <ct> -- where captcha_page_ct keeps the page's solved
# proof-of-work (the function runs in a command substitution, so a variable
# could not carry it out).
captcha_pow_file() {
    printf '%s/unmask-e2e-pow.%s' "${TMPDIR:-/tmp}" "$(printf '%s' "$1" | tr -c 'a-zA-Z0-9._-' '_')"
}

# captcha_page_pow <ct> -- the proof-of-work solved for the page whose ct
# this is ("<issued>.pow2.<nonce>.0"), for the "pow" field of the verify
# body; empty when the page carried no seed.
captcha_page_pow() {
    local f
    f=$(captcha_pow_file "$1")
    [ -f "$f" ] && tr -d '\n' < "$f"
    rm -f "$f"
    return 0
}
