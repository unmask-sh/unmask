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
