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
log_fail() { printf '%b\n' "  ${RED}FAIL${RESET}  $*" >&2; }
log_skip() { printf '%b\n' "  ${YELLOW}SKIP${RESET}  $*"; }

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
