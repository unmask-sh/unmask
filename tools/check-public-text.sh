#!/bin/bash
# check-public-text.sh -- refuse production measurements in text we publish.
#
# Traffic figures taken from our own nodes have leaked into public surfaces four
# times (2026-07-29, 08-13, 08-14, 08-23).  Each cleanup was scoped to the release
# being cut, so figures in older entries survived every sweep.  This runs over
# everything, every time.
#
# Why it matters: a request count, a pass rate or an address-pool size lets a
# reader derive our traffic volume and bot mix, and states one site's traffic as
# though it were a property of the software.  The claim always survives without
# the number ("the overwhelming majority", "a large pool of addresses").
#
# The surfaces, widest exposure first:
#   tools/releases.json      the admin About tab renders these notes into EVERY install
#   admin/assets/static/*    served to every visitor of every install
#   nginxconf/templates/*    rendered onto every install's disk
#   admin/**/*.go, *.html    public repo, and help text an operator reads
#   CHANGELOG.md             public repo + the GitHub release page
#
#   usage: ./tools/check-public-text.sh [path ...]     (default: the repo root)
#   e.g.:  ./tools/check-public-text.sh . ../CHANGELOG-master.md
#
# Escaping a false positive: round the figure (fixtures read "10,000 requests")
# or drop it.  There is deliberately no inline suppression -- a pragma would be
# reached for exactly when the check is right.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
SELFTEST=0
if [ "${1:-}" = "--self-test" ]; then SELFTEST=1; shift; fi
TARGETS=("$@"); [ ${#TARGETS[@]} -eq 0 ] && TARGETS=(.)

# --self-test scans a fixture instead of the tree.  A rule whose regex stops
# matching -- one stray backslash through the shell is enough -- reports the
# tree as clean, which reads exactly like a tree that IS clean.  So CI proves
# every rule still fires, and that the four shapes that legitimately carry
# numbers (a round fixture, a throughput benchmark, hypothetical sizing in help
# text, a query timing) still do not.
if [ "$SELFTEST" = 1 ]; then
    d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
    cat > "$d/probe.go" <<'PROBE'
// must-fire grouped:   served itself 137,051 requests in a day.
// must-fire phrase:    Measured on a live install: 942,209 against 941,283.
// must-fire percent:   abandoned at 51% against a baseline, 44% of all requests.
// must-fire magnitude: on the tool1-us production DB (3.9M events) it took 10s.
// must-fire node:      Hit live on tool1-gb applying a rule.
// stay-quiet fixture:  10,000 requests, 2,000 of them from crawlers.
// stay-quiet bench:    measured 56k -> 3.9k req/s in the gate key.
// stay-quiet sizing:   a site around 33,000 events/day is 230k rows.
// stay-quiet timing:   Measured on a multi-GB event DB: 0.36s with the hint.
PROBE
    TARGETS=("$d")
fi

# A measurement, not a fixture: fixtures are written round (10,000 / 3,100), a
# real count never is (137,051 / 7,856 / 1,120).  So the grouped number must end
# in something other than "00".  ERE has no lookahead, hence the two branches.
NUM='[0-9]{1,3},([0-9]{2}[1-9]|[0-9][1-9]0)'
NOUN='(requests?|challenges?|serves?|cookies?|addresses|addrs?|events?|hits?|visitors?|pages?|sessions?|IPs|rows)'
# Phrases that introduce one of our own measurements -- but only when a figure
# follows in the same sentence.  "Observed on a production install: a crawler
# solved the proof-of-work across a large pool of addresses" is the approved
# form; it is the number after the colon that is not ours to publish.
PHRASE='([Mm]easured (live|on)|[Oo]bserved (live|on)|[Oo]n a live install|on the measured install|One node read|[Hh]it live on|[Rr]eproduced on|[Vv]erified in production)[^.]{0,120}'"$NUM"''
# A fleet node name is only a finding next to a figure or a measurement verb --
# the same strings appear legitimately as fixture data and as example hostnames.
NODE='(tool[12]-(jp|us|gb|sg)|alink1|bbs-ros1)'
VERB='([Mm]easured|[Oo]bserved|[Rr]eproduced|[Hh]it live|[Vv]erified|[Ss]een|[Cc]aptured|incident|rendered|served|rejects)'
# Magnitudes written with a suffix (6.6M rows, 137k requests) escape NUM, and
# rounding cannot tell them apart from a fixture.  What marks them as ours is
# the claim around them -- our node, our fleet, our install.  A throughput
# ("3.9k req/s") is a benchmark, not a volume, so rates are excluded.
MAG='[0-9]+(\.[0-9]+)?[MkK] ?(rows|events|requests|IPs|addresses|sessions|serves)([^/s]|$)'
OURS='(production|fleet|live install|on a node|on one node|on the .{0,20}DB)'

hits=0
report=""
scan() { # scan <label> <regex>
    local out
    out=$(grep -rEn --binary-files=without-match \
        --include='*.go' --include='*.js' --include='*.html' --include='*.tmpl' \
        --include='*.json' --include='*.md' --include='*.yml' --include='*.conf' \
        --include='*.sh' --include='*.py' \
        --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor \
        --exclude='check-public-text.sh' \
        -- "$2" "${TARGETS[@]}" 2>/dev/null)
    [ -z "$out" ] && return 0
    if [ "$SELFTEST" != 1 ]; then          # in self-test these are the expected result
        echo "::error::$1"
        echo "$out" | sed 's/^/  /'
    fi
    report="$report$(echo "$out" | sed 's/^/  /')
"
    hits=$((hits + 1))
}

# A number is only a finding when a traffic noun sits near it, in either order.
scan "production traffic figure" "${NUM}[^0-9]{0,40}${NOUN}|${NOUN}[^0-9]{0,20}${NUM}"
scan "a measurement of our own traffic is being cited" "$PHRASE"
# A share of our own traffic, which no grouped number needs to appear in.
scan "a share of our own traffic" "[0-9]{1,3}(\\.[0-9]+)?% of (all |the )?${NOUN}|[0-9]+\\.[0-9]+% (of|abandon|pass|baseline|malicious)"
scan "a magnitude of our own traffic" "${OURS}[^.]{0,90}${MAG}|${MAG}[^.]{0,90}${OURS}"
scan "a fleet node named beside a figure or a measurement" "${NODE}[^.]{0,60}(${VERB}|${NUM})|(${VERB}|${NUM})[^.]{0,60}${NODE}"

if [ "$SELFTEST" = 1 ]; then
    fired=$(printf '%s' "$report" | grep -c "^  .*must-fire")
    quiet=$(printf '%s' "$report" | grep -c "^  .*stay-quiet")
    if [ "$hits" -eq 5 ] && [ "$fired" -eq 5 ] && [ "$quiet" -eq 0 ]; then
        echo "check-public-text: self-test ok (5 rules fire, 4 exemptions quiet)"
        exit 0
    fi
    echo "::error::self-test FAILED: $hits/5 rules fired, $fired must-fire lines, $quiet stay-quiet lines" >&2
    printf '%s\n' "$report" >&2
    exit 1
fi

if [ "$hits" -gt 0 ]; then
    cat >&2 <<'MSG'

Public text must not carry figures measured on our own nodes, or name our hosts.
Round a fixture number, or make the claim without the figure.  See the header of
this script for why.
MSG
    exit 1
fi
echo "check-public-text: clean (${#TARGETS[@]} path(s))"
