#!/bin/sh
# check-dco.sh -- every commit of a pull request is signed off by its author.
#
# CONTRIBUTING.md asks for a `Signed-off-by:` trailer on each commit of a
# contribution (the Developer Certificate of Origin), and for a long time
# nothing looked.  This reads the commits of a pull request as the GitHub API
# lists them and names the ones without the trailer.
#
#   usage: gh api --paginate repos/<owner>/<repo>/pulls/<n>/commits | tools/check-dco.sh
#          tools/check-dco.sh --self-test
#
# A commit passes when its message carries a line
#
#   Signed-off-by: Any Name <address>
#
# whose address is the commit author's (letter case aside) -- what
# `git commit -s` writes.  Not asked: a merge commit (more than one parent;
# it brings in commits that are asked on their own) and a commit a bot
# authored (the dependency updates).
#
# The commit messages are a stranger's text.  jq reads them; the shell never
# evaluates a byte of them.
set -eu

# The filter: commit objects in (an array, or several arrays, as --paginate
# prints them), one line out per commit that lacks its author's sign-off.
FILTER='
def norm: ascii_downcase | gsub("^\\s+|\\s+$"; "");
[ .[] | if type == "array" then .[] else . end ]
| map(select((.parents | length) < 2))
| map(select(((.author.login // "") | test("\\[bot\\]$")) | not))
| map(. as $c
      | (($c.commit.author.email // "") | norm) as $email
      | [ ($c.commit.message // "") | split("\n")[]
          | select(test("^Signed-off-by:\\s*.*<[^<>]+>\\s*$"; "i"))
          | capture("<(?<e>[^<>]+)>\\s*$").e | norm ] as $signers
      | select(($signers | index($email)) == null)
      | "  \($c.sha[0:8])  \($c.commit.author.name // "?") <\($c.commit.author.email // "?")>  \(($c.commit.message // "") | split("\n")[0] | .[0:60])")
| .[]'

check() { # commits JSON on stdin; prints the commits that fail, exits 1 if any
    missing=$(jq -r -s "$FILTER")
    if [ -n "$missing" ]; then
        echo "These commits carry no Signed-off-by line of their author:"
        printf '%s\n' "$missing"
        echo
        echo "Add it with:  git commit --amend -s   (one commit)"
        echo "         or:  git rebase --signoff <base>   (several), then push again."
        echo "What the line asserts: https://developercertificate.org/ (CONTRIBUTING.md, \"Developer Certificate of Origin\")."
        return 1
    fi
    echo "every commit is signed off by its author"
}

if [ "${1:-}" != "--self-test" ]; then
    check
    exit $?
fi

# --- self-test ---------------------------------------------------------------
fails=0
expect() { # <what> <want: pass|fail> <want the output to hold, or ""> ; commits JSON on stdin
    if out=$(check 2>&1); then got=pass; else got=fail; fi
    if [ "$got" != "$2" ]; then echo "FAIL  $1: $got, want $2"; printf '%s\n' "$out"; fails=$((fails + 1)); return; fi
    if [ -n "$3" ] && ! printf '%s' "$out" | grep -qF -- "$3"; then echo "FAIL  $1: the output lacks \"$3\""; printf '%s\n' "$out"; fails=$((fails + 1)); return; fi
    echo "PASS  $1"
}
commit() { # <sha> <parents> <login> <name> <email> <message, \n for a line break>
    printf '{"sha":"%s","parents":[%s],"author":{"login":"%s"},"commit":{"author":{"name":"%s","email":"%s"},"message":"%s"}}' "$1" "$2" "$3" "$4" "$5" "$6"
}
P1='{"sha":"p"}'
expect "a signed commit" pass "" <<EOF2
[$(commit aaaaaaaa1 "$P1" alice "Alice A" alice@example.com "Fix the thing\n\nBody.\n\nSigned-off-by: Alice A <alice@example.com>")]
EOF2
expect "an unsigned commit" fail "bbbbbbbb" <<EOF2
[$(commit bbbbbbbb1 "$P1" bob "Bob B" bob@example.com "Add a feature\n\nNo trailer here.")]
EOF2
expect "signed by somebody else" fail "cccccccc" <<EOF2
[$(commit cccccccc1 "$P1" bob "Bob B" bob@example.com "Change\n\nSigned-off-by: Alice A <alice@example.com>")]
EOF2
expect "the address in another letter case, and spaces after it" pass "" <<EOF2
[$(commit dddddddd1 "$P1" carol "Carol C" Carol@Example.COM "Change\n\nsigned-off-by: Carol C <carol@example.com>  ")]
EOF2
expect "two sign-offs, the author's among them" pass "" <<EOF2
[$(commit eeeeeeee1 "$P1" dave "Dave D" dave@example.com "Change\n\nSigned-off-by: Alice A <alice@example.com>\nSigned-off-by: Dave D <dave@example.com>")]
EOF2
expect "a merge commit is not asked" pass "" <<EOF2
[$(commit ffffffff1 "$P1,$P1" erin "Erin E" erin@example.com "Merge branch main into topic")]
EOF2
expect "a bot's commit is not asked" pass "" <<EOF2
[$(commit 99999999a "$P1" "dependabot[bot]" "dependabot[bot]" 49699333+dependabot[bot]@users.noreply.github.com "deps: bump something")]
EOF2
expect "one bad commit among good ones, over two pages" fail "bbbbbbbb" <<EOF2
[$(commit aaaaaaaa1 "$P1" alice "Alice A" alice@example.com "One\n\nSigned-off-by: Alice A <alice@example.com>")]
[$(commit bbbbbbbb1 "$P1" bob "Bob B" bob@example.com "Two"),$(commit eeeeeeee1 "$P1" dave "Dave D" dave@example.com "Three\n\nSigned-off-by: Dave D <dave@example.com>")]
EOF2
expect "the words in the middle of a line do not count" fail "abababab" <<EOF2
[$(commit abababab1 "$P1" frank "Frank F" frank@example.com "Change\n\nI will add Signed-off-by: Frank F <frank@example.com> later")]
EOF2
expect "a message that tries to be shell is only text" fail "cdcdcdcd" <<EOF2
[$(commit cdcdcdcd1 "$P1" mallory "Mallory" m@example.com "\$(touch /tmp/check-dco-must-not-exist) \`id\`; echo")]
EOF2
[ ! -e /tmp/check-dco-must-not-exist ] || { echo "FAIL  a commit message was evaluated"; fails=$((fails + 1)); }
expect "no commits at all" pass "" <<EOF2
[]
EOF2
if [ "$fails" -eq 0 ]; then echo "check-dco self-test: all passed"; else echo "check-dco self-test: $fails FAILED"; exit 1; fi
