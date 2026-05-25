#!/usr/bin/env bash
# with-gpg-preset.sh -- export project-local GNUPGHOME + preset the signing key
# passphrase into the gpg-agent cache, then exec the rest of the argv.
#
# Used by Makefile sign-rpm / sign-* targets so a `rpm --addsign` invoked from
# a non-TTY shell (= sudo -iu apps / cron / nohup) does not deadlock on
# pinentry-tty / pinentry-curses (= both fail with 'inappropriate ioctl' in
# that environment).  build-repo.sh has the same logic inline; this file is
# the equivalent for the more granular sign-* Makefile targets.
#
# Env:
#   UNMASK_GPG_KEY_ID         required (fingerprint preferred)
#   UNMASK_GNUPGHOME          default: <repo>/../keys/gpg
#   UNMASK_GPG_PASSPHRASE     optional; if unset, prompts via read -s
#
# License: Apache 2.0

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export GNUPGHOME="${UNMASK_GNUPGHOME:-${ROOT%/repo}/keys/gpg}"

if [ -z "${UNMASK_GPG_KEY_ID:-}" ]; then
    echo "ERR: UNMASK_GPG_KEY_ID not set" >&2
    exit 1
fi

KEYGRIP=$(gpg --list-keys --with-keygrip --with-colons "$UNMASK_GPG_KEY_ID" 2>/dev/null \
    | awk -F: '$1=="grp"{print $10; exit}')
if [ -z "$KEYGRIP" ]; then
    echo "ERR: keygrip lookup failed for $UNMASK_GPG_KEY_ID under GNUPGHOME=$GNUPGHOME" >&2
    exit 1
fi

if [ -z "${UNMASK_GPG_PASSPHRASE:-}" ]; then
    printf "GPG passphrase for %s: " "$UNMASK_GPG_KEY_ID" >&2
    stty -echo 2>/dev/null
    IFS= read -r UNMASK_GPG_PASSPHRASE
    stty echo 2>/dev/null
    printf '\n' >&2
    export UNMASK_GPG_PASSPHRASE
fi

HEX=$(printf '%s' "$UNMASK_GPG_PASSPHRASE" | od -An -tx1 | tr -d ' \n')
gpg-connect-agent <<EOF >/dev/null 2>&1
PRESET_PASSPHRASE $KEYGRIP -1 $HEX
EOF

# Probe -- fail loudly here rather than deep inside rpm --addsign.
if ! echo probe | gpg --batch --pinentry-mode loopback \
        --passphrase "$UNMASK_GPG_PASSPHRASE" \
        --local-user "$UNMASK_GPG_KEY_ID" --clearsign >/dev/null 2>&1; then
    echo "ERR: GPG signing probe failed -- wrong passphrase or key absent in $GNUPGHOME" >&2
    exit 1
fi

# Unset the plaintext passphrase from the env we hand to the child process.
# The agent cache is what the child will hit; the env var is no longer needed.
unset UNMASK_GPG_PASSPHRASE

exec "$@"
