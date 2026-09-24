# tools/

Release-side helpers for assembling and publishing the unmask download
repository (= `https://unmask.sh/dl/`).

## Scripts

| File                  | Purpose                                                                 |
|-----------------------|-------------------------------------------------------------------------|
| `build-repo.sh`       | Assemble `../unmask-dl-build/` from `../dist/*.rpm / *.deb / *.apk`.    |
| `publish-repo.sh`     | `rsync` the assembled tree up to `unmask.sh:/var/www/unmask.sh/dl/`.    |
| `promote-repo.sh`     | Copy a confirmed testing build into the stable tree (no rebuild).       |
| `pkgdeps-test.sh`     | Install a companion package next to the core it pins, per format.       |
| `repoconf-test.sh`    | Install `unmask-release` and let each package manager read what it wrote.|
| `with-gpg-preset.sh`  | Shim that preseeds the GPG passphrase before invoking `rpm --addsign`.  |
| `Dockerfile.alpine`   | Image used by `make repo-apk` (apk-tools + abuild on Alpine 3.20).      |

## Common flows

### Full repo rebuild (rpm + deb + apk)

Requires `createrepo_c`, `apt-ftparchive`, and `apk` on the build host.  The
default Rocky 9 dev host has the first two but no `apk` / `abuild`, so the apk
stage is silently skipped — see `make repo-apk` below to regenerate the apk
index in a container.

```sh
make repo
```

Output layout:

```
../unmask-dl-build/
  rpm/{x86_64,aarch64}/{RPMS,repodata}/
  deb/dists/stable/main/binary-{amd64,arm64}/{Packages.gz,InRelease,Release.gpg}
  deb/pool/main/u/unmask/*.deb
  apk/main/{x86_64,aarch64}/{APKINDEX.tar.gz,*.apk}
  keys/{RPM-GPG-KEY-unmask,unmask.rsa.pub}
```

Pass `UNMASK_GPG_KEY_ID` to sign rpm packages + repo metadata, and
`UNMASK_RSA_PRIVKEY` for the apk index signature.

### apk-only regen (Alpine container)

`make repo-apk` runs the apk stage of `build-repo.sh` inside an Alpine 3.20
container so dev hosts without apk-tools / abuild can still produce a current
`APKINDEX.tar.gz`.  rpm/ and deb/ are left untouched.

```sh
make repo-apk
```

Requires `docker` (already a dependency of `make e2e-docker`).  Mounts:

- `<repo>/`               → `/work`     (build-repo.sh + scripts)
- `<repo>/../keys/`       → `/keys` ro  (RSA private key)
- `<repo>/../unmask-dl-build/` → `/out`     (output)

Override the signing key via `UNMASK_RSA_PRIVKEY` (path inside the container,
default `/keys/oss@unmask.sh-260509.rsa`) and `UNMASK_RSA_PUBNAME` (name written
into the `.SIGN.RSA.<pubname>` entry, default `oss@unmask.sh-260509.rsa.pub`).

Notes:
- The container runs as the host uid:gid so files under `unmask-dl-build/` stay
  writable by the host user.
- The corresponding public key is shipped to clients separately via the
  `unmask-release` package (= `/etc/apk/keys/oss@unmask.sh-260509.rsa.pub`).
  It is not part of this repo.

### Publish to `unmask.sh/dl/`

```sh
make publish              # full rsync
make publish ARGS=--dry-run
```

`apk/` is now included by default (= since v0.2 with `make repo-apk` wired in).
Set `UNMASK_PUBLISH_SKIP_APK=1` for the legacy v0.1 behavior of preserving the
remote `apk/` copy (e.g. emergency push when `make repo-apk` was not run).

### A release, end to end (`release-run.sh`)

```sh
tools/release-run.sh 0.1.40 status                       # what is done
tools/release-run.sh 0.1.40 all --notes-file NOTES.txt   # every stage, in order
tools/release-run.sh 0.1.40 sign                         # one stage, again
```

Stages: `preflight` (clean + pushed main, CI green, embedded IP-range
snapshot current, tag free) → `bump` (CHANGELOG master + Makefile + main.go +
releases.json, commit, tag) → `push` (main and the tag, explicitly; waits for
the release workflow's draft and the GHCR images) → `build` (clean worktree
at the tag, 27 packages for amd64 and arm64 + 2 binaries) → `gate` (unsigned
repo to hv1, `make distro-check`) → `sign` (sign-rpm, THEN checksums + .sig,
THEN the signed repository) → `archive` (dist/ kept as
`../unmask-dl-build/releases/vX.Y.Z/`, the newest six versions) → `registry`
→ `publish` (with its own verification; carries `releases/` up as
[unmask.sh/dl/releases/](https://unmask.sh/dl/releases/), the only place on
the site where an older version is still installable) → `github` (assets
over the draft's, body, latest, verified by download).

Each stage records itself under `../unmask-dl-build/release-state/<ver>/`
(with its log) and the next refuses to run until the one before it
finished.  The passphrase comes from `../.gpgpass` (one line, shredded once
read) or `UNMASK_GPG_PASSPHRASE`; it is never on a command line.  What the
script does not do -- the fleet, the site docs, the notes -- it prints at
the end.  `--ref HEAD` builds from HEAD instead of the tag, for a rehearsal
of the build stage.

## Stage filter

`build-repo.sh` takes an optional second argument that limits which stages run:

```sh
./tools/build-repo.sh ../unmask-dl-build all   # default = rpm + deb + apk
./tools/build-repo.sh ../unmask-dl-build rpm   # rpm stage only
./tools/build-repo.sh ../unmask-dl-build deb   # deb stage only
./tools/build-repo.sh ../unmask-dl-build apk   # apk stage only (used by make repo-apk)
```

Stages that are not active leave their existing output untouched (= no
`rm -rf`).

## The testing channel

A channel for handing a fix to whoever reported it -- and our own fleet --
before a release.  `UNMASK_CHANNEL=testing` indexes and publishes into
`/dl/testing/`; unset, everything behaves exactly as it did before.

### Publishing a pre-release

```sh
tools/testing-run.sh 0.1.46 rc1      # build -> sign -> publish -> read back
```

A pre-release of 0.1.46 is packaged as `0.1.46-0.1.rc1` (rpm, deb) and
`0.1.46_rc1-r0` (apk), so it sorts above every earlier release and below
`0.1.46-1`: an ordinary update never takes a node back to the previous release,
and the final replaces it on its own.  The next attempt is `rc2`, never a
rebuild of `rc1` -- a reporter's update only moves if the version does, and two
files under one NVR cannot be fixed.  `testing-run.sh` refuses a number already
used, and an rc of a version stable already reached.  `UNMASK_PRERELEASE` in the
Makefile has how each format spells it.

Then give the reporter one line:

```sh
sudo dnf --enablerepo=unmask-testing update unmask                   # RHEL family
sudo apt update && sudo apt install unmask=0.1.46-0.1.rc1            # Debian family, + each unmask-* package they have
sudo apk upgrade --repository https://unmask.sh/dl/testing/apk/main  # Alpine
```

Nothing else to set up: `unmask-release` already configured the channel and
left it inactive, and both channels share one signing key.

### The release after it

A pre-release is never promoted.  The final is built, gated and signed by
`tools/release-run.sh` as `<version>-1`, a name no testing build can take, and
`promote-repo.sh` refuses anything whose Release is below 1.  (It still copies a
confirmed *release-numbered* testing build into stable byte for byte -- the way
this channel worked before pre-releases -- and everything below about promotion
applies to that case.)

### Before publishing anything

```sh
make verify-packages     # also gate 1/5 of `make distro-check`
```

A green build says nothing about whether the packages can be installed.  Three
failures in one evening proved it, each reporting success at build time:

- deb and apk pinned the core without its release, so the companion packages
  could not be installed alongside it (`held broken packages`).
- a backtick inside a **comment** in the postinstall ran `dnf` and pasted its
  output into `/etc/yum.repos.d/unmask.repo`, so the whole file -- stable repo
  included -- stopped parsing.  The package installed reporting success.
- the Makefile's own `ls` patterns still had the release hardcoded, so a
  correct build exited non-zero.

All three are invisible until a package manager reads the result, so
`verify-packages` asks one: install the packages in a container, per format,
and check what the tools say.

### Things that bite

- **Reindexing stable re-copies `dist/`, not the promoted files.**  Every stage
  regenerates its subtree from `dist/`, so after a promotion the artifacts that
  actually land in stable come from `dist/` -- and a rebuilt `dist/` (same
  version, different file: the binary embeds build ids) would ship something
  nobody confirmed, under the exact NVR the reporter quoted, without tripping
  `promote-repo.sh`'s collision check.  `build-repo.sh` therefore compares
  `dist/` against the testing tree before touching anything -- payload digest
  for rpm (indexing re-signs them, so bytes never match twice), bytes for deb
  and apk -- and refuses on a mismatch.  Replacing a confirmed build on
  purpose requires saying so: `UNMASK_ALLOW_TESTING_MISMATCH=1`.
- **`publish-repo.sh` runs `--delete-after`.**  Publishing stable excludes
  `testing/` explicitly; without that it deletes the remote testing tree out
  from under whoever is confirming a fix.  Each channel syncs only its own
  subtree.
- **The apt pin needs origin AND suite.**  `o=unmask` alone demotes stable too
  and ordinary upgrades stop; `a=testing` alone catches Debian's own testing
  suite.  Written by the `unmask-release` postinstall, verified against a real
  two-suite repo.
- **The apk index is built in a container.**  This host has no apk-tools or
  abuild, and `build-repo.sh` here skips the apk stage while keeping whatever
  index was there -- so through rc1 and rc2 the testing apk index still listed
  0.1.24, and the post-publish check passed because it accepted any unmask it
  could install.  `testing-run.sh` runs `make repo-apk` (as the release run does
  in its gate), and `verify-published.sh` now requires deb and apk to install
  the very version the rpm check did.
- **`apk add` changes nothing about a package that is already installed.**  A
  reporter already has unmask, so `apk add --repository …` left them on the
  release they had; `apk upgrade --repository …` moves them, and the companion
  packages with their exact pins.
- **deb and apk pin the companion packages with the release, rpm without it.**
  rpm's `=` matches any release; dpkg and apk compare the whole string.  Get it
  wrong and the packages build cleanly and cannot be installed.
  `tools/pkgdeps-test.sh` checks all three.
- **The channel is only reachable once a release ships the `unmask-release`
  that configures it.**  Before that a reporter can still use it by hand
  (`dnf --repofrompath=...`, `apk --repository`, a manual sources.list entry).

