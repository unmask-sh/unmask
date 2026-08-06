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

A channel for handing a fix to whoever reported it, confirming it, and then
shipping the same build.  `UNMASK_CHANNEL=testing` indexes and publishes into
`/dl/testing/`; unset, everything behaves exactly as it did before.

### Publishing a build for confirmation

```sh
# Release 1 for the first attempt.  Bump it for every further attempt -- the
# reporter's update only moves if the version does, and republishing the same
# one leaves them on the broken build believing they tested the fix.
make package UNMASK_VERSION=0.1.21 UNMASK_RELEASE=1
UNMASK_CHANNEL=testing tools/build-repo.sh
UNMASK_CHANNEL=testing tools/publish-repo.sh
```

Then give the reporter one line:

```sh
sudo dnf --enablerepo=unmask-testing update unmask                        # RHEL family
sudo apt update && sudo apt install unmask=0.1.21-1                       # Debian family
sudo apk add --repository https://unmask.sh/dl/testing/apk/main unmask    # Alpine
```

Nothing else to set up: `unmask-release` already configured the channel and
left it inactive, and both channels share one signing key.

### Promoting a confirmed build

```sh
tools/promote-repo.sh --dry-run     # read it first
tools/promote-repo.sh               # copies the SAME files into the stable tree
tools/build-repo.sh                 # reindex stable
tools/publish-repo.sh               # push stable (testing is left untouched)
```

The build is copied, never rebuilt.  That is the whole point: a rebuild
produces different bytes even from identical source, because the version is
compiled into the binary, so "what you confirmed is what shipped" would stop
being literally true.  `promote-repo.sh` reads each file back after copying and
refuses outright if a name already exists in stable with different content --
two artifacts under one NVR cannot be fixed by overwriting, only by publishing
a new release number.

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
- **deb and apk pin the companion packages with the release, rpm without it.**
  rpm's `=` matches any release; dpkg and apk compare the whole string.  Get it
  wrong and the packages build cleanly and cannot be installed.
  `tools/pkgdeps-test.sh` checks all three.
- **The channel is only reachable once a release ships the `unmask-release`
  that configures it.**  Before that a reporter can still use it by hand
  (`dnf --repofrompath=...`, `apk --repository`, a manual sources.list entry).

