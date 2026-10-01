# tools/

Release-side helpers for assembling and checking the unmask download
repository (= `https://unmask.sh/dl/`).  Publishing it, and running a release
end to end, is done by the maintainers' release tooling, which is not part of
this repository; the scripts here build and check the trees it publishes.

## Scripts

| File                  | Purpose                                                                 |
|-----------------------|-------------------------------------------------------------------------|
| `build-repo.sh`       | Assemble `../unmask-dl-build/` from `../dist/*.rpm / *.deb / *.apk`.    |
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

The release tooling builds, signs and publishes a pre-release.  One of 0.1.46
is packaged as `0.1.46-0.1.rc1` (rpm, deb) and
`0.1.46_rc1-r0` (apk), so it sorts above every earlier release and below
`0.1.46-1`: an ordinary update never takes a node back to the previous release,
and the final replaces it on its own.  The next attempt is `rc2`, never a
rebuild of `rc1` -- a reporter's update only moves if the version does, and two
files under one NVR cannot be fixed.  The tooling refuses a number already
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
the release tooling as `<version>-1`, a name no testing build can take, and
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
- **The apt pin needs origin AND suite.**  `o=unmask` alone demotes stable too
  and ordinary upgrades stop; `a=testing` alone catches Debian's own testing
  suite.  Written by the `unmask-release` postinstall, verified against a real
  two-suite repo.
- **The apk index is built in a container.**  This host has no apk-tools or
  abuild, and `build-repo.sh` here skips the apk stage while keeping whatever
  index was there -- so through rc1 and rc2 the testing apk index still listed
  0.1.24, and the post-publish check passed because it accepted any unmask it
  could install.  A pre-release now runs `make repo-apk` (as the release does
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

