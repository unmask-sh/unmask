# tools/

Release-side helpers for assembling and publishing the unmask download
repository (= `https://unmask.sh/dl/`).

## Scripts

| File                  | Purpose                                                                 |
|-----------------------|-------------------------------------------------------------------------|
| `build-repo.sh`       | Assemble `../unmask-dl-build/` from `../dist/*.rpm / *.deb / *.apk`.    |
| `publish-repo.sh`     | `rsync` the assembled tree up to `unmask.sh:/var/www/unmask.sh/dl/`.    |
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
