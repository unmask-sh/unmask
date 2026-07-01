<!--
Thanks for the contribution.  A few notes:

- One logical change per PR.  Split unrelated changes.
- Match the surrounding code style; admin/ uses gofmt, nginx-module/ follows
  nginx upstream style, challenge.js is plain ES5-compatible JavaScript.
- Update CHANGELOG.md under [Unreleased] (= or the active release section).
- Run `go test ./...` from admin/ before submitting.
- See CONTRIBUTING.md for the full guidelines.
-->

## What this changes

<!-- Short description of the user-facing change. -->

## Why

<!-- The motivation: bug fix, missing feature, alignment with another part
of the system, etc. -->

## How to verify

<!-- Steps a reviewer can take to confirm the change works:

  1. `make e2e-docker` (= all 16 scenarios pass)
  2. `docker run --rm alpine:latest sh -c 'apk add ...'` (= what / why)
  3. ...

-->

## Checklist

- [ ] One logical change (= split unrelated edits into separate PRs).
- [ ] gofmt clean (= `gofmt -l admin/` is empty).
- [ ] `go test ./...` passes in admin/.
- [ ] `make e2e-docker` passes locally (= for nginx / forward-auth / Apache scenarios).
- [ ] CHANGELOG.md updated under the active release.
- [ ] Docs / install page updated if the change affects the install flow.
