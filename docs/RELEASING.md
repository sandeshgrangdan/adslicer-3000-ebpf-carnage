# Releasing `ebpf-adblocker`

Maintainer-only document. If you're not cutting a release, you can
skip it.

## Versioning

Semver: `MAJOR.MINOR.PATCH`.

- **MAJOR** — breaking changes to the YAML config schema, the BPF
  map layout, or the CLI surface.
- **MINOR** — new features, new subcommands, new sources.
- **PATCH** — bug fixes, doc updates, dependency bumps with no
  behavior change.

Pre-release suffixes: `-rc.1`, `-rc.2`, … for release candidates.
GoReleaser automatically marks tags containing `-` as prereleases on
GitHub.

## Release cadence

- **Patch**: as soon as a fix lands. Same day if security.
- **Minor**: when there's a meaningful chunk of new functionality.
- **Major**: only when a breaking change is unavoidable. We do
  **not** rev major just because time has passed.

## Pre-release checklist

```sh
# you should be on a clean checkout of main
git fetch origin
git checkout main
git pull --ff-only

# everything green locally?
make test
cd tui && cargo test --locked && cargo clippy --all-targets --locked -- -D warnings && cd ..
golangci-lint run ./...

# CI green on main?
# https://github.com/ebpf-adblocker/ebpf-adblocker/actions

# CHANGELOG.md has an entry under [Unreleased]?
$EDITOR CHANGELOG.md

# any open security advisories that should ride along?
# https://github.com/ebpf-adblocker/ebpf-adblocker/security/advisories
```

## Cutting the tag

```sh
VER=v0.2.0   # set me

# 1. Move the [Unreleased] block in CHANGELOG.md under [{{VER}}].
$EDITOR CHANGELOG.md

# 2. Commit the changelog rewrite (no other changes in this commit).
git add CHANGELOG.md
git commit -m "chore: prepare ${VER} changelog"
git push origin main

# 3. Tag and push. GoReleaser fires on tag.
git tag -a "${VER}" -m "Release ${VER}"
git push origin "${VER}"
```

## What CI does on tag push

[`.github/workflows/release.yml`](../.github/workflows/release.yml):

1. Installs clang/llvm/libbpf-dev/bpftool on the runner.
2. Regenerates `bpf/vmlinux.h` from the runner's BTF.
3. Runs `go generate ./...` (bpf2go → embeds the .o into the binary).
4. Runs **GoReleaser**:
   - cross-compiles `adblockerctl` for `linux/amd64` + `linux/arm64`
   - builds `.deb` and `.rpm` packages with nfpm
   - builds and pushes the multi-arch container image to
     `ghcr.io/ebpf-adblocker/ebpf-adblocker:{vX.Y.Z, latest}`
   - generates `SHA256SUMS`
   - publishes a GitHub Release with auto-generated notes
5. **Rust matrix job** builds `adblocker-tui` for:
   - `linux/{amd64, arm64}`
   - `darwin/{amd64, arm64}` (Intel + Apple Silicon)
   - …and uploads each tarball + `.sha256` to the same GitHub Release.

### What you should see when it succeeds

- A new Release at
  `https://github.com/ebpf-adblocker/ebpf-adblocker/releases/tag/<VER>`
  with: `.tar.gz` per arch, `.deb`, `.rpm`, `SHA256SUMS`, plus 4 TUI
  tarballs (linux x2, darwin x2).
- A new image at `ghcr.io/ebpf-adblocker/ebpf-adblocker:<VER>` and
  `:latest`, multi-arch (`docker manifest inspect` shows both).

## Post-release verification

```sh
# 1. Pull the package on a clean Linux box.
curl -L -o ab.deb \
  https://github.com/ebpf-adblocker/ebpf-adblocker/releases/download/${VER}/ebpf-adblocker_linux_amd64.deb
sudo dpkg -i ab.deb
sudo systemctl enable --now adblocker
adblockerctl --version       # confirms the right hash + tag

# 2. Pull the container.
docker pull ghcr.io/ebpf-adblocker/ebpf-adblocker:${VER}
docker run --rm ghcr.io/ebpf-adblocker/ebpf-adblocker:${VER} --version

# 3. Pull a TUI tarball.
curl -L -o tui.tgz \
  https://github.com/ebpf-adblocker/ebpf-adblocker/releases/download/${VER}/adblocker-tui-linux-amd64.tar.gz
tar xzf tui.tgz && ./adblocker-tui --version
```

If any of those fail, **don't delete the release** — that breaks
mirrors and dependabot. Instead, ship a `${VER}.1` patch with the
fix.

## Hotfix process

```sh
# 1. Branch from the bad tag.
git fetch --tags
git checkout -b hotfix/v0.2.1 v0.2.0

# 2. Cherry-pick the fix from main (or write it on this branch).
git cherry-pick <sha>

# 3. Bump CHANGELOG.md ([0.2.1] section).
$EDITOR CHANGELOG.md
git commit -am "chore: prepare v0.2.1 changelog"

# 4. Tag, push, let CI release.
git tag -a v0.2.1 -m "Release v0.2.1"
git push origin hotfix/v0.2.1 v0.2.1

# 5. Backport the fix into main.
git checkout main
git cherry-pick <sha>
git push origin main
```

## Manual release fallback

If GoReleaser fails on the runner, you can run it locally:

```sh
# Need: docker, goreleaser, GH PAT with packages:write + contents:write
export GITHUB_TOKEN=ghp_***
goreleaser release --clean
```

Don't normalize this — investigate the CI failure and re-run there.

## Yanking a release

GitHub Releases can be deleted but tags are forever. If a release
ships with a serious bug:

1. Mark the GitHub Release as a "draft" with a note pointing at the
   replacement.
2. Ship `vN.M.K+1` with the fix.
3. Update `latest` in GHCR (re-tag the new image).
4. Notify users in `CHANGELOG.md` and (for security issues) via
   GitHub Security Advisory.

## Coordinated security releases

For embargoed CVEs:

1. Develop the fix on a private fork or on a private GitHub Security
   Advisory branch.
2. Pre-stage release artifacts on a draft GitHub Release.
3. Publish the advisory + the release in the same minute.
4. Push the fix commit + the tag in the same `git push`.

See [SECURITY.md](../SECURITY.md) for the disclosure timeline.
