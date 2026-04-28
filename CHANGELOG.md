# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `systemd/adblocker.service` now grants `CAP_PERFMON` in addition to
  `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_SYS_RESOURCE`. Without
  `CAP_PERFMON` the kernel verifier on Linux 5.8+ treats the loader
  as unprivileged for pointer-ALU checks and rejects the program with
  `pointer arithmetic with it prohibited for !root`, even at UID 0.
  Surfaces as `adblocker.service: Failed with result 'exit-code'` on
  `systemctl start adblocker` (reported on Ubuntu 24).
- `bpf/parsers.h::parse_qname` rewritten as a single MAX_QNAME-bounded
  flat unroll over a state machine (length-byte vs content-byte)
  instead of nested `MAX_LABELS × 63` loops. The old shape compiled
  fine but the kernel verifier on Linux 6.8 lost per-pointer bounds
  proofs through the inner unroll because clang created fresh
  packet-pointer ids per iteration, causing `invalid access to
  packet, off=N size=1, R4 offset is outside of the packet` at load
  time. The flat loop uses a single packet-pointer base with constant
  per-iteration offsets, which the verifier can prove. Output is
  byte-identical to the old implementation for any valid DNS query.

## [0.1.0] — 2026-04-27

### Added

- Initial public release.
- Kernel programs: TC egress + XDP ingress, attached on every non-loopback up
  interface; drops outbound DNS / TLS to blocklisted domains.
- FNV-1a 64-bit hashing, byte-identical between kernel C and Go.
- Suffix walk in the kernel (bounded to 6 labels) so a single entry covers
  all subdomains.
- Four pinned BPF maps under `/sys/fs/bpf/adblocker/`: `blocklist`,
  `ip_blocklist` (LPM trie), `stats` (per-CPU array), `events` (ring buffer).
- Daemon goroutines: list refresher (24h ticker + SIGHUP), expiry reaper
  (60s ticker), event reader (logs `BLOCK[DNS] s -> d (qname)`).
- CLI: `daemon`, `block`, `unblock`, `temp-block`, `allow`, `list`, `stats`,
  `update`.
- List ingestion: 3 default sources (StevenBlack hosts, OISD, EasyPrivacy)
  via three parsers (`hosts`, `adblock`, `domain`); strict regex
  validation; `BatchUpdate` in chunks of 4096.
- Static `static_block` config knob to block well-known DoH/DoT endpoints.
- Allowlist file with `ALLOW` flag override.
- Ratatui TUI (`adblocker-tui`) with four views (Dashboard / Blocklist /
  Allowlist / Events), shells out to `adblockerctl`, supports
  `--ssh user@host` for remote management from macOS.
- systemd unit with `CAP_BPF + CAP_NET_ADMIN + CAP_SYS_RESOURCE`,
  `ProtectSystem=strict`, `ReadWritePaths=/sys/fs/bpf`. (`CAP_PERFMON`
  added in [Unreleased]; v0.1.0 itself ships without it.)
- Docs: `README.md`, `docs/INSTALL.md`, `docs/TUI.md`,
  `docs/ARCHITECTURE.md`, `docs/PRODUCTION.md`, `docs/RELEASING.md`.
- CI: GitHub Actions for build + test + lint + security scans (CodeQL,
  govulncheck, cargo-audit).
- Release pipeline (GoReleaser): `linux/{amd64,arm64}` binaries +
  `.deb` + `.rpm` + GHCR container image; Rust TUI built for
  `linux/{amd64,arm64}` + `darwin/{amd64,arm64}`.

[Unreleased]: https://github.com/sandeshgrangdan/adslicer-3000-ebpf-carnage/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sandeshgrangdan/adslicer-3000-ebpf-carnage/releases/tag/v0.1.0
