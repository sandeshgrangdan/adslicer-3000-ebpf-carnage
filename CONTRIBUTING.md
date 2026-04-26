# Contributing to adblocker

Thanks for considering a contribution. This project is small and the
review bar is high — we'd rather have a few well-written changes than
many half-finished ones.

## Ground rules

- **Open an issue first** for non-trivial changes (new features, public
  API changes, config-format changes). For bug fixes and docs, a PR
  is fine.
- **One change per PR.** A bug fix and a refactor in the same PR is
  two PRs.
- **No regressions allowed.** Every PR must pass `make test` and
  `make lint` locally before review.
- **Match the existing style.** See [code style](#code-style).
- **Small commits, descriptive messages.** Imperative mood, ≤72 chars
  for the subject. Body explains *why*, not *what*.

## Local development

### Prerequisites

```sh
# Debian/Ubuntu
sudo apt install -y clang llvm libbpf-dev linux-tools-common \
                    linux-tools-generic linux-tools-$(uname -r) \
                    make golang-go

# Rust toolchain
rustup component add clippy rustfmt
```

### First build

```sh
make deps           # installs bpf2go
make vmlinux        # writes bpf/vmlinux.h from the running kernel
make                # generate + build  →  ./adblockerctl

# TUI
cd tui && cargo build --release
```

### Run the test suite

```sh
make test                                 # Go: hash + lists
cd tui && cargo test                      # Rust
cd tui && cargo clippy --all-targets -- -D warnings
cd tui && cargo fmt --check
```

### Run with verbose logging

```sh
sudo ./adblockerctl daemon --config configs/adblocker.yaml
# or watch live events from a running systemd unit
journalctl -u adblocker -f
```

### Iterate on the BPF C code

```sh
# After editing bpf/*.c or bpf/*.h:
make generate                                 # rebuilds adblocker_bpfel.{go,o}
sudo ./adblockerctl daemon -c configs/adblocker.yaml
```

If the verifier rejects the program you'll see a multi-line dump in
the daemon log — read it bottom-up; the last "math between …" / "R0 !=
…" line is usually the culprit. Common fixes:

- Add a `data_end` recheck after every `p++`.
- Tighten the `#pragma unroll` bound.
- Replace a variable read of `len` with a constant.

## Code style

### Go

- `gofmt`-clean (CI enforces).
- `goimports`-clean (CI enforces).
- `golangci-lint run` clean (CI enforces, uses `.golangci.yml`).
- Default to **no comments**. Only add one when *why* is non-obvious.
- Errors wrapped with `%w` so the chain is preserved for `errors.As`.

### Rust

- `cargo fmt` clean (CI enforces, uses `rustfmt.toml`).
- `cargo clippy --all-targets -- -D warnings` clean.
- Use `anyhow::Result` for top-level error flow, `thiserror` for
  library-style typed errors when needed.

### BPF C

- Match the verifier-friendly patterns documented in
  [docs/ARCHITECTURE.md §4](docs/ARCHITECTURE.md#4-kernel-programs-in-depth).
- Every loop has a fixed `#pragma unroll` upper bound.
- Recheck `data_end` after every pointer advance.

## Adding a list source

1. Implement a parser in `internal/lists/` if the format isn't already
   supported (`hosts`, `adblock`, `domain`).
2. Add a `Format` constant + a case to `Parse()`.
3. Add tests with realistic snippets of the format.
4. Document the format in [docs/INSTALL.md → Updating the upstream
   blocklists](docs/INSTALL.md#updating-the-upstream-blocklists).

## Releasing

See [docs/RELEASING.md](docs/RELEASING.md). Maintainers cut releases
by tagging `vX.Y.Z`; CI does the rest.

## Reporting security issues

**Don't open a public issue.** See [SECURITY.md](SECURITY.md) for the
private disclosure process.

## License

By contributing you agree that your contributions are licensed under
the [MIT License](LICENSE).
