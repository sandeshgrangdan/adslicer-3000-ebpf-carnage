# ebpf-adblocker

A system-wide eBPF ad/tracker blocker for Linux. Attaches to network
interfaces and drops outgoing DNS queries and TLS ClientHello packets
destined for blocked domains. Works for every browser and every app
simultaneously, with no per-application config, no proxy, no
certificate install.

## How it compares

| Approach              | Layer            | Limitation                          |
| --------------------- | ---------------- | ----------------------------------- |
| uBlock / AdBlock      | Browser          | Per-browser, MV3 nerfs it           |
| `/etc/hosts`          | Resolver         | Static, no logic, no SNI            |
| Pi-hole / NextDNS     | DNS server       | Bypassed by DoH/DoT/hardcoded IPs   |
| AdGuard desktop       | Local MITM proxy | Needs root cert, breaks pinning     |
| **ebpf-adblocker**    | Kernel packet    | No path-level/cosmetic; system-wide |

## Architecture

Three blocking layers, in order:

1. **DNS interception** on UDP/TCP port 53. Parse QNAME, FNV-1a hash,
   look up in the kernel `blocklist` map. Hit -> drop.
2. **SNI inspection** on TCP port 443. Parse TLS ClientHello, extract
   the SNI extension, hash and look up. Catches DoH, DoT, and apps
   that hardcode resolver IPs.
3. **IP/CIDR blocklist** in an LPM trie. Final backstop on both hooks.

Hooks:

- **TC egress** (`sched_cls` on the `clsact` qdisc) - primary. Outgoing
  DNS and TLS handshakes pass through here. XDP is ingress-only on most
  kernels, so TC is the right hook for blocking outbound packets.
- **XDP ingress** - secondary, IP/CIDR backstop on inbound replies.

The kernel program walks the QNAME suffix-by-suffix
(`a.b.example.com` -> `b.example.com` -> `example.com`), so a single
entry covers all subdomains. The walk is bounded to 6 labels for the
verifier.

## Requirements

- Linux **5.15+** (BTF + ring buffer)
- `clang`, `bpftool`, `make`, Go **1.21+**
- `CAP_BPF` and `CAP_NET_ADMIN` (the systemd unit grants these)

## Docs

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — deep walkthrough:
  packet flow, the three blocking layers (DNS / SNI / IP), FNV-1a +
  suffix walk, BPF map layout, list ingestion pipeline, daemon
  goroutines, comparison with other approaches, threat model.
- **[docs/INSTALL.md](docs/INSTALL.md)** — full Linux + macOS install
  & usage guide (toolchain per distro, daemon lifecycle, allowlist,
  troubleshooting).
- **[docs/TUI.md](docs/TUI.md)** — Ratatui-based interactive frontend
  (`adblocker-tui`) that manages the blocklist / allowlist / stats /
  events. Works locally on Linux or over `--ssh` from macOS.

## Build

```sh
make deps       # install bpf2go
make vmlinux    # regenerate bpf/vmlinux.h from this kernel's BTF
make            # generate + build  (writes ./adblockerctl)
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now adblocker

# optional: terminal UI (Rust)
cd tui && cargo build --release
sudo install -m 0755 target/release/adblocker-tui /usr/local/bin/adblocker-tui
```

If `clang`, `bpftool`, or `make` are missing:

| Distro         | Install                                                                     |
| -------------- | --------------------------------------------------------------------------- |
| Debian/Ubuntu  | `sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-generic make` |
| Fedora/RHEL    | `sudo dnf install clang llvm libbpf-devel bpftool make`                      |
| Arch           | `sudo pacman -S clang llvm libbpf bpf make`                                  |

BTF is provided by kernels built with `CONFIG_DEBUG_INFO_BTF=y`. Verify
with `ls /sys/kernel/btf/vmlinux`.

## Usage

```sh
sudo adblockerctl block doubleclick.net googleadservices.com
sudo adblockerctl unblock googleadservices.com
sudo adblockerctl temp-block reddit.com 2h
sudo adblockerctl allow my-cdn.example.com
sudo adblockerctl list
sudo adblockerctl stats
```

### Use case: lend a laptop, block one site for a few hours

> I lend my laptop to a friend. I want `gmail.com` blocked while they
> use it, then unblocked when I get it back. They open Chrome, Firefox,
> Mail.app - all blocked, no per-app config.

```sh
sudo adblockerctl temp-block gmail.com 4h
# ...later, when you get the laptop back...
sudo adblockerctl unblock gmail.com
```

### Smoke test

```sh
sudo adblockerctl block example.com
curl -v https://example.com   # should fail to connect
sudo adblockerctl unblock example.com
```

## Limitations / TODOs

- **IPv6** - not yet wired into the kernel programs (v2).
- **TLS SNI across TCP segments** - v1 only inspects the first segment.
  Splitting the ClientHello across two segments evades SNI matching.
- **`bpf_ktime_get_ns` is uptime, not wall-clock** - kernel-side TEMP
  expiry can't compare against an absolute time. The user-space reaper
  does the deletion every 60s.
- **Loopback** is skipped during interface auto-detect.
- **DoH/DoT** - we can't decrypt these. The default config blocks
  well-known DoH endpoint domains (`dns.google`,
  `cloudflare-dns.com`, ...) so that apps fall back to plain DNS we
  can inspect.

## Layout

```
bpf/                  # kernel C: TC egress + XDP ingress, parsers, maps
cmd/adblocker/        # CLI entrypoint
internal/loader/      # cilium/ebpf load+attach+pin lifecycle (bpf2go)
internal/hash/        # FNV-1a 64-bit, byte-identical with kernel
internal/lists/       # hosts/adblock/domain fetchers + parsers
internal/cli/         # cobra commands
configs/              # YAML config + allowlist
systemd/              # unit file
```

## License

MIT
