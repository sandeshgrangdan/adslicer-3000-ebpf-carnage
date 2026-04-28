# Installation & usage — `adblocker`

> **Running this on more than one host, in production, or behind an
> on-call rotation?** Read [PRODUCTION.md](PRODUCTION.md) first — it
> covers deployment topologies, capacity planning, monitoring,
> hardening, and the upgrade/rollback playbook. This document is the
> single-host install + everyday CLI guide.

This guide covers:

- [Linux install (build from source)](#linux-install-build-from-source)
- [Linux quick-install (prebuilt binary)](#linux-quick-install-prebuilt-binary)
- [macOS — what works, what doesn't](#macos--what-works-what-doesnt)
- [Daemon usage](#daemon-usage)
- [Day-to-day CLI](#day-to-day-cli)
- [Updating the upstream blocklists](#updating-the-upstream-blocklists)
- [Logs & observability](#logs--observability)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)

---

## Linux install (build from source)

### 1. Prerequisites

| What                                | Why                                                 |
| ----------------------------------- | --------------------------------------------------- |
| Linux kernel **5.15+**              | BTF + ring buffer support                           |
| `CONFIG_DEBUG_INFO_BTF=y`           | needed for CO-RE / `vmlinux.h`                      |
| `clang`, `llvm-strip`               | bpf2go compiles `bpf/adblocker.bpf.c`               |
| `bpftool`                           | dumps kernel BTF into `bpf/vmlinux.h`               |
| `make`                              | runs the Makefile targets                           |
| Go **1.21+**                        | builds the user-space binary                        |
| `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN` + `CAP_SYS_RESOURCE` | runtime capabilities (the systemd unit grants them). `CAP_PERFMON` is what unlocks the verifier's pointer-arithmetic checks on Linux 5.8+. |

Verify BTF is available:

```sh
ls /sys/kernel/btf/vmlinux
```

If the file is missing, your kernel was built without BTF info — install a
distro kernel that has it (every modern Ubuntu/Fedora/Debian/Arch kernel
does), or rebuild with `CONFIG_DEBUG_INFO_BTF=y`.

### 2. Install the toolchain

```sh
# Debian / Ubuntu / Pop!_OS / Mint
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-tools-common \
                    linux-tools-generic linux-tools-$(uname -r) \
                    make golang-go

# Fedora / RHEL / Rocky / Alma
sudo dnf install -y clang llvm libbpf-devel bpftool make golang

# Arch / Manjaro
sudo pacman -S clang llvm libbpf bpf make go

# openSUSE
sudo zypper install -y clang llvm libbpf-devel bpftool make go
```

WSL2 users on Windows: install the same packages inside your WSL distro.
Note that WSL2's network stack is virtual; eBPF will see the WSL
interface, not the Windows host's traffic.

### 3. Clone & build

```sh
git clone https://github.com/<your-fork>/adblocker.git
cd adblocker

make deps           # installs bpf2go (one-time)
make vmlinux        # writes bpf/vmlinux.h from the running kernel's BTF
make                # = make generate + make build  →  ./adblockerctl
```

`make` succeeds when you see `./adblockerctl` in the project root.

### 4. Install system-wide

```sh
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now adblocker
```

This drops:

| File                                        | Owner / mode |
| ------------------------------------------- | ------------ |
| `/usr/local/bin/adblockerctl`               | `root:root 0755` |
| `/etc/adblocker/adblocker.yaml`             | `root:root 0644` |
| `/etc/adblocker/allowlist.txt`              | `root:root 0644` |
| `/etc/systemd/system/adblocker.service`     | `root:root 0644` |
| `/sys/fs/bpf/adblocker/{blocklist,ip_blocklist,stats,events}` | (created at runtime) |

Verify:

```sh
systemctl status adblocker
journalctl -u adblocker -f       # live logs
sudo adblockerctl stats          # counters from the kernel
```

---

## Linux quick-install (prebuilt binary)

If you just want to run a release tarball:

```sh
curl -LO https://github.com/<your-fork>/adblocker/releases/latest/download/adblocker-linux-amd64.tar.gz
tar xzf adblocker-linux-amd64.tar.gz
cd adblocker-*

sudo install -m 0755 adblockerctl /usr/local/bin/adblockerctl
sudo install -d /etc/adblocker
sudo install -m 0644 configs/adblocker.yaml /etc/adblocker/adblocker.yaml
sudo install -m 0644 configs/allowlist.txt  /etc/adblocker/allowlist.txt
sudo install -m 0644 systemd/adblocker.service /etc/systemd/system/adblocker.service
sudo systemctl daemon-reload && sudo systemctl enable --now adblocker
```

Releases ship the kernel ELF embedded in the binary — no `make generate`
needed at install time, but the kernel must still be 5.15+ with BTF.

---

## macOS — what works, what doesn't

**The eBPF daemon does not run on macOS.** eBPF is a Linux kernel
subsystem; macOS has no equivalent. There is **no path** to system-wide
DNS/TLS dropping at the packet level on macOS using this codebase.

Two practical ways to use this project on a Mac:

### Option A — Remote management (recommended)

Run the daemon on a Linux machine you own (homelab, NAS, EdgeRouter,
old laptop, Raspberry Pi 4+, cloud VM) and manage it from your Mac.

- The TUI (see [TUI.md](TUI.md)) supports a `--ssh user@host` mode that
  invokes `adblockerctl` over SSH instead of locally. Your Mac never
  needs eBPF.
- Point your Mac's DNS / DHCP at the Linux box and route relevant
  traffic through it (e.g. by using it as your home router, or by
  pointing macOS DNS to it). For traffic that doesn't go through the
  Linux box, this project can't see it.

```sh
# From your Mac
brew install rustup-init && rustup-init -y       # toolchain
cd tui && cargo build --release
./target/release/adblocker-tui --ssh user@linux-box.lan
```

### Option B — Build only the userspace tooling for inspection

You can `go build ./cmd/adblocker` on macOS — the binary will compile,
but `daemon`, `block`, `stats`, etc. will fail at runtime with
`BPF object not generated yet` (the stub) or `operation not supported`
(no eBPF). This is useful only for testing the CLI shape locally.

```sh
brew install go
git clone https://github.com/<your-fork>/adblocker.git
cd adblocker
go build ./cmd/adblocker      # builds, but won't actually block on Mac
```

### Honest macOS alternatives

If you want native macOS blocking and don't have a Linux box:

| Tool                      | What it does                          |
| ------------------------- | ------------------------------------- |
| `/etc/hosts`              | Static name → 0.0.0.0 mapping. No SNI, no logic. |
| **NextDNS** client        | DoH-based filtering with their lists. |
| **AdGuard for Mac**       | Local MITM proxy. Needs a root cert installed. |
| **Little Snitch**         | Per-app outbound firewall. Manual rules. |
| **PF** (`pf.conf`)        | Native packet filter; can drop by IP. No name-based matching. |

These are different products with different tradeoffs — none of them
gives you the "kernel packet drop on hashed domain" behavior of this
project.

---

## Daemon usage

### YAML config (`/etc/adblocker/adblocker.yaml`)

```yaml
interfaces: []                                 # empty = auto-detect non-loopback up ifaces
allowlist_file: /etc/adblocker/allowlist.txt
update_interval_hours: 24
cleanup_interval_seconds: 60

sources:
  - { name: stevenblack-unified, url: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts, format: hosts }
  - { name: oisd-small,          url: https://small.oisd.nl/domainswild,                                format: domain }
  - { name: easyprivacy,         url: https://easylist.to/easylist/easyprivacy.txt,                     format: adblock }

static_block:
  - dns.google
  - cloudflare-dns.com
  - mozilla.cloudflare-dns.com
```

After editing the config, restart the daemon:

```sh
sudo systemctl restart adblocker
```

### Pinning to specific interfaces

Auto-detection grabs every non-loopback interface that's up. To attach
only to one (e.g. your physical NIC and skip a docker bridge), enumerate
explicitly:

```yaml
interfaces:
  - eth0
  - wlan0
```

### Allowlist file (`/etc/adblocker/allowlist.txt`)

One domain per line, `#` comments allowed. Entries here override the
upstream blocklists — they get the `ALLOW` flag in the kernel map,
which beats `BLOCK`.

```text
# domains that must always pass, even if a feed lists them
my-cdn.example.com
internal.corp.example
```

---

## Day-to-day CLI

```sh
# permanent block
sudo adblockerctl block doubleclick.net googleadservices.com

# remove a block
sudo adblockerctl unblock googleadservices.com

# block for a fixed duration (m / h supported)
sudo adblockerctl temp-block reddit.com 2h
sudo adblockerctl temp-block youtube.com 30m

# allowlist override (wins over upstream feeds)
sudo adblockerctl allow my-cdn.example.com

# inspect (first 50 entries with hash + flags)
sudo adblockerctl list

# kernel counters (summed across CPUs)
sudo adblockerctl stats

# trigger a fresh fetch of upstream lists
sudo adblockerctl update      # = systemctl restart adblocker (sends SIGHUP equivalent)
```

### Smoke test

```sh
# pick a domain that isn't already on a feed
sudo adblockerctl block example.com
curl -v https://example.com           # should fail to connect
sudo adblockerctl unblock example.com
curl -v https://example.com           # should succeed again
```

### "Lend the laptop" use case

> I'm lending my laptop to a friend for the afternoon and don't want
> them on `gmail.com`. Every browser. No per-app config.

```sh
sudo adblockerctl temp-block gmail.com 4h
# ... when you get the laptop back ...
sudo adblockerctl unblock gmail.com
```

---

## Updating the upstream blocklists

The daemon refreshes lists every `update_interval_hours` (default 24h).
To force an immediate refresh:

```sh
sudo adblockerctl update
```

This sends a SIGHUP-equivalent (today: `systemctl restart adblocker`)
and the daemon re-fetches every source in the YAML config, parses,
deduplicates, and bulk-inserts into the kernel `blocklist` map in
chunks of 4096.

You can also edit the YAML to add/remove a source:

```yaml
sources:
  - { name: my-list, url: https://example.com/my-blocklist.txt, format: domain }
```

Three formats are supported:

| Format    | Looks like                                  |
| --------- | ------------------------------------------- |
| `hosts`   | `0.0.0.0 ads.example.com` (one per line)    |
| `adblock` | `\|\|ads.example.com^` (EasyList style)     |
| `domain`  | `ads.example.com` (one per line)            |

---

## Logs & observability

```sh
# live blocking events (BLOCK[DNS] / BLOCK[SNI] / BLOCK[IP])
journalctl -u adblocker -f

# kernel counter snapshot
sudo adblockerctl stats

# show what's currently blocked
sudo adblockerctl list
```

Sample event line:

```text
2026-04-25 12:34:56.789012 BLOCK[DNS] 192.168.1.42 -> 8.8.8.8 (doubleclick.net)
```

---

## Uninstall

```sh
sudo systemctl disable --now adblocker
sudo rm -f  /etc/systemd/system/adblocker.service
sudo rm -rf /etc/adblocker
sudo rm -f  /usr/local/bin/adblockerctl
sudo rm -rf /sys/fs/bpf/adblocker      # detaches and frees the maps
sudo systemctl daemon-reload
```

---

## Troubleshooting

### `failed to load BPF objects: ... operation not supported`

You're on a kernel without BPF or BTF. Confirm:

```sh
uname -r                              # need 5.15+
ls /sys/kernel/btf/vmlinux            # must exist
zgrep BTF /proc/config.gz             # CONFIG_DEBUG_INFO_BTF=y
```

### `BPF object not generated yet — run \`make generate\``

You ran `go build ./...` directly on a checkout that has never had
`make generate` executed. The userspace stub is in place so the package
compiles. Run:

```sh
make deps
make vmlinux
make
```

### `attach tc egress on eth0: ... permission denied`

The daemon needs `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, and
`CAP_SYS_RESOURCE`. The systemd unit grants all four. If you're
running by hand, use `sudo` or run as root.

### `verifier rejected program: ... pointer arithmetic with it prohibited for !root`

Despite the message, this isn't a UID issue — the kernel verifier
treats anything without **`CAP_PERFMON`** as `!root` for relaxed
pointer-ALU checks (Linux 5.8+). If you see this on `systemctl start
adblocker`, your unit file is missing `CAP_PERFMON` from
`AmbientCapabilities` / `CapabilityBoundingSet`. Either upgrade to a
package that includes the fix, or `systemctl edit adblocker` and add:

```ini
[Service]
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_RESOURCE
```

Then `systemctl daemon-reload && systemctl restart adblocker`.

### Some traffic still gets through

Common reasons:

- The app is using **DoH/DoT** to a domain not in your blocklist. Add
  its endpoint domain to `static_block` in the YAML to push the app
  back onto plain DNS.
- The app is connecting to an IP **directly** (no DNS, no SNI). Add
  the IP/CIDR to the LPM trie via the daemon's IP-blocklist config.
- The TLS ClientHello was **split across TCP segments**. v1 only
  inspects the first segment — see [README.md → Limitations](../README.md).
- You're on **IPv6** and the kernel program currently only handles
  IPv4. v2 TODO.

### High CPU on the userspace side

The daemon iterates the blocklist every `cleanup_interval_seconds` for
the expiry reaper. With ~1M entries and a 60s cycle this is cheap, but
on slow hardware bump it to 300s.
