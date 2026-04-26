# Running `adblocker` in production

This is the operator's playbook. If you're a single user installing
on a laptop, [docs/INSTALL.md](INSTALL.md) is shorter and probably
all you need. This document is for fleets of more than one host,
24/7 deployments, and shared on-call rotations.

## Table of contents

1. [Deployment topologies](#1-deployment-topologies)
2. [Installation methods](#2-installation-methods)
3. [Configuration management](#3-configuration-management)
4. [Capacity planning](#4-capacity-planning)
5. [Monitoring & alerting](#5-monitoring--alerting)
6. [Logging & log retention](#6-logging--log-retention)
7. [Upgrade procedure](#7-upgrade-procedure)
8. [Backup & recovery](#8-backup--recovery)
9. [Hardening](#9-hardening)
10. [Performance tuning](#10-performance-tuning)
11. [Troubleshooting playbook](#11-troubleshooting-playbook)

---

## 1. Deployment topologies

Pick one. They're not mutually exclusive — you can mix.

### 1a. **Per-host** (the simple case)

Install the daemon on every machine you want filtered. Each host
filters its own traffic. Best for laptops, desktops, dev VMs.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   laptop    │     │   laptop    │     │  workstation │
│   (daemon)  │     │   (daemon)  │     │  (daemon)    │
└─────────────┘     └─────────────┘     └─────────────┘
        │                  │                   │
        └──── internet (no central hop) ───────┘
```

Pros: no SPOF, no extra hop, identical config per host. Cons: per-host
operational toil; updating the YAML on 200 boxes is your problem.

### 1b. **Gateway / router** (the Pi-hole replacement)

Install on the box that is the LAN's default route. All client
traffic passes through it; one daemon protects every device.

```
[ phones, TVs, laptops ]──── LAN ────►[ gateway/router (daemon) ]──── WAN ──►
```

Pros: no client-side install; covers IoT and devices you can't put
software on. Cons: SPOF; the gateway must be Linux 5.15+ with BTF;
sized to handle aggregate WAN traffic.

### 1c. **VPN concentrator**

A roaming-friendly version of (1b): clients tunnel to a Linux box
running WireGuard / OpenVPN, and that box runs the daemon. Useful
when laptops travel.

```
[ laptop ] === wg-tunnel ===► [ VPS (wireguard + daemon) ]──── WAN ──►
```

Pros: works wherever the laptop is. Cons: latency hit, paying for
the VPS.

---

## 2. Installation methods

In order of "what you should pick":

### 2a. **Distro packages** (`.deb` / `.rpm`) — recommended

```sh
# Debian/Ubuntu
curl -L -o adblocker.deb \
  https://github.com/adblocker/adblocker/releases/latest/download/adblocker_linux_amd64.deb
sudo dpkg -i adblocker.deb
sudo systemctl enable --now adblocker

# Fedora/RHEL
curl -L -o adblocker.rpm \
  https://github.com/adblocker/adblocker/releases/latest/download/adblocker_linux_amd64.rpm
sudo rpm -i adblocker.rpm
sudo systemctl enable --now adblocker
```

The packages drop the binary in `/usr/local/bin`, the configs in
`/etc/adblocker`, and the systemd unit in `/lib/systemd/system`.
Postinstall doesn't auto-enable the unit — operators decide when
to start it.

### 2b. **GitHub Release tarball** (if you need a specific version)

```sh
VER=v0.1.0
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -L -o ab.tgz \
  https://github.com/adblocker/adblocker/releases/download/${VER}/adblocker_${VER#v}_linux_${ARCH}.tar.gz
tar xzf ab.tgz
sudo install -m 0755 adblockerctl /usr/local/bin/adblockerctl
sudo install -d /etc/adblocker
sudo install -m 0644 configs/*.yaml configs/*.txt /etc/adblocker/
sudo install -m 0644 systemd/adblocker.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 2c. **Container image** (`ghcr.io`) — for k8s / nomad

```sh
docker run --rm --privileged --network=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v "$PWD/configs:/etc/adblocker:ro" \
  ghcr.io/adblocker/adblocker:latest
```

> **Container caveat**: BPF programs need access to the host's
> network namespaces and `/sys/fs/bpf`. There's no way to sandbox
> them away — `--privileged` (or fine-grained CAP_BPF +
> CAP_NET_ADMIN + bind mounts) is unavoidable.

### 2d. **Build from source**

See [docs/INSTALL.md](INSTALL.md). For production, build inside CI
with a pinned toolchain rather than on each box.

---

## 3. Configuration management

The daemon's full state is two files:

| file                                | what it controls                                  |
| ----------------------------------- | ------------------------------------------------- |
| `/etc/adblocker/adblocker.yaml`     | sources, intervals, interfaces, static_block list |
| `/etc/adblocker/allowlist.txt`      | per-host overrides (ALLOW flag in kernel)         |

Both are plain text — drop them in your existing config-management
pipeline. The systemd unit declares them as `noreplace` so an upgrade
won't clobber operator edits.

### Ansible task example

```yaml
- name: install adblocker
  ansible.builtin.apt:
    deb: "https://github.com/adblocker/adblocker/releases/download/{{ ab_version }}/adblocker_linux_{{ ansible_architecture | regex_replace('x86_64','amd64') }}.deb"
    state: present
  notify: restart adblocker

- name: deploy adblocker config
  ansible.builtin.template:
    src: adblocker.yaml.j2
    dest: /etc/adblocker/adblocker.yaml
    owner: root
    group: root
    mode: "0644"
  notify: restart adblocker

- name: deploy allowlist
  ansible.builtin.copy:
    src: "files/allowlists/{{ inventory_hostname }}.txt"
    dest: /etc/adblocker/allowlist.txt
    owner: root
    group: root
    mode: "0644"
  notify: restart adblocker

- name: enable & start adblocker
  ansible.builtin.systemd:
    name: adblocker
    enabled: true
    state: started

# in handlers:
- name: restart adblocker
  ansible.builtin.systemd:
    name: adblocker
    state: restarted
```

### Config drift detection

`adblockerctl list` and `adblockerctl stats` give you the runtime
view of what the kernel actually has loaded. If you suspect config
drift (someone hand-edited the YAML on a box), diff the running
counters against the expected ones from your IaC.

---

## 4. Capacity planning

| dimension                | hard limit / default      | when to raise                           |
| ------------------------ | ------------------------- | --------------------------------------- |
| `blocklist` map entries  | `1 << 20` (1 048 576)     | combine more feeds and you'll hit this  |
| `ip_blocklist` entries   | `1 << 16` (65 536)        | rare; LPM is per-prefix not per-IP      |
| Ringbuf size             | 256 KiB                   | high block rates → bump to 1 MiB        |
| Stats slots              | 7 × `nproc` × `u64`       | fixed; per-CPU                          |
| `update_interval_hours`  | 24                        | shorter = more bandwidth, fresher       |
| `cleanup_interval_seconds` | 60                      | longer = stale TEMP entries persist     |

To raise the blocklist cap, edit `bpf/maps.h`:

```c
__uint(max_entries, 1 << 21);   // 2 097 152
```

…then rebuild. The map is allocated when the daemon starts, so a
larger cap = more kernel memory pinned (~32 bytes per entry, so
1M entries ≈ 32 MiB).

### Memory footprint (rough)

| component | size |
| --- | --- |
| `blocklist` (1M entries) | ~32 MiB kernel heap |
| `ip_blocklist` (LPM, sparse) | ~per-entry, low six-digit kB typical |
| `stats` (8 CPUs × 7 × 8B) | < 1 KiB |
| `events` (ringbuf) | 256 KiB |
| daemon RSS (Go) | ~30 MiB at idle, ~80 MiB during a list refresh |

### CPU

Per-packet cost on the hot path is dominated by the LPM lookup
(~100 ns) and, on TCP/443, the SNI parser (~3–5 µs). On a busy
gateway routing 1 Gbps you'll see <2% CPU dedicated to TC egress.

---

## 5. Monitoring & alerting

The daemon exposes **counters via `adblockerctl stats`** and
**events via the systemd journal**. There's no Prometheus exporter
shipped today; the simplest path is a 30-line wrapper.

### Quick wrapper to expose stats over HTTP

```sh
#!/bin/sh
# /usr/local/bin/adblocker-metrics
while true; do
  /usr/local/bin/adblockerctl stats | awk '
    NR>1 { gsub(",", "", $2); printf "adblocker_%s %s\n", tolower($1), $2 }
  ' > /var/run/adblocker-metrics.prom.new
  mv /var/run/adblocker-metrics.prom.new /var/run/adblocker-metrics.prom
  sleep 15
done
```

…then point `node_exporter --collector.textfile.directory=/var/run`
at that file. Alternative: write a real exporter that opens the
pinned maps via `loader.AttachExisting()`.

### Prometheus alerts (suggested)

```yaml
groups:
  - name: adblocker
    rules:
      - alert: AdblockerDown
        expr: time() - max_over_time(adblocker_pkts_seen[5m]) > 600
        for: 2m
        annotations:
          summary: "adblocker on {{ $labels.instance }} stopped seeing packets"

      - alert: AdblockerVerifierLoop
        expr: rate(systemd_unit_failed_total{name="adblocker.service"}[5m]) > 0
        for: 1m
        annotations:
          summary: "adblocker.service is failing to start (likely BPF verifier)"

      - alert: AdblockerListRefreshFailing
        expr: time() - max_over_time(adblocker_blocklist_size[2h]) == 0
        for: 6h
        annotations:
          summary: "blocklist hasn't grown in 6h - upstream feeds may be unreachable"
```

### Health checks

```sh
# liveness: are the maps pinned?
test -e /sys/fs/bpf/adblocker/blocklist || exit 1

# readiness: is the daemon attached to at least one iface?
systemctl is-active --quiet adblocker || exit 1
```

---

## 6. Logging & log retention

### Where logs go

- `journalctl -u adblocker` — every BLOCK event ends up here.
- The daemon writes to stderr; systemd captures it.
- The kernel ringbuf is **lossy under pressure**. Counters in `stats`
  are exact, but events may be dropped during traffic spikes.

### Sample event line

```
2026-04-25 12:34:56.789012 BLOCK[DNS] 192.168.1.42 -> 8.8.8.8 (doubleclick.net)
```

### Retention

Set `MaxRetentionSec=` and `SystemMaxUse=` in
`/etc/systemd/journald.conf`:

```
SystemMaxUse=2G
MaxRetentionSec=2week
```

If you ship logs to a central store (Loki, ELK, Splunk),
`journalbeat` / `vector` / `promtail` all parse `journalctl` output
out of the box. Filter for the `adblocker.service` unit.

### What's in the logs

- Cleartext domain names (the qname we hashed). If your privacy
  posture forbids that, **don't enable event logging in prod** —
  fork the kernel program to omit `qname` from `block_event`. The
  hash alone is non-reversible.
- Source/dest IPs and ports of dropped packets.
- No payloads, no headers beyond what you need to drop.

---

## 7. Upgrade procedure

```sh
# 1. Read CHANGELOG.md for breaking changes.
curl -L https://github.com/adblocker/adblocker/raw/<new-tag>/CHANGELOG.md \
  | head -100

# 2. Stage the new package on one host first.
sudo apt install ./adblocker_linux_amd64.deb        # in-place upgrade
# OR
sudo dpkg -i ./adblocker_linux_amd64.deb

# 3. Watch the unit come back up.
sudo systemctl status adblocker
journalctl -u adblocker -f

# 4. Smoke test before rolling fleet-wide.
sudo adblockerctl block example.com
curl -v --max-time 5 https://example.com    # should fail
sudo adblockerctl unblock example.com
sudo adblockerctl --version                  # confirm new version
```

### Rollback

```sh
# .deb
sudo apt install ./adblocker_linux_amd64.<previous-version>.deb

# binary
sudo systemctl stop adblocker
sudo install -m 0755 /opt/adblocker-rollback/adblockerctl /usr/local/bin/adblockerctl
sudo systemctl start adblocker
```

There is no schema migration for the BPF maps — a downgrade just
reloads the previous binary against a fresh map. The blocklist gets
re-fetched on first refresh.

### Verifier-rejection during upgrade

If the new daemon fails to start with a verifier error, the old
maps stay pinned. The system *isn't* dropping packets but it isn't
broken either — programs were never (re)loaded. Roll back.

---

## 8. Backup & recovery

The daemon has **no durable state** worth backing up. Everything
of substance is recoverable:

| state                       | source of truth          | recovery       |
| --------------------------- | ------------------------ | -------------- |
| Kernel `blocklist` map      | upstream feeds + allowlist file | re-fetched on next refresh |
| `ip_blocklist` LPM trie     | (currently empty by default) | populate via your config-management |
| Allowlist overrides         | `/etc/adblocker/allowlist.txt` | back this up |
| Daemon config               | `/etc/adblocker/adblocker.yaml` | back this up |
| Counters                    | per-CPU array, ephemeral | not worth saving |

**Back up `/etc/adblocker/`.** That's the entire DR surface for the
adblocker.

If a host is destroyed, recovery is: install package → restore
`/etc/adblocker/` → start unit → wait ~30s for first refresh.

---

## 9. Hardening

The shipped systemd unit is already tight:

```
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/sys/fs/bpf
ProtectHome=true
```

Recommended additions for paranoid environments (drop into a
`override.conf` via `systemctl edit adblocker`):

```ini
[Service]
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
PrivateTmp=true
PrivateDevices=false   # leave false; we need /dev/null and friends
DeviceAllow=
```

### CLI access control

`adblockerctl block`/`unblock`/etc. need `CAP_BPF` to talk to the
pinned maps. Don't let unprivileged users have it. The clean
approach:

```sh
# /etc/sudoers.d/adblocker
%adblocker-admins ALL=(root) NOPASSWD: /usr/local/bin/adblockerctl
```

…then add operators to the `adblocker-admins` group. Or use polkit
for a more granular policy.

### Audit logging

Every `block`/`unblock`/`allow`/`temp-block` invocation is a
`/usr/local/bin/adblockerctl ...` exec by an authenticated user via
`sudo`. Wire this into auditd:

```sh
auditctl -w /usr/local/bin/adblockerctl -p x -k adblocker_admin
```

---

## 10. Performance tuning

### `cleanup_interval_seconds`

Default 60s. The reaper iterates the entire blocklist on each tick.
On a host with a 1M-entry blocklist that's a few-millisecond walk;
fine. On low-power hardware (e.g. an ARM router) bump to 300 to
amortize.

### `update_interval_hours`

Default 24. Each refresh re-fetches every source URL and bulk-loads
~600k entries. Network cost ~40 MB. On metered links bump to 168 (weekly).

### XDP attach mode

Default is `XDPGenericMode` because it's portable. On a NIC that
supports `XDPDriverMode` ("native XDP") you'll save a few CPU cycles
per packet on ingress drops. Edit `internal/loader/loader.go`:

```go
Flags: link.XDPDriverMode,    // was: link.XDPGenericMode
```

If the NIC doesn't support it, the attach fails and the daemon
silently falls back to no-XDP for that interface. Egress drops still
work via TC.

### Map sharding

Don't bother. The hash map is per-CPU-friendly; we don't see lock
contention before millions of pps.

---

## 11. Troubleshooting playbook

### `adblocker.service: Failed with result 'exit-code'`

```sh
journalctl -u adblocker -n 50 --no-pager
```

Common causes, in order of likelihood:

| symptom in log                                                | cause / fix |
| ------------------------------------------------------------- | ----------- |
| `failed to load BPF objects: ... operation not supported`     | kernel too old or no BTF. Need 5.15+ with `CONFIG_DEBUG_INFO_BTF=y`. |
| `verifier rejected program: ...`                              | the kernel changed an internal type and CO-RE relocations failed. Re-run `make vmlinux && make` against the running kernel; if you're on a release binary, file an issue. |
| `attach tc egress on eth0: file exists`                       | a previous incarnation didn't clean up. `tc qdisc del dev eth0 clsact` on the iface. |
| `attach tc egress on eth0: permission denied`                 | not running with `CAP_BPF + CAP_NET_ADMIN`. Check the unit's `AmbientCapabilities`. |
| `mkdir pin dir /sys/fs/bpf/adblocker: no such file or directory` | bpffs isn't mounted. `mount -t bpf bpf /sys/fs/bpf`. Add to `/etc/fstab`. |

### Some traffic still gets through

See [docs/INSTALL.md → Troubleshooting](INSTALL.md#troubleshooting).
The usual suspects: DoH/DoT to a non-listed endpoint, a hardcoded
IP we haven't seen, or IPv6 (not yet supported).

### Counters not going up

```sh
sudo adblockerctl stats          # all zeros?
sudo bpftool prog list           # is our prog actually attached?
sudo tc filter show dev eth0 egress
```

If stats are zero, the program isn't seeing packets. If `tc filter
show` is empty, the attach didn't stick — restart the service.

### High CPU in the daemon

```sh
top -p $(pidof adblockerctl)
```

Almost always the list refresher pulling a 100MB feed over a slow
link. Increase `update_interval_hours` or trim sources.

### Disk full from journald

```sh
journalctl --vacuum-size=500M
```

Set `SystemMaxUse=` in `/etc/systemd/journald.conf` so this can't
recur.

---

## See also

- [README.md](../README.md) — overview
- [INSTALL.md](INSTALL.md) — single-host install + everyday CLI
- [ARCHITECTURE.md](ARCHITECTURE.md) — how the kernel programs work
- [TUI.md](TUI.md) — interactive frontend
- [RELEASING.md](RELEASING.md) — for maintainers cutting releases
