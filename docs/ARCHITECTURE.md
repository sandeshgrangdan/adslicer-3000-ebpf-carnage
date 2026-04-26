# Architecture — `ebpf-adblocker`

How the kernel programs, user-space daemon, CLI, and TUI fit together —
from "browser opens a tab" all the way down to "kernel drops the
packet". This doc is the source of truth for the **why** behind every
design choice; the **what** for each piece is in the source.

> Read in order. Each section builds on the previous one. Source
> references are `path:line`-style so you can jump straight to the
> code.

## Table of contents

1. [Bird's-eye view](#1-birds-eye-view)
2. [The three blocking layers](#2-the-three-blocking-layers)
3. [Hashing and the suffix walk](#3-hashing-and-the-suffix-walk)
4. [Kernel programs in depth](#4-kernel-programs-in-depth)
5. [The four BPF maps](#5-the-four-bpf-maps)
6. [User-space daemon](#6-user-space-daemon)
7. [List ingestion pipeline](#7-list-ingestion-pipeline)
8. [Temp-block and expiry](#8-temp-block-and-expiry)
9. [Event stream (kernel → user-space)](#9-event-stream-kernel--user-space)
10. [CLI ↔ daemon ↔ kernel](#10-cli--daemon--kernel)
11. [TUI ↔ CLI](#11-tui--cli)
12. [Comparison with other approaches](#12-comparison-with-other-approaches)
13. [Threat model and limitations](#13-threat-model-and-limitations)
14. [Glossary](#14-glossary)

---

## 1. Bird's-eye view

When an application on this machine opens a network connection, the
kernel walks the egress path: socket buffer → routing → neighbor
resolution → device transmit. We attach a BPF program to the
**clsact** qdisc on egress so it sees every outbound packet *after*
routing decisions but *before* it leaves the NIC.

```
┌────────────┐     write(fd, "GET /...")
│  browser   │─────────────────────────────────┐
│  curl      │                                  │
│  Mail.app  │                                  │
│  …         │                                  │
└────────────┘                                  │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │   Linux network stack       │
                                  │   (route, neigh, iptables)  │
                                  └──────────────┬──────────────┘
                                                 │ skb
                                                 ▼
─────────── clsact qdisc ─────────────  ◀── attach point ──┐
                                                 │          │
                                                 │     ┌────┴───────────────┐
                                                 │     │  tc_egress (BPF)   │
                                                 │     │  ───────────────   │
                                                 │     │  parse Eth→IP→L4   │
                                                 │     │                    │
                                                 │     │  IP/CIDR check     │
                                                 │     │  DNS QNAME parse   │
                                                 │     │  TLS SNI parse     │
                                                 │     │  blocklist lookup  │
                                                 │     │                    │
                                                 │     │  → TC_ACT_OK       │
                                                 │     │    TC_ACT_SHOT     │
                                                 │     └─────────┬──────────┘
                                                 │               │
                                                 ▼               ▼
                                              NIC TX        emit event
                                              (or drop)     (ring buf)
```

Three things to notice:

1. **No proxy.** The decision happens in the kernel, on the same
   `skb` that was about to leave the box. There is no userspace bounce,
   no MITM, no port redirect.
2. **Hooks before serialization.** We see the DNS QNAME and TLS SNI in
   their cleartext on-wire forms because TLS encrypts the *body*, not
   the SNI extension in the ClientHello (TLS 1.3 ECH excepted — see
   §13).
3. **Fail open.** Anything we can't decisively match passes through.
   The only way a packet gets dropped is if we hashed something and
   found that hash in the blocklist map with the BLOCK flag set.

Source: `bpf/adblocker.bpf.c:1-220`, `internal/loader/loader.go:1-150`.

---

## 2. The three blocking layers

The kernel program runs the same packet through three layers in order
of cheapness. The first match wins; nothing further is evaluated.

### Layer 1 — IP/CIDR backstop (LPM trie)

```
skb → Eth → IPv4 → look up ip->daddr in ip_blocklist (LPM)
           ├─ hit  → TC_ACT_SHOT, event reason=IP
           └─ miss ↓
```

This is the first check because an LPM trie lookup on a `__be32` is
~100 ns. It catches:

- Apps that hardcode IPs (no DNS, no SNI to inspect).
- Repeat connections to known-bad IPs after an earlier DNS hit.
- IPv4-only blocklists you import directly (e.g. firehol).

Source: `bpf/adblocker.bpf.c:184-194`, `bpf/maps.h:60-72`.

### Layer 2 — DNS interception (UDP port 53)

```
skb → … → UDP → dport == 53?
                ├─ no → next layer
                └─ yes → parse_qname() → name + dot offsets
                        ├─ malformed (compression pointers etc.) → pass
                        └─ ok → suffix walk + blocklist lookup
                               ├─ hit + BLOCK → TC_ACT_SHOT, reason=DNS
                               └─ else → pass
```

Why DNS first (after IP)? Most ad/tracker traffic begins with a DNS
query for the tracker's hostname, *before* any TLS handshake. Killing
the DNS query means the app never gets an A record and never opens
the TLS connection — cheaper for the kernel and faster for the user.

The DNS layer also catches **DoH/DoT bypass attempts**. The default
config blocks the well-known DoH endpoint domains (`dns.google`,
`cloudflare-dns.com`, `mozilla.cloudflare-dns.com`, `dns.quad9.net`,
`one.one.one.one`). Browsers configured to use those will fall back
to the system resolver, which we then see on UDP/53.

Source: `bpf/adblocker.bpf.c:103-126`, `bpf/parsers.h:74-126`.

### Layer 3 — TLS SNI inspection (TCP port 443)

```
skb → … → TCP → dport == 443 → payload starts with TLS Record Type 0x16?
                              ├─ no → pass
                              └─ yes → parse_sni() → server_name
                                      └─ same suffix walk + lookup
                                         ├─ hit + BLOCK → SHOT, reason=SNI
                                         └─ else → pass
```

This is the safety net for everything DNS misses:

- Apps using DoH/DoT directly (you can't see the DNS, but the SNI on
  the actual TLS connection is still cleartext).
- Apps that use a hardcoded resolver IP (you missed the DNS, but they
  still need TLS to reach the upstream).
- Cached resolutions inside long-running apps.

The SNI is in the ClientHello's `server_name` extension (type
`0x0000`) — see RFC 6066 §3. It's not encrypted in TLS 1.2 or 1.3
(without ECH).

Source: `bpf/adblocker.bpf.c:128-160`, `bpf/parsers.h:128-220`.

### Layered ordering — why this order?

| order | layer  | typical cost  | catches |
| ----- | ------ | ------------- | ------- |
| 1     | IP LPM | ~100 ns       | hardcoded IPs, repeat connections |
| 2     | DNS    | ~1–2 µs       | the resolution itself; cheapest "no app retry" win |
| 3     | TLS    | ~3–5 µs       | DoH/DoT, hardcoded resolvers, post-DNS connections |

Cheap-first means most packets exit at Layer 1 with no further
parsing. Only TCP/443 SYN+payload packets that survived the IP and
DNS layers pay the SNI-parsing cost.

---

## 3. Hashing and the suffix walk

### FNV-1a 64-bit, byte-identical between kernel and user-space

The kernel doesn't store domain *names*. It stores their **64-bit
FNV-1a hashes**. There are two hard requirements:

1. The hash function must be cheap to evaluate inside a BPF program
   under the verifier.
2. Kernel-side and user-space hashes must match **byte for byte** for
   the same input. If they ever diverge, the kernel computes one hash
   and userspace stores another, and blocking silently breaks.

FNV-1a 64 fits both:

```
offset = 0xcbf29ce484222325   # 14695981039346656037
prime  = 0x100000001b3        # 1099511628211

h = offset
for byte in lowercase(name):       # ASCII A-Z → a-z
    h = (h ^ byte) * prime          # mod 2^64
```

The kernel implementation lives in `bpf/parsers.h:9-23`:

```c
static __always_inline __u64 fnv1a_lower(const char *buf, __u32 len) {
    __u64 h = FNV1A_OFFSET;
    #pragma unroll
    for (int i = 0; i < MAX_QNAME; i++) {
        if ((__u32)i >= len) break;
        __u8 c = (__u8)buf[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        h ^= c;
        h *= FNV1A_PRIME;
    }
    return h;
}
```

The Go side is in `internal/hash/fnv.go` and is enforced by tests
against canonical FNV-1a vectors:

```go
{"":       Offset},              // 0xcbf29ce484222325
{"a":      0xaf63dc4c8601ec8c},
{"foobar": 0x85944171f73967e8},
```

If anyone ever changes the kernel offset, prime, lower-case rule, or
input bytes, the test breaks the build before drift can ship.

> **Why not a cryptographic hash?** Collision resistance buys nothing
> here. A 64-bit FNV-1a has ~2^32 collision birthday-bound — at 1M
> entries the chance of any pair colliding is ~10⁻⁷. We're matching
> against a known list, not authenticating; collisions just mean a
> rare false-positive block. Worth it for the speed.

### The suffix walk

A blocklist entry like `doubleclick.net` should match
`pagead2.googlesyndication.doubleclick.net` too. We don't store every
subdomain (that's combinatorial); instead the kernel walks suffixes:

```
Input QNAME: a.b.example.com   (length 13, dots at offsets 1, 3, 11)

iter 0: hash("a.b.example.com")    → look up → miss
iter 1: hash(  "b.example.com")    → look up → miss
iter 2: hash(  "  example.com")    → look up → HIT! drop.
iter 3: hash(  "  com")            (skipped)

Bound: 6 iterations (subdomains in practice almost never go deeper).
```

The `parse_qname` and `parse_sni` parsers both produce *two* outputs:
the flat lowercase name and a small `dots[]` array recording the
byte offset of every `'.'` they wrote. The suffix walk reuses those
offsets — no scanning, no allocation.

Source: `bpf/parsers.h:25-65`, `bpf/parsers.h:74-126` (parser keeps
dot offsets), `bpf/adblocker.bpf.c:103-126` (caller).

### Why a verifier-friendly upper bound (8/6)?

The BPF verifier rejects programs whose loops don't have a static
upper bound. Real DNS names cap at 255 bytes / 127 labels per RFC,
but 99.9% of real traffic stays under 8 labels and 128 bytes. We
hard-code:

```c
#define MAX_QNAME  128   // bytes of the flattened name
#define MAX_LABELS 8     // dot count we record
```

…and bound the suffix walk to **6** iterations. A pathological 9-label
name like `a.b.c.d.e.f.g.h.example.com` won't get its longest
suffixes checked, but the *registrable* suffix
(`example.com`) still hits at iteration ≤ 6. In practice, blocklists
target registrable domains ("doubleclick.net", "googleadservices.com")
not deep subdomains, so the bound is invisible.

---

## 4. Kernel programs in depth

### Two programs, one ELF

`bpf/adblocker.bpf.c` compiles into a single ELF that contains two
program sections:

```
SEC("tc")     int tc_egress(struct __sk_buff *skb) { … }
SEC("xdp")    int xdp_ingress(struct xdp_md *ctx) { … }
```

`bpf2go` produces `internal/loader/adblocker_bpfel.{go,o}`. The .o is
embedded into the Go binary at compile time; the .go file gives us
typed `adblockerObjects` / `adblockerPrograms` / `adblockerMaps`
helpers.

### `tc_egress` — the primary hook

Attached to the **clsact qdisc** on every non-loopback up interface
via `link.AttachTCX(... ebpf.AttachTCXEgress)`. Verdicts:

| return code   | effect                                   |
| ------------- | ---------------------------------------- |
| `TC_ACT_OK`   | continue down the stack (NIC TX)         |
| `TC_ACT_SHOT` | drop the skb; iptables/conntrack untouched |

Pseudocode of the full program:

```
1.  parse Eth: must be IPv4 (IPv6 is v2 TODO)
2.  parse IPv4 header (recheck data_end after IHL × 4)
3.  IP backstop: LPM lookup ip->daddr → if hit, SHOT + emit event
4.  if IPPROTO_UDP and dport == 53:
        parse DNS payload past 12-byte header
        parse_qname → name + dot offsets
        suffix-walk lookup on `blocklist`
        if hit + BLOCK and not ALLOW: SHOT + emit event
5.  if IPPROTO_TCP and dport == 443:
        skip TCP header (doff × 4)
        parse_sni → server_name + dot offsets
        same suffix-walk lookup
        if hit + BLOCK and not ALLOW: SHOT + emit event
6.  return TC_ACT_OK; bump PASSED counter
```

Defensive patterns (every one is required by the verifier or by
real-world packet fragmentation):

- **`data_end` rechecks**. Every `p++` advance is followed by an
  explicit bounds check before dereferencing.
- **`#pragma unroll` on every loop** with a fixed bound.
- **DNS compression pointers** (high bits `0xC0`) bail out — they
  shouldn't appear in queries, and chasing them out-of-bounds reads
  beyond `data_end`.
- **TCP `doff` minimum check** — a fabricated `doff < 5` would underflow
  the payload pointer.

Source: `bpf/adblocker.bpf.c:165-226`.

### `xdp_ingress` — the secondary hook

Attached via `link.AttachXDP(..., link.XDPGenericMode)` — generic
mode is accepted by every driver but slower than native. We use
generic because we only need the LPM lookup for dropping inbound
replies from already-flagged IPs; the heavy lifting was on egress.

```
1.  parse Eth → IPv4
2.  LPM lookup ip->saddr in `ip_blocklist`
3.  hit → XDP_DROP + emit IP event
4.  miss → XDP_PASS
```

If a driver refuses XDP attach for some reason (rare, mostly virtual
ifaces) we log and skip silently — egress drop still works.

Source: `bpf/adblocker.bpf.c:230-260`, `internal/loader/loader.go:96-108`.

### Verifier discipline checklist

| pattern                                 | why                                       |
| --------------------------------------- | ----------------------------------------- |
| `#pragma unroll` everywhere             | the verifier rejects unbounded loops      |
| recheck `data_end` after every advance  | bounds proofs invalidate after pointer arithmetic |
| `MAX_QNAME=128`, `MAX_LABELS=8`         | small enough that the 1M-instruction limit isn't even close |
| reject DNS compression `0xC0`           | otherwise chase pointers OOB              |
| no `bpf_ktime_get_ns` in expiry compare | uptime ≠ wall-clock; user-space reaper handles it |

---

## 5. The four BPF maps

All four are pinned to `/sys/fs/bpf/adblocker/` so they survive the
daemon restarting and so the CLI's `AttachExisting()` can open them
without re-attaching programs.

```
/sys/fs/bpf/adblocker/
├── blocklist        BPF_MAP_TYPE_HASH         max=1<<20  key→value: u64 → domain_entry
├── ip_blocklist     BPF_MAP_TYPE_LPM_TRIE     max=1<<16  key→value: {pfx,addr} → u32
├── stats            BPF_MAP_TYPE_PERCPU_ARRAY max=7      key→value: u32 → u64 (per CPU)
└── events           BPF_MAP_TYPE_RINGBUF      256 KiB
```

### `blocklist` (the heart of the system)

| field       | type                | layout              |
| ----------- | ------------------- | ------------------- |
| key         | `u64`               | FNV-1a hash         |
| value       | `struct domain_entry` | `{u8 flags; u8 _pad[7]; u64 expires_at;}` |
| max_entries | `1 << 20` (1 048 576) | typical full lists are 200k–600k |

Flags are a bitmap:

| bit | name    | meaning                                             |
| --- | ------- | --------------------------------------------------- |
| `1` | `BLOCK` | drop packets matching this hash                     |
| `2` | `ALLOW` | pass packets matching this hash (overrides BLOCK)   |
| `4` | `TEMP`  | temp-block — paired with `expires_at`, deleted by reaper |

The kernel checks ALLOW *before* BLOCK so an allowlist override
always wins. `TEMP` is informational to the kernel — it doesn't
compare `expires_at` against `bpf_ktime_get_ns()` because the latter
is uptime, not wall-clock. The user-space reaper does the deletion
on a 60s ticker (see §8).

Source: `bpf/maps.h:31-46`, `bpf/adblocker.bpf.c:121-126` (ALLOW
beats BLOCK).

### `ip_blocklist` (LPM trie for IP/CIDR)

Keys are `{prefixlen: u32, addr: u32}` in network byte order. The
LPM trie supports `/32` (single IP) all the way through `/0`
(everything — don't do that). We use `BPF_F_NO_PREALLOC` so memory
scales with population, not capacity.

Source: `bpf/maps.h:48-58`.

### `stats` (per-CPU counters)

Seven slots, summed in user-space. Per-CPU means the kernel writes
without atomics in the hot path:

| slot | name           | what                                |
| ---- | -------------- | ----------------------------------- |
| 0    | `PKTS_SEEN`    | every skb that hit `tc_egress`      |
| 1    | `DNS_PARSED`   | parsers ran successfully on UDP/53  |
| 2    | `SNI_PARSED`   | parsers ran successfully on TCP/443 |
| 3    | `BLOCKED_DNS`  | drops via DNS layer                 |
| 4    | `BLOCKED_SNI`  | drops via SNI layer                 |
| 5    | `BLOCKED_IP`   | drops via IP/CIDR backstop          |
| 6    | `PASSED`       | `TC_ACT_OK` returns                 |

`adblockerctl stats` and the TUI dashboard sum across CPUs.

Source: `bpf/maps.h:60-66`, `internal/cli/stats.go:1-50`.

### `events` (256 KiB ring buffer)

Kernel writers, single user-space reader. Each record is a
`struct block_event`:

```c
struct block_event {
    __u64 ts_ns;          // bpf_ktime_get_ns at drop
    __u64 domain_hash;    // the hit key
    __u32 saddr, daddr;   // host-order IPs
    __u16 sport, dport;
    __u8  reason;         // 1=DNS, 2=SNI, 3=IP
    __u8  _pad[7];
    char  qname[128];     // cleartext name we hashed
};
```

The Go mirror is `loader.BlockEvent`. Field order, padding, and
endianness are byte-for-byte identical so the daemon can
`binary.LittleEndian.UintN` straight out of the ringbuf without a
parser.

Source: `bpf/maps.h:36-46`, `internal/loader/loader.go:38-53`,
`internal/cli/daemon.go:225-260` (decoder).

---

## 6. User-space daemon

### Lifecycle

```
adblockerctl daemon --config /etc/adblocker/adblocker.yaml
        │
        ├─ rlimit.RemoveMemlock       (raise the BPF memory cap)
        ├─ os.MkdirAll  /sys/fs/bpf/adblocker
        │
        ├─ loadAdblockerObjects(...)  (embedded ELF → kernel via libbpf)
        │   └─ all four maps come back pinned
        │
        ├─ for each iface in cfg.Interfaces (or auto-detected):
        │     link.AttachTCX(ifindex, tc_egress, AttachTCXEgress)
        │     link.AttachXDP(ifindex, xdp_ingress, XDPGenericMode)  best-effort
        │
        ├─ start three goroutines:
        │     listRefresher → fetches feeds, calls bulkLoad
        │     expiryReaper  → deletes TEMP entries past expiry
        │     eventReader   → pumps ringbuf to log
        │
        └─ wait for SIGINT/SIGTERM, then close every link & map
```

Source: `internal/loader/loader.go:55-118`, `internal/cli/daemon.go:42-98`.

### Goroutines

```
┌─────────────────────────────────────────────────────────────────┐
│ daemon process                                                  │
│                                                                 │
│  ┌──────────────────────────────┐   ┌──────────────────────┐   │
│  │ goroutine: list refresher    │   │ blocklist (kernel)   │   │
│  │  on start: refresh()         │──▶│  BatchUpdate         │   │
│  │  every 24h:  refresh()       │   │  (chunks of 4096)    │   │
│  │  on SIGHUP:  refresh()       │   └──────────────────────┘   │
│  └──────────────────────────────┘                              │
│                                                                 │
│  ┌──────────────────────────────┐                              │
│  │ goroutine: expiry reaper     │   blocklist (kernel)         │
│  │  every 60s:                  │──▶  for each (k, v):          │
│  │    iterate                   │       if TEMP && exp<now:    │
│  │    delete expired            │         Delete(k)            │
│  └──────────────────────────────┘                              │
│                                                                 │
│  ┌──────────────────────────────┐   events (ringbuf)           │
│  │ goroutine: event reader      │◀───  kernel writes here      │
│  │  ringbuf.Reader.Read()       │                              │
│  │  log "BLOCK[DNS] s -> d (n)" │                              │
│  └──────────────────────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

All three live in `internal/cli/daemon.go`. They share a
`context.Context`; `SIGINT` / `SIGTERM` cancels it and `wg.Wait()`
blocks until all three return.

---

## 7. List ingestion pipeline

This is "how the blocklist is maintained" end to end. Same as
Pi-hole and uBlock conceptually, but we do it once into a kernel
map instead of into a DNS server's RPZ or a browser's filter table.

```
┌──────────────────────────────────────────────────────────────────────┐
│  /etc/adblocker/adblocker.yaml                                       │
│                                                                      │
│  sources:                                                            │
│    - { name: stevenblack-unified, url: …/StevenBlack/hosts, format: hosts }   │
│    - { name: oisd-small,          url: …/oisd.nl/domainswild, format: domain }│
│    - { name: easyprivacy,         url: …/easyprivacy.txt,   format: adblock } │
│                                                                      │
│  static_block: [dns.google, cloudflare-dns.com, …]   # DoH endpoints │
│  allowlist_file: /etc/adblocker/allowlist.txt                        │
└──────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │  Fetch (per source)    │   internal/lists/lists.go:185-205
                    │   - 30 s timeout       │
                    │   - 64 MiB body cap    │
                    │   - User-Agent set     │
                    └───────────┬────────────┘
                                │ raw bytes
                                ▼
                    ┌────────────────────────┐
                    │  Parse (per format)    │   ParseHosts / ParseAdblock / ParseDomain
                    │   regex extracts the   │
                    │   domain from each     │
                    │   line                 │
                    └───────────┬────────────┘
                                │ []string (raw)
                                ▼
                    ┌────────────────────────┐
                    │  Validate              │   ValidDomain()
                    │   strict regex:        │
                    │   labels 1..63, alnum/-, │
                    │   no leading/trailing -, │
                    │   total ≤ 253, ≥1 dot, │
                    │   skip localhost etc.  │
                    └───────────┬────────────┘
                                │ []string (clean, lowercase)
                                ▼
                    ┌────────────────────────┐
                    │  Dedupe + sort         │   map[string]struct{} → sorted slice
                    └───────────┬────────────┘
                                │
                                ▼ (per source)
                    ┌────────────────────────┐
                    │  Merge across sources  │   FetchAll
                    │  + append static_block │
                    └───────────┬────────────┘
                                │ []string (final)
                                ▼
                    ┌────────────────────────┐
                    │  bulkLoad()            │   internal/cli/daemon.go:130-160
                    │   for each domain:     │
                    │     h = FNV1a(lower(d))│
                    │     v = {flags, exp}   │
                    │   m.BatchUpdate in     │
                    │   chunks of 4096       │
                    └───────────┬────────────┘
                                │
                                ▼
                    /sys/fs/bpf/adblocker/blocklist
                                │
                                ▼
                    ┌────────────────────────┐
                    │  Allowlist override    │   readAllowlist + bulkLoad(FlagAllow)
                    │   entries from         │
                    │   /etc/adblocker/      │
                    │   allowlist.txt set    │
                    │   the ALLOW flag,      │
                    │   beating BLOCK at     │
                    │   match time.          │
                    └────────────────────────┘
```

### Format parsers

| format    | example line                             | regex                                    |
| --------- | ---------------------------------------- | ---------------------------------------- |
| `hosts`   | `0.0.0.0 doubleclick.net`                | `^\s*(?:0\.0\.0\.0\|127\.0\.0\.1)\s+([A-Za-z0-9._-]+)` |
| `adblock` | `\|\|tracker.example.com^$third-party`   | `^\|\|([A-Za-z0-9._-]+)\^?`              |
| `domain`  | `analytics.example.com`                  | (whole line, after stripping `#`)        |

Skipped:
- hosts: `localhost`, `broadcasthost`, `local`, `localhost.localdomain`, `ip6-*`
- adblock: lines starting with `!`, `[`, `@@`, `##`
- domain: empty lines and `#`-comments

Source: `internal/lists/lists.go:80-160`.

### Validation regex (the gatekeeper)

```regex
^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}[a-z0-9]?$
```

Enforces:
- 1..63 ASCII alnum chars per label
- no leading or trailing hyphen
- at least one dot (we reject TLD-only entries)
- total length ≤ 253

Anything that fails is dropped silently. Real-world feeds are noisy
(empty lines, `0.0.0.0 0.0.0.0`, inline `<script>`); the regex is
the firewall between "internet text" and "kernel map keys".

Source: `internal/lists/lists.go:46-60`.

### Bulk load

`Map.BatchUpdate` is the fast path: a single syscall inserts up to
4096 entries. With a 600k-entry feed that's ~150 syscalls instead of
600k:

```go
keys := make([]uint64, 0, batch)
vals := make([]loader.DomainEntry, 0, batch)
for _, d := range domains {
    keys = append(keys, hash.SumString(d))
    vals = append(vals, loader.DomainEntry{Flags: flags})
    if len(keys) >= 4096 {
        m.BatchUpdate(keys, vals, nil)
        keys, vals = keys[:0], vals[:0]
    }
}
m.BatchUpdate(keys, vals, nil)  // tail flush
```

Bulk load is **idempotent** — a second update with the same key
overwrites in place. So we re-run the whole pipeline every refresh
without bothering to compute a diff.

Source: `internal/cli/daemon.go:130-160`.

### How a refresh is triggered

| trigger                          | path                                    |
| -------------------------------- | --------------------------------------- |
| daemon startup                   | `runDaemon` → goroutine fires `refresh()` once on entry |
| `update_interval_hours` ticker   | `time.NewTicker(24h)` in `listRefresher` |
| `SIGHUP`                         | `signal.Notify` channel feeds the same select |
| `adblockerctl update`            | runs `systemctl restart adblocker` (which also fires the startup path) |
| TUI `[u]` key                    | shells out to `adblockerctl update`      |

Source: `internal/cli/daemon.go:108-128`.

---

## 8. Temp-block and expiry

Two-layer design because BPF can't compare wall-clock time.

```
                           ┌────────────────────────────┐
sudo adblockerctl  ──────▶ │ CLI: temp-block reddit.com │
       temp-block          │      2h                    │
       reddit.com 2h       └─────────────┬──────────────┘
                                         │ expires_at = unix nanos now + 2h
                                         ▼
                                 blocklist[FNV(reddit.com)]
                                  = {flags: BLOCK|TEMP,
                                     expires_at: 1714…}
                                         │
                                         ▼
                                 (kernel matches normally;
                                  doesn't compare expires_at —
                                  bpf_ktime_get_ns is uptime,
                                  not wall-clock)

                                 ── 60 s tick ──
                           ┌────────────────────────────┐
                           │ expiryReaper goroutine     │
                           │  iterate blocklist         │
                           │  delete entries where      │
                           │    flags & TEMP &&         │
                           │    expires_at != 0 &&      │
                           │    expires_at < now (wall) │
                           └────────────────────────────┘
                                         │
                                         ▼
                                 blocklist key deleted
                                 (effective unblock at next match)
```

Why split? The BPF helper `bpf_ktime_get_ns` returns
`CLOCK_MONOTONIC` (system uptime). Our `expires_at` is
`time.Now().UnixNano()`. Comparing the two would silently misfire on
every reboot. Doing the deletion in user-space lets us use the right
clock and keeps the kernel program tiny.

Source: `internal/cli/daemon.go:172-208` (reaper),
`internal/cli/mutate.go:52-78` (CLI side that sets `expires_at`).

---

## 9. Event stream (kernel → user-space)

When the kernel drops a packet, it writes a `block_event` to the
256 KiB ring buffer:

```
kernel: bpf_ringbuf_reserve(&events, sizeof(*e), 0)
        fill in ts_ns, hash, addrs, ports, reason, qname
        bpf_ringbuf_submit(e, 0)

user:   r := ringbuf.NewReader(events)
        rec, _ := r.Read()
        ev := decodeEvent(rec.RawSample)
        log.Printf("BLOCK[%s] %s -> %s (%s)", reason, src, dst, qname)
```

The decoder reads fields at fixed offsets:

| offset | field      |
| ------ | ---------- |
| 0      | ts_ns      |
| 8      | domain_hash |
| 16     | saddr      |
| 20     | daddr      |
| 24     | sport      |
| 26     | dport      |
| 28     | reason     |
| 29     | _pad[7]    |
| 36     | qname[128] |

Sample log line:
```
2026-04-25 12:34:56.789012 BLOCK[DNS] 192.168.1.42 -> 8.8.8.8 (doubleclick.net)
```

The ringbuf is **lossy under pressure** — if the daemon falls behind
during a flood, the kernel returns NULL from `bpf_ringbuf_reserve`
and we just don't emit that event. The drop itself still happens.
Counters (per-CPU array) are not lossy.

Source: `bpf/adblocker.bpf.c:62-87` (kernel writer),
`internal/cli/daemon.go:210-260` (user reader).

---

## 10. CLI ↔ daemon ↔ kernel

Two clean modes, both backed by the same loader package.

### `daemon` mode — owns programs and maps

```
adblockerctl daemon
   │
   ▼
loader.New(ifaces)
   ├─ loads programs into kernel
   ├─ creates + pins maps
   └─ attaches links
```

### Every other subcommand — opens pinned maps only

```
adblockerctl block doubleclick.net
   │
   ▼
loader.AttachExisting()
   ├─ does NOT load programs
   ├─ opens /sys/fs/bpf/adblocker/blocklist
   ├─ opens /sys/fs/bpf/adblocker/ip_blocklist
   ├─ opens /sys/fs/bpf/adblocker/stats
   └─ opens /sys/fs/bpf/adblocker/events

then:
   h = FNV1a("doubleclick.net")
   blocklist.Update(&h, &DomainEntry{Flags: BLOCK}, ebpf.UpdateAny)
```

This is why `block`, `unblock`, `temp-block`, `allow`, `list`, `stats`
all work even while the daemon is running — they don't load
anything; they just poke the maps the daemon owns.

`update` is the odd one out: it can't reach into the daemon's
goroutines, so today it just `systemctl restart adblocker`s. The
restart triggers the on-startup `refresh()`, which is functionally
equivalent.

Source: `internal/loader/loader.go:120-160` (AttachExisting),
`internal/cli/mutate.go`, `internal/cli/list.go`, `internal/cli/stats.go`.

### Why `unblock` needs the cleartext name

The blocklist is keyed on the FNV-1a hash. The hash is **one-way** —
we don't store the cleartext anywhere kernel-side. To unblock you
have to retype the name; the CLI hashes it the same way, then
`Delete`s the matching key. The TUI's `d` / `Del` / `U` keys all
prompt for the cleartext for this reason.

---

## 11. TUI ↔ CLI

```
┌──────────────────────┐    ┌────────────────┐
│  adblocker-tui       │    │ adblockerctl   │
│  (Rust + Ratatui)    │    │ (Go)           │
│                      │    │                │
│  every 1.5s:         │    │  AttachExisting│
│   Command::new(      │    │  → pinned maps │
│     "sudo -n",       │───▶│  → reads stats │
│     "adblockerctl",  │    │  → returns text│
│     "stats")         │◀───│                │
│                      │    │                │
│  on [a] / [t] / etc: │    │                │
│   spawn block /      │───▶│  hashes name   │
│   temp-block / allow │    │  Update map    │
│   subprocess         │◀───│                │
│                      │    │                │
│  on [u]:             │───▶│  systemctl     │
│   spawn update       │    │  restart       │
│                      │    │                │
│  --ssh user@host:    │    │                │
│   wraps the above in │    │                │
│   ssh -o BatchMode=yes│   │  (runs on the  │
│   user@host '<cmd>'  │    │   remote box)  │
└──────────────────────┘    └────────────────┘
```

Two design points:

1. **The TUI never touches BPF directly.** It just runs
   `adblockerctl`. That keeps the Rust crate portable (no libbpf
   dep) and means anything the TUI does, you can also script from a
   shell — and vice versa.
2. **`--ssh user@host` is just a prefix transform.** The TUI swaps
   `["sudo", "-n", "adblockerctl", ...]` for
   `["ssh", "-o", "BatchMode=yes", target, "sudo -n adblockerctl ..."]`.
   That's how macOS users (no eBPF on Darwin) manage a Linux host.

Source: `tui/src/backend.rs`, `tui/src/app.rs`, `tui/src/input.rs`.

---

## 12. Comparison with other approaches

> Quick reference: every row catches different traffic. The interesting
> column is "what does it miss".

| tool                  | layer / mechanism                             | catches                                | misses                                                                  |
| --------------------- | --------------------------------------------- | -------------------------------------- | ----------------------------------------------------------------------- |
| **uBlock Origin**     | browser extension; URL & cosmetic filters     | browser-rendered ads, trackers, JS     | other browsers, native apps, anything outside that browser              |
| **AdBlock Plus / etc.** | browser extension                           | same                                   | same; MV3 has nerfed the network-blocking ability                       |
| **`/etc/hosts`**      | resolver pre-empt (`0.0.0.0 ads.example.com`) | most browser+app DNS lookups          | DoH/DoT (apps using their own resolver), TLS SNI, hardcoded IPs         |
| **Pi-hole**           | DNS server with RPZ-style sinkhole            | every DNS that uses your Pi-hole       | DoH/DoT, hardcoded resolvers, TLS SNI, hardcoded IPs                    |
| **NextDNS / DoH-based** | DNS server with their lists                 | DNS over a managed pipe                | apps that bypass it (DoH to Google directly), hardcoded IPs             |
| **AdGuard for Mac/Win** | local MITM TLS proxy with their CA installed | URL paths, in-app traffic              | pinned-cert apps; needs root cert install; one bug = MITM your everything |
| **PF / iptables / nftables** | packet filter                          | drop by IP, port, simple match         | no name-based matching; you maintain IP lists yourself                  |
| **Little Snitch**     | per-app outbound firewall, manual rules       | new outbound connections, per-app      | tedious; doesn't help against sites you allow that then load ads        |
| **`ebpf-adblocker`** *(this project)* | TC-egress + XDP-ingress BPF in kernel | DNS QNAME, TLS SNI, IP/CIDR — every app, no proxy, no cert | path-level (URL), in-page cosmetic, IPv6 (v1), TLS-1.3 ECH, multi-segment ClientHello |

Where this project sits in the design space:

- **Vs. Pi-hole / NextDNS:** they catch DNS only; we catch DNS *and*
  SNI *and* IP. They run on a separate box; we run inline on the
  client kernel.
- **Vs. AdGuard MITM:** no cert install, no pinned-cert breakage. But
  also no path-level (`/ad.js`) blocking — we see only the SNI hostname.
- **Vs. uBlock:** we cover every app, not just one browser. But
  uBlock blocks the iframe inside the page; we just kill the
  connection it would have opened. For "make ads invisible inside
  the rendered page" you still want uBlock.

In practice, the most useful combo is:

- `ebpf-adblocker` to kill tracker + ad-network traffic system-wide
- `uBlock Origin` in the browser to clean up cosmetic remnants and
  block first-party ads served from the same hostname as the content

Each tool covers a layer the other can't.

---

## 13. Threat model and limitations

What this project is and isn't.

### What it is

- A **defense in depth** at the kernel packet layer for DNS-name and
  TLS-SNI based blocking.
- Per-host: it protects the box it's installed on, against the
  apps running on that box.
- A way to enforce a blocklist that **every application on the host**
  obeys, regardless of resolver, browser, or DNS-over-anything.

### What it isn't

- **Not a privacy / anonymity tool.** Successful blocks emit ringbuf
  events with cleartext qnames into local logs. If your threat model
  includes "another user on this host", encrypt or rotate logs
  separately.
- **Not a network-level firewall.** It operates per-host. To
  protect every device on a LAN, install on the gateway/router or
  use a router-side tool (Pi-hole, AdGuard Home).
- **Not a content filter.** We don't see URL paths, page contents,
  or in-page tracking pixels (except by the third-party connection
  they trigger). For path-level blocking you still need something
  in-browser or MITM.

### Concrete known gaps

| gap                                | impact                                                         | mitigation                                                                |
| ---------------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------- |
| **IPv6**                           | v1 only matches IPv4 packets                                   | v2 TODO. For now, prefer IPv4 (sysctl) or run dual-stack with the IP backstop on `::/0` |
| **TLS 1.3 ECH**                    | hides SNI in the ClientHello when both endpoints support it    | rare in 2026 as default. Block known ECH-enabling DNS endpoints (HTTPS RR) at the DNS layer |
| **Multi-segment ClientHello**      | huge ClientHellos split across TCP segments — we only inspect the first | rare in practice. Document and accept; v2 could buffer.                   |
| **DoH/DoT to a non-listed endpoint** | a custom DoH endpoint not in `static_block` evades DNS layer    | SNI layer still catches it on the way out. Add the endpoint to the config.|
| **Hash collisions**                | 64-bit FNV-1a, ~2^32 birthday bound; at 1M entries ~10⁻⁷ pair collision | unlikely false-positive blocks. Rotate to a different hash (xxh3) if it ever bites |
| **Hash is one-way**                | can't list cleartext names; CLI/TUI need user-typed names to delete | by design. If you want a reverse map, add a userspace BoltDB next to the maps |
| **DNS compression in queries**     | bail out (drop on `0xC0`) — would fail on a deliberately compressed query | queries don't compress in practice; a malicious peer using compression just causes a passthrough, not OOB read |
| **Ringbuf back-pressure**          | very high block rates can drop *events* (not drops)            | counters in `stats` are exact; events are advisory                        |
| **Loopback skipped**               | doesn't block traffic between processes on the same host       | by design; intra-host traffic is the host's own business                  |

---

## 14. Glossary

- **BPF / eBPF** — extended Berkeley Packet Filter. A sandboxed VM
  inside the Linux kernel for running pre-verified programs at
  hooks like TC, XDP, kprobe, tracepoint.
- **TC** — Traffic Control. Linux's queueing-discipline framework on
  network devices. We use the `clsact` qdisc and attach a BPF
  program of type `BPF_PROG_TYPE_SCHED_CLS`.
- **XDP** — eXpress Data Path. The earliest BPF hook on packet
  receive, before the skb is allocated. Drop-here is the cheapest
  drop possible.
- **clsact** — a special TC qdisc that has both `ingress` and
  `egress` attach points. Required for our egress program.
- **BTF** — BPF Type Format. Kernel-side type info that lets BPF
  programs do **CO-RE** (compile once, run everywhere) field
  relocations against arbitrary running kernels.
- **vmlinux.h** — generated by `bpftool btf dump` from the running
  kernel's BTF. Lets BPF C source `#include "vmlinux.h"` instead of
  pulling in `linux/*.h`.
- **LPM trie** — Longest Prefix Match trie. The map type used for
  IP/CIDR matching in BPF.
- **ring buffer** — `BPF_MAP_TYPE_RINGBUF`. A single-producer-many
  (kernel writer) MPSC-style queue for kernel→userspace events.
  Lossy under back-pressure.
- **per-CPU array** — `BPF_MAP_TYPE_PERCPU_ARRAY`. One slot per
  online CPU; user-space sums them. Lock-free hot path.
- **CO-RE** — Compile Once, Run Everywhere. Pattern + tooling that
  lets a BPF object built against today's kernel BTF run on
  yesterday's and tomorrow's kernels by relocating field offsets at
  load time.
- **CAP_BPF / CAP_NET_ADMIN** — Linux capabilities the daemon
  needs. Granted by the systemd unit's `AmbientCapabilities`.
- **FNV-1a 64** — Fowler-Noll-Vo hash, 64-bit, "alternate" variant.
  Cheap, deterministic, byte-for-byte identical between our kernel
  and Go implementations.

---

## See also

- [README.md](../README.md) — short overview, build steps, smoke test
- [INSTALL.md](INSTALL.md) — installation per distro, daemon
  lifecycle, allowlist, troubleshooting
- [TUI.md](TUI.md) — Ratatui-based interactive frontend
- Source: [`bpf/adblocker.bpf.c`](../bpf/adblocker.bpf.c),
  [`bpf/parsers.h`](../bpf/parsers.h),
  [`bpf/maps.h`](../bpf/maps.h),
  [`internal/loader/loader.go`](../internal/loader/loader.go),
  [`internal/cli/daemon.go`](../internal/cli/daemon.go),
  [`internal/lists/lists.go`](../internal/lists/lists.go),
  [`internal/hash/fnv.go`](../internal/hash/fnv.go).
