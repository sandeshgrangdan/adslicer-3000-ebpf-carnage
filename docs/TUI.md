# `adblocker-tui` — terminal UI

A [Ratatui](https://github.com/ratatui-org/ratatui)-based interactive
frontend for `adblocker`. Manage the kernel blocklist, allowlist,
counters, and event stream from one screen, locally or over SSH.

> The TUI never touches BPF maps directly. Every action shells out to
> `adblockerctl` — the same binary the daemon and CLI use — so anything
> you can do in the TUI you can also script from a shell.

```
┌ adblocker  ·  local ─────────────────────────────────────────────┐
│ Dashboard   Blocklist   Allowlist   Events                            │
└───────────────────────────────────────────────────────────────────────┘
┌ counters ──────────────┐┌ summary ──────────────────────────────────┐
│ counter      value     ││                                           │
│ PKTS_SEEN    142,981   ││   blocked                                 │
│ DNS_PARSED       472   ││     DNS  88    SNI  41    IP  3           │
│ SNI_PARSED       219   ││                                           │
│ BLOCKED_DNS       88   ││   share of seen packets                   │
│ BLOCKED_SNI       41   ││     0.092%                                │
│ BLOCKED_IP         3   ││                                           │
│ PASSED       142,849   ││   blocklist size                          │
└────────────────────────┘│     50 entries (capped at 50 in list view)│
                          │                                           │
                          │   shortcuts                               │
                          │   [r] refresh  [u] update lists  [?] help │
                          └───────────────────────────────────────────┘
┌ block> doubleclick.net_ ──────────────────────────────────────────────┐
│ type a domain to BLOCK, Enter to confirm, Esc to cancel               │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Install

The TUI lives at [`tui/`](../tui/) inside this repo. It's a separate
Rust crate with no Go dependency at runtime — you just need
`adblockerctl` reachable on the target host.

### Linux

```sh
# install the Rust toolchain if you don't have it
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

cd tui
cargo build --release
sudo install -m 0755 target/release/adblocker-tui /usr/local/bin/adblocker-tui
```

### macOS

```sh
brew install rustup-init && rustup-init -y
cd tui
cargo build --release
install -m 0755 target/release/adblocker-tui /usr/local/bin/adblocker-tui
```

On macOS the TUI is only useful in **remote management mode** because
eBPF doesn't exist on Darwin (see
[INSTALL.md → macOS](INSTALL.md#macos--what-works-what-doesnt)).
Run it pointing at a Linux box you control:

```sh
adblocker-tui --ssh user@linux-box.lan
```

The Linux box must have `adblockerctl` installed and a working daemon.
Your SSH key needs to be configured for non-interactive auth — the
TUI runs SSH with `BatchMode=yes` so it never prompts for a password.

---

## Run it

```sh
sudo adblocker-tui                        # local Linux, simplest case
adblocker-tui --no-sudo                   # already root or have polkit rule
adblocker-tui --ssh user@router.lan       # remote Linux box (works on macOS)
adblocker-tui --refresh-ms 500            # snappier stats polling
adblocker-tui --adblockerctl /opt/bin/adblockerctl    # custom binary path
```

The TUI clears the screen, takes over your terminal, and starts
polling `adblockerctl stats` and `adblockerctl list` every
`--refresh-ms` (default 1.5s).

---

## Views

### 1. Dashboard

Live counters (per-CPU sums across all 7 stat slots) and a quick
summary: blocked-share-of-seen, current blocklist size, and the most
useful shortcuts.

### 2. Blocklist

Scrollable table of the first 50 entries the kernel `blocklist` map
exposes:

```
#    hash               flags  expires_at
1    21bce4eea7c0f0d8   B      -
2    85944171f73967e8   BT     1714123456789012345
3    7e96d1e9bf52a481   BA     -
```

Flags are a packed string:

| char | meaning |
| ---- | ------- |
| `B`  | BLOCK   |
| `A`  | ALLOW (overrides BLOCK) |
| `T`  | TEMP (kernel-side hint; user-space reaper does the deletion) |

> **Why hashes, not domains?** The kernel only stores FNV-1a 64 hashes
> of the lowercase name — there is no reverse lookup. To unblock or
> manage by name, type the cleartext into the prompt; the hash is
> recomputed and the matching entry is removed.

### 3. Allowlist

Filtered view of entries with the `A` (ALLOW) flag set. Useful for
seeing which domains you've explicitly whitelisted to override an
upstream feed (e.g. `my-cdn.example.com`).

### 4. Events

Last few hundred messages produced by the TUI itself: actions you've
taken, errors from `adblockerctl`, and update-list outcomes. Newest
first. `[ok ]` lines are green, `[err]` lines are red.

> The kernel emits a separate ringbuffer event stream
> (`BLOCK[DNS] saddr -> daddr (qname)`) which the daemon logs to
> `journalctl -u adblocker -f`. The TUI doesn't read that stream
> today — open a second terminal and tail journalctl if you want
> live block events.

---

## Keybindings

### Global

| key                   | action                                          |
| --------------------- | ----------------------------------------------- |
| `q`, `Ctrl-C`         | quit                                            |
| `?`, `F1`             | toggle help overlay                             |
| `Tab` / `→` / `l`     | next view                                       |
| `Shift+Tab` / `←` / `h` | previous view                                 |
| `1` / `2` / `3` / `4` | jump to Dashboard / Blocklist / Allowlist / Events |
| `r`                   | force refresh (stats + blocklist)               |
| `u`                   | update upstream lists (`adblockerctl update`)   |

### Blocklist view

| key | action |
| --- | ------ |
| `↑` / `↓` (or `j`/`k`) | move highlight |
| `a` | prompt to **add** a domain to the blocklist |
| `t` | prompt to **temp-block** — first the domain, then duration (`30m`, `2h`, `1d`) |
| `d`, `Del`, `U` | prompt to **unblock** by cleartext name |

### Allowlist view

| key | action |
| --- | ------ |
| `↑` / `↓` (or `j`/`k`) | move highlight |
| `a` | prompt to **add** a domain to the allowlist |

### Edit mode (any prompt)

| key       | action                                |
| --------- | ------------------------------------- |
| any char  | append to buffer                      |
| `Backspace` | delete last char                    |
| `Enter`   | submit                                |
| `Esc`     | cancel                                |

---

## Updating upstream blocklists

Press **`u`** anywhere. The TUI invokes `adblockerctl update`, which
restarts the daemon (so it re-fetches every source from
`/etc/adblocker/adblocker.yaml`, parses, deduplicates, and bulk-loads
into the kernel map in chunks of 4096).

After ~10–30 seconds the new lists are in place — the dashboard
counters keep ticking and the blocklist size will jump.

To add or remove sources, edit the YAML directly and press `u` again:

```yaml
sources:
  - { name: my-list, url: https://example.com/blocklist.txt, format: domain }
```

Three formats are supported (see
[INSTALL.md → Updating the upstream blocklists](INSTALL.md#updating-the-upstream-blocklists)).

---

## Common workflows

### Block a site for the afternoon

1. Press `2` to jump to Blocklist
2. Press `t`
3. Type `gmail.com`, press `Enter`
4. Type `4h`, press `Enter`

The dashboard shows `BLOCKED_DNS` ticking up as soon as anyone on the
machine tries to resolve gmail.com.

### Unblock a domain

1. Press `2` to jump to Blocklist
2. Press `d` (or `U`)
3. Type the cleartext name (e.g. `gmail.com`), press `Enter`

The hash is one-way; the highlighted row's hex is informational only.

### Override a feed false-positive

1. Press `3` to jump to Allowlist
2. Press `a`
3. Type `my-cdn.example.com`, press `Enter`

ALLOW beats BLOCK in the kernel program, so `my-cdn.example.com` will
pass even if an upstream feed lists it.

### Kick off a fresh fetch of upstream lists

Press `u`. Watch the Events tab for `[ok ] update: daemon restarted`.

---

## Troubleshooting

**`adblockerctl stats failed: sudo: a password is required`**
You're running over SSH and the remote sudoers asks for a password
non-interactively. Either:
- Add a NOPASSWD rule for the user on `/usr/local/bin/adblockerctl`, or
- Run `--no-sudo` and configure a polkit rule, or
- SSH in as root (not recommended).

**`Connection refused` over `--ssh`**
The remote must allow your key, `BatchMode=yes` is on. Test from the
shell first: `ssh user@host adblockerctl stats`. If that fails, the
TUI will fail too.

**Counters never change**
Check `journalctl -u adblocker -f` on the daemon side. The daemon may
have failed to attach — most often this is a kernel/BTF mismatch.

**The TUI froze**
Press `Ctrl-C`. The terminal will be restored on exit (alt-screen
leave + raw-mode disable + cursor show).
