# `adblocker-tui` — terminal UI

A Ratatui-based frontend for the eBPF adblocker. From a single screen
you can see live counters, browse the kernel blocklist, add /
temp-block / unblock domains, manage allowlist entries, and trigger
upstream list updates. The TUI shells out to `adblockerctl` for every
action, so it works locally on the daemon host or remotely over SSH
from any machine that can reach the host.

The TUI itself is Linux-only. The daemon (kernel BPF programs) is also
Linux-only — running the TUI on macOS or Windows is not supported.

---

## Install

### One-line install (recommended)

The release pipeline publishes a self-installing shell script on every
tagged release. Pick the latest version from the
[Releases page](https://github.com/sandeshgrangdan/adslicer-3000-ebpf-carnage/releases)
and run:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/sandeshgrangdan/adslicer-3000-ebpf-carnage/releases/latest/download/adblocker-tui-installer.sh | sh
```

The installer detects your architecture (`x86_64`/`aarch64`,
`gnu`/`musl`), drops the binary into `$CARGO_HOME/bin` (default
`~/.cargo/bin`), and writes a small updater so future versions can be
fetched with `adblocker-tui --update`.

If `~/.cargo/bin` isn't on your `$PATH`, add it:

```sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.profile
```

### Prebuilt tarball

Download a tarball directly from the Releases page if you don't want
the installer:

```sh
# pick the artifact for your arch+libc
TARGET=x86_64-unknown-linux-gnu       # or aarch64-unknown-linux-gnu, x86_64-unknown-linux-musl
curl -fsSL -o /tmp/adblocker-tui.tgz \
  https://github.com/sandeshgrangdan/adslicer-3000-ebpf-carnage/releases/latest/download/adblocker-tui-$TARGET.tar.gz
tar -xzf /tmp/adblocker-tui.tgz -C /tmp
sudo install -m 0755 /tmp/adblocker-tui-$TARGET/adblocker-tui /usr/local/bin/
```

### From source

If you have a Rust toolchain (1.95+ stable):

```sh
git clone https://github.com/sandeshgrangdan/adslicer-3000-ebpf-carnage
cd adslicer-3000-ebpf-carnage/tui
cargo install --path .
# binary lands in ~/.cargo/bin/adblocker-tui
```

---

## Run it

The TUI assumes `adblockerctl` is reachable on the host where the daemon
runs. Three usage modes:

```sh
# Local (TUI + daemon on the same Linux box)
sudo adblocker-tui

# Local with passwordless adblockerctl (polkit or sudoers NOPASSWD rule)
adblocker-tui --no-sudo

# From a workstation, against a remote daemon over SSH
adblocker-tui --ssh user@server.example
```

`--ssh` wraps every `adblockerctl` call in
`ssh -o BatchMode=yes user@host`, so your SSH key must be configured for
non-interactive auth. The daemon stays on the remote box; only the TUI
runs locally.

Common flags:

```sh
adblocker-tui --refresh-ms 500                          # snappier polling (default 1500ms)
adblocker-tui --adblockerctl /opt/bin/adblockerctl      # custom binary path
adblocker-tui --update                                  # self-update via the cargo-dist updater
```

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
| `t` | prompt to **temp-block** (asks domain, then duration: `30m`, `2h`, `1d`) |
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

## Updating

```sh
adblocker-tui --update
```

Pulls the latest release tarball for your platform, replaces the
in-place binary, and exits. Powered by the cargo-dist self-updater that
ships in every release.

To pin to a specific version, just re-run the install one-liner against
that version's URL:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/sandeshgrangdan/adslicer-3000-ebpf-carnage/releases/download/v<TAG>/adblocker-tui-installer.sh | sh
```

Replace `v<TAG>` with the version you want, e.g. `v0.1.1`.

---

## Troubleshooting

**`adblockerctl stats failed: open pinned map blocklist: no such file or directory (is the daemon running?)`**

The daemon hasn't created the BPF map pins under `/sys/fs/bpf/adblocker/`.
Either start it (`sudo systemctl start adblocker`) or check its logs
(`journalctl -u adblocker -f`) — it may have failed to attach because
the kernel lacks `CONFIG_DEBUG_INFO_BTF=y` or the `clsact` qdisc isn't
available on the chosen interfaces.

**`adblockerctl stats failed: sudo: a password is required`**

You're running over SSH and the remote sudoers asks for a password
non-interactively. Three fixes:

- Add a NOPASSWD rule for the user on `/usr/local/bin/adblockerctl`, or
- Run with `--no-sudo` and configure a polkit rule allowing the user to
  read the BPF maps, or
- SSH in as root (not recommended).

**`Permission denied (publickey)` over `--ssh`**

The TUI runs SSH with `BatchMode=yes`, so password prompts are disabled.
Test from a normal shell first:

```sh
ssh user@host adblockerctl stats
```

If that fails, add your key to the remote's `~/.ssh/authorized_keys` (or
configure `~/.ssh/config` with the right `IdentityFile`). Once that
works, the TUI will work too.

**`command not found: adblockerctl` on the daemon side**

Either install the daemon binary (`sudo make install` from the source
checkout) or point the TUI at the binary's path:

```sh
adblocker-tui --adblockerctl /opt/local/bin/adblockerctl
```

---

## How it works (brief)

The TUI never opens a BPF map directly. On every tick it spawns
`adblockerctl stats` and `adblockerctl list`, parses the output, and
redraws the screen. Mutations (`block`, `unblock`, `temp-block`,
`allow`, `update`) all flow through the same CLI — anything you can do
in the TUI you can also script from a shell.

Architectural detail (state model, the four views, the SNI/DNS lookup
flow on the kernel side, the `[d]` unblock-by-cleartext path) lives in
[`docs/superpowers/specs/2026-04-28-tui-architecture.md`](superpowers/specs/2026-04-28-tui-architecture.md).
