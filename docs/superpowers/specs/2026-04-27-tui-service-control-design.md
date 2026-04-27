# TUI service control + attached-interfaces visibility

Status: design approved 2026-04-27.

## Goal

Let an operator enable/disable the adblocker daemon from the Ratatui TUI, and
see at a glance which network interfaces the running daemon is actually
attached to (TC egress + XDP ingress).

## Background

Today the TUI shells out to `adblockerctl` for every action and has no
control over the daemon's lifecycle. The daemon attaches BPF programs in
`internal/loader/loader.go` (`Loader.New`) and detaches them in
`Loader.Close()` on `SIGINT`/`SIGTERM`. The list of attached ifaces lives
only in memory in the daemon process.

## Non-goals

- A "pause" mode that detaches links without exiting the daemon. Stop is
  always a full process exit via systemd.
- Editing the on-disk YAML config from the TUI.
- IPv6, container, or non-systemd init systems. We keep the existing
  systemd-only assumption.
- Authn/authz beyond what `sudo`/polkit already enforce.

## Architecture

Three pieces, each independently testable:

1. **Daemon state file** — the daemon writes the truth about itself to a
   well-known path on disk; the file's existence is the running signal.
2. **`adblockerctl status` subcommand** — reads the state file, validates
   liveness, prints human or JSON.
3. **TUI service panel + toggle** — polls `status --json`, renders a panel
   on the Dashboard, and binds `[s]` to start/stop via `sudo systemctl`.

```text
   daemon            file                CLI                  TUI
   ───────           ────                ───                  ───
   Loader.New ─────► /run/adblocker/    ─► status --json ────► poll 1.5s
                     state.json                                ▼
   Loader.Close ───► (unlink)                                 [s] toggle
                                                               ▼
                                            sudo systemctl start|stop
```

## Component 1 — daemon state file

**Path:** `/run/adblocker/state.json`. Created via `RuntimeDirectory=adblocker`
in the systemd unit, which gives correct permissions and automatic cleanup
on stop. The daemon also calls `os.MkdirAll("/run/adblocker", 0o755)` as a
fallback so direct (non-systemd) invocations still produce a usable state
file. If the mkdir fails (e.g. read-only `/run`), the write is skipped
silently — the daemon continues to attach normally; only the TUI's status
view loses visibility.

**Schema:**

```json
{
  "pid": 12345,
  "tc":  ["eth0", "wlan0"],
  "xdp": ["eth0"]
}
```

- `pid` — `os.Getpid()` at write time.
- `tc` — names of interfaces where `link.AttachTCX` succeeded.
- `xdp` — subset of `tc` where `link.AttachXDP` also succeeded (XDP attach
  is best-effort today).

**Write site:** `loader.New`, immediately after the attach loop, before
returning the `Loader`. If `len(tc) == 0` we do not write the file — `New`
already returns an error in that case.

**Remove site:** `Loader.Close()`, after detach. Best-effort
(`os.Remove` errors are logged, never fatal). Stale files left behind by a
crash are handled by the CLI via PID liveness.

## Component 2 — `adblockerctl status`

New file `internal/cli/status.go`. Cobra subcommand wired into the root.

Logic:

```text
data, err := os.ReadFile("/run/adblocker/state.json")
if errors.Is(err, fs.ErrNotExist):
    print "stopped"
parse JSON
if syscall.Kill(pid, 0) == ESRCH:
    print "stopped (stale state file)"
print running + tc + xdp
```

Default output (human):

```text
status:  running (pid 12345)
tc:      eth0, wlan0
xdp:     eth0
```

```text
status:  stopped
```

`--json` flag toggles to a fixed schema:

```json
{"running": true, "pid": 12345, "tc": ["eth0","wlan0"], "xdp": ["eth0"]}
```

```json
{"running": false}
```

The TUI parses only this JSON form. The schema is the contract.

## Component 3 — TUI service panel + toggle

**Polling.** `App` already has a 1.5s tick that fetches `stats`. Add a
sibling fetch of `adblockerctl status --json` on the same tick. Both
fetches are independent; failure of one does not affect the other.

**State.** `App` gains:

```rust
struct ServiceStatus {
    running: bool,
    pid: Option<u32>,
    tc: Vec<String>,
    xdp: Vec<String>,
}
```

Plus a `last_service_error: Option<String>` for the footer.

**Layout.** A new "service" panel sits next to the existing summary panel
in the Dashboard view:

```text
┌ service ──────────────────────────────┐
│ status:  RUNNING (pid 12345)          │
│ tc:      eth0, wlan0                  │
│ xdp:     eth0                         │
│                                       │
│ [s] stop adblocker                    │
└───────────────────────────────────────┘
```

When stopped:

```text
│ status:  STOPPED                      │
│                                       │
│ [s] start adblocker                   │
```

**Keybinding.** `[s]` in `InputMode::Normal` opens a new
`InputMode::ConfirmService { action: ServiceAction }`. Footer prompts:

```text
Stop adblocker daemon? [y/N]
```

`y` (or `Y`) executes the action and returns to `Normal`. Any other key
cancels.

**Backend.** `tui/src/backend.rs` gains three methods that reuse the
existing `Command::new` / `--ssh` plumbing:

| method | invocation |
|--------|------------|
| `service_status()`  | `adblockerctl status --json` (parsed via `serde_json`) |
| `service_start()`   | `sudo -n systemctl start adblocker` |
| `service_stop()`    | `sudo -n systemctl stop adblocker` |

`serde_json` is added as a dependency (already implied by `serde`).

**SSH mode.** Works for free. Every command is already wrapped in
`ssh user@host`; `systemctl` simply runs on the remote.

**Error display.** On a failed start/stop, the stderr line goes into the
existing footer status area. No new modal or popup.

## Edge cases

- **Daemon crashes without removing the state file.** PID liveness check
  in `adblockerctl status` reports stopped.
- **Operator runs the daemon outside systemd** (e.g. directly from CLI).
  `systemctl start/stop` will fail; the TUI surfaces stderr in the footer.
  No state-file logic changes — the CLI tool itself still writes the file.
- **`/run/adblocker` does not exist** (operator started the daemon by hand
  without the unit). Covered by the `MkdirAll` fallback above. If even
  that fails, `adblockerctl status` reports stopped — the operator can
  still see via `bpftool net show` if desired.
- **Race: TUI polls during attach.** Either the file isn't there yet
  (TUI shows STOPPED for one tick) or it is (TUI shows RUNNING). Both
  states are accurate at that instant; no special handling.
- **Race: TUI polls during stop.** Same as above, in reverse.

## Files touched (predicted)

- `internal/loader/loader.go` — write/remove `state.json`.
- `internal/cli/status.go` — new file, ~80 lines.
- `internal/cli/root.go` (or wherever subcommands register) — wire up `status`.
- `systemd/adblocker.service` — add `RuntimeDirectory=adblocker`.
- `tui/Cargo.toml` — add `serde_json`.
- `tui/src/backend.rs` — `ServiceStatus`, `service_status`, `service_start`,
  `service_stop`.
- `tui/src/app.rs` — `service_status` field, polling, new `InputMode` variant.
- `tui/src/input.rs` — `[s]` handler + confirm flow.
- `tui/src/ui.rs` — render the service panel on Dashboard.
- `docs/TUI.md`, `docs/ARCHITECTURE.md` — document the new key and panel.

## Testing

- Unit test `status` command in `internal/cli/status_test.go`: feed it a
  fixture state file, verify human + JSON output for running, stopped,
  and stale-PID cases.
- Manual smoke test: `make install`, start TUI, press `[s]` to stop,
  observe panel transition; press `[s]` again, observe restart.
