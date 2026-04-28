# TUI Service Control + Attached-Interfaces Visibility — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let operators enable/disable the adblocker daemon from the Ratatui TUI, and show the actually-attached TC/XDP interface lists on the Dashboard.

**Architecture:** Daemon writes `/run/adblocker/state.json` after a successful attach and removes it on Close. New `adblockerctl status [--json]` reads that file (with PID liveness check). TUI polls `status --json`, renders a service panel on the Dashboard, and binds `[s]` to a confirm-then-`sudo systemctl start|stop adblocker` flow.

**Tech Stack:** Go (cilium/ebpf, cobra, encoding/json, syscall.Kill), Rust (ratatui, crossterm, serde_json), systemd (`RuntimeDirectory=`).

**Spec:** `docs/superpowers/specs/2026-04-27-tui-service-control-design.md`.

---

## File Structure

| Path | Action | Responsibility |
|------|--------|----------------|
| `internal/loader/state.go` | create | Marshal/write/remove `state.json`; pure I/O so it's unit-testable. |
| `internal/loader/state_test.go` | create | Tests for `writeState` / `readStateForTest`. |
| `internal/loader/loader.go` | edit | Track per-iface success names; call `writeState` after attach loop, `removeState` in `Close()`. |
| `internal/cli/status.go` | create | `status` cobra subcommand + pure `readStatus(path, alive)` helper. |
| `internal/cli/status_test.go` | create | Table-driven tests for `readStatus` and human formatter. |
| `internal/cli/cli.go` | edit | Register `newStatusCmd()` in `root.AddCommand`. |
| `systemd/adblocker.service` | edit | Add `RuntimeDirectory=adblocker`. |
| `tui/Cargo.toml` | edit | Add `serde_json = "1"`. |
| `tui/src/backend.rs` | edit | `ServiceStatus` struct, `service_status()`, `service_start()`, `service_stop()`. |
| `tui/src/app.rs` | edit | Store service state, poll on tick, new `InputMode::ConfirmService`, `ServiceAction` enum. |
| `tui/src/input.rs` | edit | `[s]` handler in `handle_normal`; new `handle_confirm_service`. |
| `tui/src/ui.rs` | edit | Split Dashboard right column to add service panel; render confirm prompt. |
| `docs/TUI.md` | edit | Document `[s]` and the service panel. |
| `docs/ARCHITECTURE.md` | edit | Document the state file. |

---

## Task 1: Loader state file (write/remove helpers + tests)

**Files:**

- Create: `internal/loader/state.go`
- Create: `internal/loader/state_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/loader/state_test.go`:

```go
package loader

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWriteStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "state.json")

	if err := writeState(path, 4242, []string{"eth0", "wlan0"}, []string{"eth0"}); err != nil {
		t.Fatalf("writeState: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got struct {
		PID int      `json:"pid"`
		TC  []string `json:"tc"`
		XDP []string `json:"xdp"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.PID != 4242 {
		t.Errorf("pid = %d, want 4242", got.PID)
	}
	if !reflect.DeepEqual(got.TC, []string{"eth0", "wlan0"}) {
		t.Errorf("tc = %v", got.TC)
	}
	if !reflect.DeepEqual(got.XDP, []string{"eth0"}) {
		t.Errorf("xdp = %v", got.XDP)
	}
}

func TestWriteStateNilSlicesEncodeAsEmptyArrays(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := writeState(path, 1, nil, nil); err != nil {
		t.Fatalf("writeState: %v", err)
	}
	data, _ := os.ReadFile(path)
	if got := string(data); !contains(got, `"tc":[]`) || !contains(got, `"xdp":[]`) {
		t.Errorf("expected empty arrays, got %s", got)
	}
}

func TestRemoveStateMissingIsOK(t *testing.T) {
	removeState(filepath.Join(t.TempDir(), "nope.json"))
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Run tests and confirm they fail**

```bash
cd /home/sandesh/private/adblocker
go test ./internal/loader/ -run TestWriteState -v
```

Expected: build error (`undefined: writeState`).

- [ ] **Step 3: Write `internal/loader/state.go`**

```go
// Package-internal helpers for the daemon state file. The state file's
// presence is the "running" signal; the CLI reads it to answer
// `adblockerctl status`.
package loader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// StateFile is where the daemon publishes its liveness + attached
// interfaces. Created via systemd's RuntimeDirectory=adblocker; the
// daemon also MkdirAll's the parent as a fallback for non-systemd runs.
const StateFile = "/run/adblocker/state.json"

type stateDoc struct {
	PID int      `json:"pid"`
	TC  []string `json:"tc"`
	XDP []string `json:"xdp"`
}

// writeState marshals and atomically replaces the state file. nil slices
// are encoded as empty arrays so the CLI/TUI never see `null`.
func writeState(path string, pid int, tc, xdp []string) error {
	if tc == nil {
		tc = []string{}
	}
	if xdp == nil {
		xdp = []string{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	data, err := json.Marshal(stateDoc{PID: pid, TC: tc, XDP: xdp})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// removeState is best-effort; an absent file is not an error.
func removeState(path string) {
	_ = os.Remove(path)
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
go test ./internal/loader/ -run TestWriteState -v
go test ./internal/loader/ -run TestRemoveState -v
```

Expected: PASS for all three tests.

- [ ] **Step 5: Commit**

```bash
git add internal/loader/state.go internal/loader/state_test.go
git commit -m "feat(loader): state file write/remove helpers"
```

---

## Task 2: Wire state file into `loader.New` / `loader.Close`

**Files:**

- Modify: `internal/loader/loader.go:103-145` (the attach loop and Close)

- [ ] **Step 1: Edit `loader.go` `New` to track names + write state**

Replace the attach loop (currently at `loader.go:116-145`) with:

```go
	var tcNames, xdpNames []string
	for _, name := range ifaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", name, err)
			continue
		}
		// TC egress is the primary hook.
		tc, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   l.objs.TcEgress,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("attach tc egress on %s: %w", name, err)
		}
		l.tcLnks = append(l.tcLnks, tc)
		tcNames = append(tcNames, name)

		// XDP ingress is best-effort; skip silently if iface refuses.
		xd, err := link.AttachXDP(link.XDPOptions{
			Interface: iface.Index,
			Program:   l.objs.XdpIngress,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "xdp attach skipped on %s: %v\n", name, err)
			continue
		}
		l.xdLnks = append(l.xdLnks, xd)
		xdpNames = append(xdpNames, name)
	}

	if err := writeState(StateFile, os.Getpid(), tcNames, xdpNames); err != nil {
		fmt.Fprintf(os.Stderr, "warn: write state file: %v\n", err)
	}
	return l, nil
}
```

- [ ] **Step 2: Edit `Close()` to remove state file**

Replace `Close()` (currently at `loader.go:186-194`) with:

```go
// Close detaches every link and closes every map / program file
// descriptor. Pins on disk are left in place so AttachExisting still
// works after the daemon restarts.
func (l *Loader) Close() error {
	for _, k := range l.tcLnks {
		_ = k.Close()
	}
	for _, k := range l.xdLnks {
		_ = k.Close()
	}
	removeState(StateFile)
	return l.objs.Close()
}
```

- [ ] **Step 3: Build and vet to verify no regressions**

```bash
go build ./...
go vet ./...
```

Expected: both clean (no output).

- [ ] **Step 4: Commit**

```bash
git add internal/loader/loader.go
git commit -m "feat(loader): publish state.json on attach, remove on close"
```

---

## Task 3: `adblockerctl status` subcommand (pure helper + tests)

**Files:**

- Create: `internal/cli/status.go`
- Create: `internal/cli/status_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/status_test.go`:

```go
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadStatusMissingFile(t *testing.T) {
	r := readStatus(filepath.Join(t.TempDir(), "no.json"), func(int) bool { return true })
	if r.Running {
		t.Errorf("missing file should be stopped, got %+v", r)
	}
}

func TestReadStatusStaleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"pid":4242,"tc":["eth0"],"xdp":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := readStatus(path, func(int) bool { return false })
	if r.Running {
		t.Errorf("stale pid should be stopped, got %+v", r)
	}
}

func TestReadStatusRunning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"pid":4242,"tc":["eth0","wlan0"],"xdp":["eth0"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := readStatus(path, func(int) bool { return true })
	if !r.Running || r.PID != 4242 {
		t.Errorf("got %+v", r)
	}
	if len(r.TC) != 2 || r.TC[0] != "eth0" || r.TC[1] != "wlan0" {
		t.Errorf("tc = %v", r.TC)
	}
	if len(r.XDP) != 1 || r.XDP[0] != "eth0" {
		t.Errorf("xdp = %v", r.XDP)
	}
}

func TestReadStatusGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := readStatus(path, func(int) bool { return true })
	if r.Running {
		t.Errorf("garbage should be stopped, got %+v", r)
	}
}

func TestWriteHumanStopped(t *testing.T) {
	var buf bytes.Buffer
	if err := writeHumanStatus(&buf, statusReport{Running: false}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "stopped") {
		t.Errorf("got %q", buf.String())
	}
}

func TestWriteHumanRunning(t *testing.T) {
	var buf bytes.Buffer
	r := statusReport{Running: true, PID: 4242, TC: []string{"eth0", "wlan0"}, XDP: []string{"eth0"}}
	if err := writeHumanStatus(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"running", "4242", "eth0, wlan0", "eth0"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

func TestWriteJSONStopped(t *testing.T) {
	var buf bytes.Buffer
	if err := writeJSONStatus(&buf, statusReport{Running: false}); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	if got != `{"running":false}` {
		t.Errorf("stopped JSON = %q", got)
	}
}

func TestWriteJSONRunning(t *testing.T) {
	var buf bytes.Buffer
	r := statusReport{Running: true, PID: 4242, TC: []string{"eth0"}, XDP: []string{}}
	if err := writeJSONStatus(&buf, r); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	want := `{"running":true,"pid":4242,"tc":["eth0"],"xdp":[]}`
	if got != want {
		t.Errorf("running JSON\n got: %s\nwant: %s", got, want)
	}
}
```

- [ ] **Step 2: Run tests and confirm they fail**

```bash
go test ./internal/cli/ -run TestReadStatus -v
go test ./internal/cli/ -run TestWrite -v
```

Expected: build error (`undefined: readStatus`, etc.).

- [ ] **Step 3: Write `internal/cli/status.go`**

```go
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/adblocker/adblocker/internal/loader"
	"github.com/spf13/cobra"
)

// statusReport is the in-process representation. Two distinct JSON
// shapes are emitted: stopped -> {"running":false}, running -> the full
// document with pid/tc/xdp.
type statusReport struct {
	Running bool
	PID     int
	TC      []string
	XDP     []string
}

func newStatusCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "show daemon liveness and attached interfaces",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := readStatus(loader.StateFile, isProcessAlive)
			if jsonOut {
				return writeJSONStatus(cmd.OutOrStdout(), r)
			}
			return writeHumanStatus(cmd.OutOrStdout(), r)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON for machine consumers")
	return cmd
}

func readStatus(path string, alive func(pid int) bool) statusReport {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) || err != nil {
		return statusReport{Running: false}
	}
	var doc struct {
		PID int      `json:"pid"`
		TC  []string `json:"tc"`
		XDP []string `json:"xdp"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.PID <= 0 {
		return statusReport{Running: false}
	}
	if !alive(doc.PID) {
		return statusReport{Running: false}
	}
	if doc.TC == nil {
		doc.TC = []string{}
	}
	if doc.XDP == nil {
		doc.XDP = []string{}
	}
	return statusReport{Running: true, PID: doc.PID, TC: doc.TC, XDP: doc.XDP}
}

// isProcessAlive uses kill(pid, 0) which only delivers signal-0
// (no-op): success means the process exists and we can signal it,
// ESRCH means it's gone.
func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return !errors.Is(err, syscall.ESRCH)
}

func writeHumanStatus(w io.Writer, r statusReport) error {
	if !r.Running {
		_, err := fmt.Fprintln(w, "status:  stopped")
		return err
	}
	if _, err := fmt.Fprintf(w, "status:  running (pid %d)\n", r.PID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "tc:      %s\n", joinOrDash(r.TC)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "xdp:     %s\n", joinOrDash(r.XDP))
	return err
}

func writeJSONStatus(w io.Writer, r statusReport) error {
	if !r.Running {
		_, err := fmt.Fprintln(w, `{"running":false}`)
		return err
	}
	tcJSON, _ := json.Marshal(r.TC)
	xdpJSON, _ := json.Marshal(r.XDP)
	_, err := fmt.Fprintf(w,
		`{"running":true,"pid":%d,"tc":%s,"xdp":%s}`+"\n",
		r.PID, tcJSON, xdpJSON,
	)
	return err
}

func joinOrDash(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ", ")
}
```

- [ ] **Step 4: Run tests and confirm they pass**

```bash
go test ./internal/cli/ -run TestReadStatus -v
go test ./internal/cli/ -run TestWrite -v
```

Expected: PASS for all 8 tests.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/status.go internal/cli/status_test.go
git commit -m "feat(cli): adblockerctl status subcommand"
```

---

## Task 4: Register `status` in the cobra root

**Files:**

- Modify: `internal/cli/cli.go:33-42`

- [ ] **Step 1: Edit `cli.go` to register the new command**

Replace the `root.AddCommand(...)` block (currently at `cli.go:33-42`) with:

```go
	root.AddCommand(
		newDaemonCmd(),
		newBlockCmd(),
		newUnblockCmd(),
		newTempBlockCmd(),
		newAllowCmd(),
		newListCmd(),
		newStatsCmd(),
		newStatusCmd(),
		newUpdateCmd(),
	)
```

Also update the file's leading comment block to mention `status -> status.go`. The current comment ends at line 12; add this line before `package cli`:

```go
//	status     -> status.go
```

placed alphabetically (between `stats` and `update`).

- [ ] **Step 2: Build and run --help to confirm wiring**

```bash
go build -o /tmp/adblockerctl ./cmd/adblocker
/tmp/adblockerctl --help | grep status
/tmp/adblockerctl status --help
```

Expected: `status` appears in the available commands list, and `--json` shows in `status --help`.

- [ ] **Step 3: Smoke-test against a non-existent state file**

```bash
ADBLOCKER_TEST_STATE=$(mktemp -d)
# We can't override the const path easily; instead test against the real
# default location. With the daemon not running, the file should not exist.
[ ! -f /run/adblocker/state.json ] && /tmp/adblockerctl status
[ ! -f /run/adblocker/state.json ] && /tmp/adblockerctl status --json
```

Expected: `status:  stopped` and `{"running":false}` respectively.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/cli.go
git commit -m "feat(cli): wire status subcommand into root"
```

---

## Task 5: systemd unit `RuntimeDirectory`

**Files:**

- Modify: `systemd/adblocker.service`

- [ ] **Step 1: Edit the unit**

Add `RuntimeDirectory=adblocker` between `RestartSec=3` and `AmbientCapabilities=`:

```ini
[Service]
Type=simple
ExecStart=/usr/local/bin/adblockerctl daemon --config /etc/adblocker/adblocker.yaml
Restart=on-failure
RestartSec=3
RuntimeDirectory=adblocker
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/sys/fs/bpf
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Validate syntax**

```bash
systemd-analyze verify systemd/adblocker.service || true
```

(Exits non-zero on a host without the unit installed; ignore that — we just want to confirm parse-time validity. Look for "[Unit]/[Service]/[Install]" parsing errors specifically.)

- [ ] **Step 3: Commit**

```bash
git add systemd/adblocker.service
git commit -m "feat(systemd): RuntimeDirectory=adblocker for state.json"
```

---

## Task 6: TUI — add `serde_json` and `ServiceStatus`

**Files:**

- Modify: `tui/Cargo.toml`
- Modify: `tui/src/backend.rs`

- [ ] **Step 1: Add the dependency**

Edit `tui/Cargo.toml` `[dependencies]` block:

```toml
[dependencies]
ratatui    = "0.28"
crossterm  = "0.28"
clap       = { version = "4.5", features = ["derive"] }
anyhow     = "1"
thiserror  = "1"
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 2: Refresh Cargo.lock**

```bash
cd tui
cargo build --locked 2>&1 | head || true   # may fail; we want lock refresh
cargo build                                  # this updates Cargo.lock
```

Expected: `Cargo.lock` updates with `serde_json` entries.

- [ ] **Step 3: Write the failing test for `ServiceStatus` parsing**

Append to the bottom of `tui/src/backend.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::ServiceStatus;

    #[test]
    fn parse_running() {
        let json = r#"{"running":true,"pid":12345,"tc":["eth0","wlan0"],"xdp":["eth0"]}"#;
        let s: ServiceStatus = serde_json::from_str(json).unwrap();
        assert!(s.running);
        assert_eq!(s.pid, Some(12345));
        assert_eq!(s.tc, vec!["eth0".to_string(), "wlan0".to_string()]);
        assert_eq!(s.xdp, vec!["eth0".to_string()]);
    }

    #[test]
    fn parse_stopped() {
        let json = r#"{"running":false}"#;
        let s: ServiceStatus = serde_json::from_str(json).unwrap();
        assert!(!s.running);
        assert!(s.pid.is_none());
        assert!(s.tc.is_empty());
        assert!(s.xdp.is_empty());
    }
}
```

- [ ] **Step 4: Run the test and confirm it fails to compile**

```bash
cargo test --locked 2>&1 | tail -10
```

Expected: error `cannot find type ServiceStatus`.

- [ ] **Step 5: Add `ServiceStatus` and methods to `backend.rs`**

Add these imports near the top of `tui/src/backend.rs`:

```rust
use serde::Deserialize;
```

Then, immediately after the `BlocklistEntry` struct (around the existing line 50), add:

```rust
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServiceStatus {
    pub running: bool,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub tc: Vec<String>,
    #[serde(default)]
    pub xdp: Vec<String>,
}
```

Then, inside `impl Backend` (after `update_lists`, before the closing brace), add:

```rust
    pub fn service_status(&self) -> Result<ServiceStatus> {
        let raw = self.run("status", &["--json"])?;
        let s: ServiceStatus =
            serde_json::from_str(raw.trim()).context("parse status JSON")?;
        Ok(s)
    }

    pub fn service_start(&self) -> Result<String> {
        self.systemctl("start")
    }

    pub fn service_stop(&self) -> Result<String> {
        self.systemctl("stop")
    }

    fn systemctl(&self, action: &str) -> Result<String> {
        let invocation = format!("sudo -n systemctl {} adblocker", action);
        let mut c = match &self.ssh {
            Some(target) => {
                let mut c = Command::new("ssh");
                c.arg("-o")
                    .arg("BatchMode=yes")
                    .arg("-o")
                    .arg("ConnectTimeout=5")
                    .arg(target)
                    .arg(invocation);
                c
            }
            None => {
                let mut c = Command::new("sudo");
                c.arg("-n").arg("systemctl").arg(action).arg("adblocker");
                c
            }
        };
        c.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = c
            .output()
            .with_context(|| format!("systemctl {}", action))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("systemctl {}: {}", action, err.trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
```

- [ ] **Step 6: Run tests + clippy**

```bash
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

Expected: 2 tests pass, clippy clean, fmt clean.

- [ ] **Step 7: Commit**

```bash
cd /home/sandesh/private/adblocker
git add tui/Cargo.toml tui/Cargo.lock tui/src/backend.rs
git commit -m "feat(tui): ServiceStatus + service_status/start/stop backend methods"
```

---

## Task 7: TUI app state — `ServiceAction`, `ConfirmService` mode, polling

**Files:**

- Modify: `tui/src/app.rs`

- [ ] **Step 1: Add the new enum and mode variant**

In `tui/src/app.rs`, edit the `InputMode` enum (around current line 45) to add `ConfirmService`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputMode {
    /// Normal navigation - no edit prompt active.
    Normal,
    /// Adding a new blocklist entry.
    EditingBlock,
    /// Adding a new temp-block: the duration prompt comes after the domain.
    EditingTempDomain,
    EditingTempDuration {
        domain: String,
    },
    /// Adding to the allowlist.
    EditingAllow,
    /// Removing an entry by cleartext domain (the hash is one-way).
    EditingUnblock,
    /// `[s]` was pressed; waiting for y/N to start or stop the daemon.
    ConfirmService {
        action: ServiceAction,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Start,
    Stop,
}

impl ServiceAction {
    pub fn verb(self) -> &'static str {
        match self {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
        }
    }
}
```

- [ ] **Step 2: Import `ServiceStatus` and add it to `App`**

Edit the `use` line at the top of `app.rs`:

```rust
use crate::backend::{Backend, BlocklistEntry, ServiceStatus, Stats};
```

Add a `service` field to the `App` struct (after `stats`):

```rust
pub struct App {
    pub backend: Backend,
    pub tick: Duration,
    pub view: View,
    pub mode: InputMode,
    pub stats: Stats,
    pub service: ServiceStatus,
    pub blocklist: Vec<BlocklistEntry>,
    pub blocklist_cursor: usize,
    pub allowlist_cursor: usize,
    pub log: Vec<String>,
    pub edit_buffer: String,
    pub status: String,
    pub last_refresh: Option<Instant>,
    pub show_help: bool,
    pub should_quit: bool,
}
```

In `App::new`, initialize it:

```rust
            stats: Stats::default(),
            service: ServiceStatus::default(),
            blocklist: Vec::new(),
```

- [ ] **Step 3: Refresh the service status on each tick**

Edit `App::refresh` to also fetch service status. Replace it with:

```rust
    pub fn refresh(&mut self) {
        match self.backend.stats() {
            Ok(s) => self.stats = s,
            Err(e) => self.push_log(format!("[err] stats: {}", e)),
        }
        match self.backend.list() {
            Ok(l) => {
                self.blocklist = l;
                if self.blocklist_cursor >= self.blocklist.len() {
                    self.blocklist_cursor = self.blocklist.len().saturating_sub(1);
                }
            }
            Err(e) => self.push_log(format!("[err] list: {}", e)),
        }
        match self.backend.service_status() {
            Ok(s) => self.service = s,
            Err(e) => self.push_log(format!("[err] status: {}", e)),
        }
        self.last_refresh = Some(Instant::now());
    }
```

- [ ] **Step 4: Route the new mode in `handle_key`**

In `App::handle_key`, add the `ConfirmService` arm:

```rust
    fn handle_key(&mut self, k: KeyEvent) {
        match self.mode {
            InputMode::Normal => input::handle_normal(self, k),
            InputMode::EditingBlock => input::handle_edit(self, k, EditTarget::Block),
            InputMode::EditingTempDomain => input::handle_edit(self, k, EditTarget::TempDomain),
            InputMode::EditingTempDuration { .. } => {
                input::handle_edit(self, k, EditTarget::TempDuration)
            }
            InputMode::EditingAllow => input::handle_edit(self, k, EditTarget::Allow),
            InputMode::EditingUnblock => input::handle_edit(self, k, EditTarget::Unblock),
            InputMode::ConfirmService { .. } => input::handle_confirm_service(self, k),
        }
    }
```

- [ ] **Step 5: Build to confirm app.rs is consistent**

```bash
cd tui
cargo build --locked 2>&1 | tail -5
```

Expected: error from input.rs because `handle_confirm_service` doesn't exist yet — that's fine, fixed in Task 8.

- [ ] **Step 6: Commit**

```bash
cd /home/sandesh/private/adblocker
git add tui/src/app.rs
git commit -m "feat(tui): App.service field, ConfirmService mode, ServiceAction enum"
```

---

## Task 8: TUI input — `[s]` toggle + confirm handler

**Files:**

- Modify: `tui/src/input.rs`

- [ ] **Step 1: Import the new types**

At the top of `tui/src/input.rs`, edit the `use` line:

```rust
use crate::app::{App, EditTarget, InputMode, ServiceAction, View};
```

- [ ] **Step 2: Add the `[s]` arm in `handle_normal`**

Inside `handle_normal`, add this arm just after the existing `[u]` (update lists) arm (around current line 48):

```rust
        (KeyCode::Char('s'), _) => {
            let action = if app.service.running {
                ServiceAction::Stop
            } else {
                ServiceAction::Start
            };
            app.mode = InputMode::ConfirmService { action };
            app.status = format!("{} adblocker daemon? [y/N]", action.verb());
        }
```

- [ ] **Step 3: Add the new handler function**

Append to `tui/src/input.rs`:

```rust
pub fn handle_confirm_service(app: &mut App, k: KeyEvent) {
    let action = match &app.mode {
        InputMode::ConfirmService { action } => *action,
        _ => return,
    };
    let confirmed = matches!(k.code, KeyCode::Char('y') | KeyCode::Char('Y'));
    app.mode = InputMode::Normal;

    if !confirmed {
        app.status = "cancelled".into();
        return;
    }

    let result = match action {
        ServiceAction::Start => app.backend.service_start(),
        ServiceAction::Stop => app.backend.service_stop(),
    };
    match result {
        Ok(out) => {
            app.push_log(format!("[ok ] systemctl {}: {}", action.verb(), out.trim()));
            app.status = format!("systemctl {} ok", action.verb());
        }
        Err(e) => {
            app.push_log(format!("[err] systemctl {}: {}", action.verb(), e));
            app.status = format!("systemctl {} failed: {}", action.verb(), e);
        }
    }
    // Force-refresh service status so the panel updates without waiting
    // for the next tick.
    if let Ok(s) = app.backend.service_status() {
        app.service = s;
    }
}
```

- [ ] **Step 4: Build, lint, format**

```bash
cd tui
cargo build --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

Expected: build clean, clippy clean, fmt clean.

- [ ] **Step 5: Commit**

```bash
cd /home/sandesh/private/adblocker
git add tui/src/input.rs
git commit -m "feat(tui): [s] key toggles service via confirm prompt"
```

---

## Task 9: TUI UI — service panel + help/footer text

**Files:**

- Modify: `tui/src/ui.rs`

- [ ] **Step 1: Add a service panel inside the Dashboard right column**

Replace `draw_dashboard` (currently at `ui.rs:75-145`) with:

```rust
fn draw_dashboard(f: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // counters (left)
    let rows: Vec<Row> = app
        .stats
        .rows()
        .iter()
        .map(|(name, val)| {
            let style = match *name {
                "BLOCKED_DNS" | "BLOCKED_SNI" | "BLOCKED_IP" => {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                }
                _ => Style::default(),
            };
            Row::new(vec![
                Cell::from(*name).style(style),
                Cell::from(format!("{}", val)),
            ])
        })
        .collect();
    let table = Table::new(rows, [Constraint::Length(14), Constraint::Min(8)])
        .header(
            Row::new(vec!["counter", "value"]).style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title(" counters "));
    f.render_widget(table, cols[0]);

    // right column splits: summary on top, service below
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(cols[1]);

    let blocked = app.stats.blocked_dns + app.stats.blocked_sni + app.stats.blocked_ip;
    let seen = app.stats.pkts_seen.max(1);
    let pct = (blocked as f64 / seen as f64) * 100.0;
    let summary = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  blocked",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "    DNS  {}    SNI  {}    IP  {}",
            app.stats.blocked_dns, app.stats.blocked_sni, app.stats.blocked_ip
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  share of seen packets",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("    {:.3}%", pct)),
        Line::from(""),
        Line::from(Span::styled(
            "  blocklist size",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "    {} entries (capped at 50 in list view)",
            app.blocklist.len()
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  shortcuts",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("    [r] refresh   [u] update lists   [s] service   [?] help   [q] quit"),
    ];
    let p = Paragraph::new(summary)
        .block(Block::default().borders(Borders::ALL).title(" summary "))
        .wrap(Wrap { trim: false });
    f.render_widget(p, right[0]);

    f.render_widget(service_panel(app), right[1]);
}

fn service_panel(app: &App) -> Paragraph<'_> {
    let (status_line, action_label) = if app.service.running {
        let pid = app
            .service
            .pid
            .map(|p| format!(" (pid {})", p))
            .unwrap_or_default();
        (
            Line::from(vec![
                Span::raw("status:  "),
                Span::styled(
                    "RUNNING",
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ),
                Span::raw(pid),
            ]),
            "[s] stop adblocker",
        )
    } else {
        (
            Line::from(vec![
                Span::raw("status:  "),
                Span::styled(
                    "STOPPED",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ]),
            "[s] start adblocker",
        )
    };

    let tc = if app.service.tc.is_empty() {
        "-".to_string()
    } else {
        app.service.tc.join(", ")
    };
    let xdp = if app.service.xdp.is_empty() {
        "-".to_string()
    } else {
        app.service.xdp.join(", ")
    };

    let mut lines = vec![status_line];
    if app.service.running {
        lines.push(Line::from(format!("tc:      {}", tc)));
        lines.push(Line::from(format!("xdp:     {}", xdp)));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  {}", action_label),
        Style::default().add_modifier(Modifier::BOLD),
    )));

    Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" service "))
        .wrap(Wrap { trim: false })
}
```

- [ ] **Step 2: Render the confirm prompt in the footer**

In `draw_footer` (currently at `ui.rs:245-273`), extend the `prompt` `match` arm to handle `ConfirmService`:

```rust
    let prompt = match &app.mode {
        InputMode::Normal => " ".to_string(),
        InputMode::EditingBlock => format!(" block> {}_", app.edit_buffer),
        InputMode::EditingAllow => format!(" allow> {}_", app.edit_buffer),
        InputMode::EditingUnblock => format!(" unblock> {}_", app.edit_buffer),
        InputMode::EditingTempDomain => format!(" temp-block (domain)> {}_", app.edit_buffer),
        InputMode::EditingTempDuration { domain } => {
            format!(" temp-block {} for> {}_", domain, app.edit_buffer)
        }
        InputMode::ConfirmService { action } => {
            format!(" {} adblocker daemon? press [y] to confirm, any other key to cancel", action.verb())
        }
    };
```

Also add the `use` import for `ServiceAction` at the top of `ui.rs` if needed — but since `ConfirmService { action }` is matched without referencing `ServiceAction` directly, only `action.verb()` is called, so the existing `use crate::app::{App, InputMode, View};` needs `ServiceAction` added:

```rust
use crate::app::{App, InputMode, ServiceAction, View};
```

(It must be imported even though we only call a method on `action` — Rust's name resolution still needs the type in scope for method lookup if it's referenced explicitly; not strictly necessary here, but include it so future edits don't trip.)

- [ ] **Step 3: Update help overlay to mention `[s]`**

In `draw_help_overlay` (currently at `ui.rs:275-310`), add this line to `help_text` between the existing `u` and `?` lines:

```rust
        Line::from("    s                  start/stop adblocker daemon (with confirm)"),
```

Place it right after the `Line::from("    u                  update upstream lists"),` line.

- [ ] **Step 4: Build, test, lint, format**

```bash
cd tui
cargo build --locked
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

Expected: all clean.

- [ ] **Step 5: Commit**

```bash
cd /home/sandesh/private/adblocker
git add tui/src/ui.rs
git commit -m "feat(tui): service panel on Dashboard + confirm prompt + help"
```

---

## Task 10: Documentation updates

**Files:**

- Modify: `docs/TUI.md`
- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Document the `[s]` key in `docs/TUI.md`**

Find the keybindings table (around line 115 — the table with `| char | meaning |`). Locate the section that lists key shortcuts (the markdown table that documents `[a]`, `[t]`, `[d]`, `[u]`, etc.) and add a row for `[s]`. The table is the one starting near `Flags are a packed string:`. If a separate "shortcuts" listing exists in the file, add the row in the same format. Concretely: search for the line containing `[u]` and insert the new key right below it. The new row should read:

```markdown
| `[s]` | start/stop the daemon (confirm with `y`) — calls `sudo systemctl start|stop adblocker` under the hood |
```

If no exact table is found, append a new "Service control" subsection just before the "Troubleshooting" heading:

```markdown
## Service control

Press `[s]` on the Dashboard to start or stop the daemon. The TUI reads
the current state from `adblockerctl status --json` (which checks
`/run/adblocker/state.json`). After confirmation (`y`), the TUI shells
out to `sudo -n systemctl start|stop adblocker`. Failures are reported
in the footer status line.

The Dashboard's **service** panel shows the live attached interfaces:

- `tc:` — interfaces where the egress program is bound.
- `xdp:` — subset where the ingress program also attached (best-effort).
```

- [ ] **Step 2: Document the state file in `docs/ARCHITECTURE.md`**

Append a new section before the "TUI ↔ CLI" section (around the existing line `## 11. TUI ↔ CLI`). Insert this section as `## 10b. Daemon state file` (or just `## 10b.` between current 10 and 11, renumbering only if conventions require — this project numbers sections, but keep the lift small):

````markdown
## Daemon state file

The daemon publishes a tiny JSON document on every successful attach so
that any out-of-process consumer (CLI, TUI, monitoring) can answer the
question "is it running and to which interfaces?":

```text
/run/adblocker/state.json
{"pid": 12345, "tc": ["eth0","wlan0"], "xdp": ["eth0"]}
```

`tc` lists every interface where `link.AttachTCX` succeeded; `xdp` is
the subset where `link.AttachXDP` (best-effort, generic mode) also
succeeded. The file is written by `loader.New` after the attach loop
and removed by `Loader.Close()` on `SIGINT`/`SIGTERM`.

`adblockerctl status [--json]` reads this file and probes liveness via
`kill(pid, 0)`. The directory `/run/adblocker` is created by systemd
(`RuntimeDirectory=adblocker` in the unit) and as a fallback by
`os.MkdirAll` in the daemon — non-systemd direct-launch workflows still
get a usable state file.
````

- [ ] **Step 3: Run markdownlint to make sure the changes pass CI**

```bash
cd /home/sandesh/private/adblocker
npx --yes markdownlint-cli2@0.13.0 --config .markdownlint.yaml "**/*.md" 2>&1 | tail -10
```

Expected: `Summary: 0 error(s)`.

- [ ] **Step 4: Commit**

```bash
git add docs/TUI.md docs/ARCHITECTURE.md
git commit -m "docs: TUI [s] key + service panel + state file"
```

---

## Task 11: End-to-end smoke test

**Files:** none modified.

- [ ] **Step 1: Build everything**

```bash
cd /home/sandesh/private/adblocker
go build -o /tmp/adblockerctl ./cmd/adblocker
cd tui && cargo build --release --locked && cd ..
```

Expected: both binaries produced without errors.

- [ ] **Step 2: Verify the new CLI behavior offline**

```bash
# The daemon isn't running on the dev box; status should report stopped.
[ ! -e /run/adblocker/state.json ] && /tmp/adblockerctl status
[ ! -e /run/adblocker/state.json ] && /tmp/adblockerctl status --json
```

Expected:

```text
status:  stopped
{"running":false}
```

- [ ] **Step 3: Document the manual smoke test**

This step has no commit; just record in your shell what you'd run on a
real Linux host where the daemon and unit are installed:

```bash
sudo make install                       # ships the new unit + binary
sudo systemctl start adblocker
adblockerctl status                     # should show running + ifaces
adblockerctl status --json
./tui/target/release/adblocker-tui      # press [s] -> stop -> [s] -> start
```

- [ ] **Step 4: Final lint sweep (no commit)**

```bash
go vet ./...
go test -race -count=1 ./...
cd tui && cargo test --locked && cargo clippy --all-targets --locked -- -D warnings && cargo fmt --all -- --check && cd ..
npx --yes markdownlint-cli2@0.13.0 --config .markdownlint.yaml "**/*.md"
```

Expected: every command exits 0 with no errors.

---

## Self-review notes

- **Spec coverage:** every component (state file, CLI status, TUI panel + toggle) maps to at least one task. Edge cases (missing/garbage/stale state file) are tested in Task 3.
- **Type consistency:** `ServiceStatus` is the same struct everywhere (Rust). `ServiceAction.verb()` is the only stringification path. `statusReport` is the single Go-side struct.
- **No placeholders:** every step has full code or full commands.
- **Out of scope (per spec):** "pause" mode, IPv6, container init systems, polkit setup. Not in this plan.
