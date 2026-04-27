//! Wrapper around the `adblockerctl` CLI. Every TUI action funnels
//! through here. Output is parsed into structured types so the UI
//! layer stays free of regex.

use anyhow::{anyhow, bail, Context, Result};
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Backend {
    binary: String,
    sudo: bool,
    ssh: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub pkts_seen: u64,
    pub dns_parsed: u64,
    pub sni_parsed: u64,
    pub blocked_dns: u64,
    pub blocked_sni: u64,
    pub blocked_ip: u64,
    pub passed: u64,
}

impl Stats {
    pub fn rows(&self) -> [(&'static str, u64); 7] {
        [
            ("PKTS_SEEN", self.pkts_seen),
            ("DNS_PARSED", self.dns_parsed),
            ("SNI_PARSED", self.sni_parsed),
            ("BLOCKED_DNS", self.blocked_dns),
            ("BLOCKED_SNI", self.blocked_sni),
            ("BLOCKED_IP", self.blocked_ip),
            ("PASSED", self.passed),
        ]
    }
}

/// One row of `adblockerctl list` output. The CLI gives us hash, flag,
/// and expiry; the original cleartext name is one-way-hashed and not
/// recoverable, but we display whatever the user typed via `block`
/// during this TUI session in `entered_name` (best-effort cache).
#[derive(Debug, Clone)]
pub struct BlocklistEntry {
    pub hash: u64,
    pub flags: String, // "B", "BT", "A", etc.
    pub expires_at: Option<u64>,
}

impl Backend {
    pub fn new(args: &crate::Args) -> Self {
        Self {
            binary: args.adblockerctl.clone(),
            sudo: !args.no_sudo,
            ssh: args.ssh.clone(),
        }
    }

    /// Build the command to run on whatever side actually executes the
    /// `adblockerctl` invocation. On macOS via `--ssh user@host`, that
    /// host is a remote Linux box.
    fn cmd(&self, sub: &str, args: &[&str]) -> Command {
        let mut full: Vec<String> = Vec::with_capacity(8 + args.len());
        if self.sudo {
            full.push("sudo".into());
            full.push("-n".into()); // never prompt; let the call fail loudly instead
        }
        full.push(self.binary.clone());
        full.push(sub.into());
        for a in args {
            full.push((*a).into());
        }

        match &self.ssh {
            Some(target) => {
                let remote_line = full.join(" ");
                let mut c = Command::new("ssh");
                c.arg("-o")
                    .arg("BatchMode=yes")
                    .arg("-o")
                    .arg("ConnectTimeout=5")
                    .arg(target)
                    .arg(remote_line);
                c
            }
            None => {
                let mut c = Command::new(&full[0]);
                c.args(&full[1..]);
                c
            }
        }
    }

    fn run(&self, sub: &str, args: &[&str]) -> Result<String> {
        let mut c = self.cmd(sub, args);
        c.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = c
            .output()
            .with_context(|| format!("run adblockerctl {}", sub))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("adblockerctl {} failed: {}", sub, err.trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    pub fn stats(&self) -> Result<Stats> {
        let raw = self.run("stats", &[])?;
        let mut s = Stats::default();
        for line in raw.lines() {
            let mut it = line.split_whitespace();
            let (Some(name), Some(val)) = (it.next(), it.next()) else {
                continue;
            };
            let v: u64 = match val.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            match name {
                "PKTS_SEEN" => s.pkts_seen = v,
                "DNS_PARSED" => s.dns_parsed = v,
                "SNI_PARSED" => s.sni_parsed = v,
                "BLOCKED_DNS" => s.blocked_dns = v,
                "BLOCKED_SNI" => s.blocked_sni = v,
                "BLOCKED_IP" => s.blocked_ip = v,
                "PASSED" => s.passed = v,
                _ => {}
            }
        }
        Ok(s)
    }

    pub fn list(&self) -> Result<Vec<BlocklistEntry>> {
        let raw = self.run("list", &[])?;
        let mut out = Vec::new();
        for line in raw.lines().skip(1) {
            // Header: "HASH      FLAGS    EXPIRES_AT"
            let line = line.trim();
            if line.is_empty() || line.starts_with("shown:") {
                continue;
            }
            let mut it = line.split_whitespace();
            let (Some(hash_hex), Some(flags), expires) = (it.next(), it.next(), it.next()) else {
                continue;
            };
            let hash = match u64::from_str_radix(hash_hex, 16) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let expires_at = expires
                .filter(|s| *s != "-")
                .and_then(|s| s.parse::<u64>().ok());
            out.push(BlocklistEntry {
                hash,
                flags: flags.into(),
                expires_at,
            });
        }
        Ok(out)
    }

    pub fn block(&self, domain: &str) -> Result<String> {
        validate_domain(domain)?;
        self.run("block", &[domain])
    }

    pub fn unblock(&self, domain: &str) -> Result<String> {
        validate_domain(domain)?;
        self.run("unblock", &[domain])
    }

    pub fn temp_block(&self, domain: &str, dur: Duration) -> Result<String> {
        validate_domain(domain)?;
        // Render a Go time.Duration string (e.g. "2h" or "30m"). Round
        // to whole minutes so the spelling stays clean.
        let mins = dur.as_secs() / 60;
        let spec = if mins > 0 && mins.is_multiple_of(60) {
            format!("{}h", mins / 60)
        } else {
            format!("{}m", mins.max(1))
        };
        self.run("temp-block", &[domain, &spec])
    }

    pub fn allow(&self, domain: &str) -> Result<String> {
        validate_domain(domain)?;
        self.run("allow", &[domain])
    }

    pub fn update_lists(&self) -> Result<String> {
        self.run("update", &[])
    }
}

/// Match the strict regex used in `internal/lists`: lowercase ASCII
/// labels, at least one dot, total length 1..253. We don't lowercase
/// here - the daemon-side validator does, and we want to surface bad
/// input to the user verbatim.
fn validate_domain(d: &str) -> Result<()> {
    let s = d.trim().to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 {
        return Err(anyhow!("invalid domain: {:?}", d));
    }
    if !s.contains('.') {
        return Err(anyhow!("missing TLD: {:?}", d));
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(anyhow!("invalid label in {:?}", d));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(anyhow!("label can't start/end with '-': {:?}", d));
        }
        for c in label.bytes() {
            let ok = c.is_ascii_alphanumeric() || c == b'-';
            if !ok {
                return Err(anyhow!("disallowed char {:?} in {:?}", c as char, d));
            }
        }
    }
    Ok(())
}
