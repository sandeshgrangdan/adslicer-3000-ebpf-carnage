# Security policy

## Supported versions

We support the latest minor release line. Older lines receive critical
fixes only at maintainer discretion.

| version | supported            |
| ------- | -------------------- |
| 0.x     | :white_check_mark: (active) |
| < 0.1   | :x:                  |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (`Security` tab → `Report a vulnerability`).

If that's unavailable for some reason, email
`security@<your-domain>` (replace with your maintainer email when
you fork). Encrypt with GPG if the report is sensitive.

Please include:

- A clear description of the issue.
- Steps to reproduce, ideally with a minimal proof of concept.
- The version (`adblockerctl --version`) and kernel
  (`uname -r`) you tested against.
- The impact you believe this has on users.

## Response targets

- **Acknowledgment**: within 72 hours.
- **Triage**: within 7 days, with an initial assessment of severity
  and likely fix timeline.
- **Public disclosure**: coordinated with the reporter; we aim to
  ship a fix and disclose within 90 days of the original report,
  per industry norms.

## What we consider in scope

- Kernel program: bypass of the blocking layers, OOB reads, programs
  that fail to load with the verifier.
- Userspace daemon: remote / local privilege escalation, map
  corruption, pinned-map permission slips.
- CLI / TUI: arbitrary command execution via crafted input,
  authentication bypass for the SSH transport.
- List ingestion: parser crashes, OOM via crafted feeds, ReDoS in
  validation regexes.

## What we do not consider in scope

- The fact that this project does not block IPv6 (documented limit).
- The fact that TLS 1.3 ECH evades SNI inspection (documented).
- The fact that domain names are stored as one-way hashes (this is a
  feature, not a bug).
- DoS via deliberately misconfiguring the daemon.

## Hall of fame

Reporters who follow this process will be credited (with their
permission) in [CHANGELOG.md](CHANGELOG.md) and the GitHub Security
Advisory.
