//! adblocker-tui - Ratatui frontend for ebpf-adblocker.
//!
//! The TUI never touches BPF maps directly. Every action (block,
//! unblock, list, stats, update) shells out to `adblockerctl`, either
//! locally on a Linux host or through SSH for managing a remote box
//! from macOS. That keeps the user-space logic in one place and the
//! TUI honest: anything you can do here you can also do from the
//! command line.

mod app;
mod backend;
mod input;
mod ui;

use anyhow::{Context, Result};
use app::App;
use backend::Backend;
use clap::Parser;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{io, time::Duration};

/// CLI args for the TUI.
#[derive(Parser, Debug, Clone)]
#[command(name = "adblocker-tui", about, version)]
pub struct Args {
    /// Run `adblockerctl` over SSH against this user@host instead of
    /// locally. Useful on macOS, where eBPF doesn't exist.
    #[arg(long)]
    pub ssh: Option<String>,

    /// Path or name of the `adblockerctl` binary on the target host.
    #[arg(long, default_value = "adblockerctl")]
    pub adblockerctl: String,

    /// Don't prefix `adblockerctl` invocations with `sudo`. By default
    /// we use sudo because the BPF maps need CAP_BPF; pass --no-sudo
    /// if you're already root or have configured a polkit rule.
    #[arg(long, default_value_t = false)]
    pub no_sudo: bool,

    /// Refresh interval (ms) for stats/blocklist polling.
    #[arg(long, default_value_t = 1500)]
    pub refresh_ms: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let backend = Backend::new(&args);
    let tick = Duration::from_millis(args.refresh_ms);

    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).context("enter alt screen")?;
    let term_backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(term_backend).context("init terminal")?;

    let mut app = App::new(backend, tick);
    let res = app.run(&mut terminal);

    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();

    res
}
