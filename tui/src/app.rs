//! App state and run loop.

use crate::backend::{Backend, BlocklistEntry, Stats};
use crate::input;
use anyhow::Result;
use crossterm::event::{self, Event, KeyEvent};
use ratatui::{backend::Backend as RatatuiBackend, Terminal};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Dashboard,
    Blocklist,
    Allowlist,
    Events,
}

impl View {
    pub fn next(self) -> Self {
        match self {
            View::Dashboard => View::Blocklist,
            View::Blocklist => View::Allowlist,
            View::Allowlist => View::Events,
            View::Events => View::Dashboard,
        }
    }
    pub fn prev(self) -> Self {
        match self {
            View::Dashboard => View::Events,
            View::Blocklist => View::Dashboard,
            View::Allowlist => View::Blocklist,
            View::Events => View::Allowlist,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            View::Dashboard => "Dashboard",
            View::Blocklist => "Blocklist",
            View::Allowlist => "Allowlist",
            View::Events => "Events",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputMode {
    /// Normal navigation - no edit prompt active.
    Normal,
    /// Adding a new blocklist entry.
    EditingBlock,
    /// Adding a new temp-block: the duration prompt comes after the domain.
    EditingTempDomain,
    EditingTempDuration { domain: String },
    /// Adding to the allowlist.
    EditingAllow,
    /// Removing an entry by cleartext domain (the hash is one-way).
    EditingUnblock,
}

pub struct App {
    pub backend: Backend,
    pub tick: Duration,
    pub view: View,
    pub mode: InputMode,
    pub stats: Stats,
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

impl App {
    pub fn new(backend: Backend, tick: Duration) -> Self {
        Self {
            backend,
            tick,
            view: View::Dashboard,
            mode: InputMode::Normal,
            stats: Stats::default(),
            blocklist: Vec::new(),
            blocklist_cursor: 0,
            allowlist_cursor: 0,
            log: Vec::with_capacity(256),
            edit_buffer: String::new(),
            status: "press `?` for help".into(),
            last_refresh: None,
            show_help: false,
            should_quit: false,
        }
    }

    pub fn push_log(&mut self, line: String) {
        self.log.push(line);
        if self.log.len() > 500 {
            self.log.drain(0..self.log.len() - 500);
        }
    }

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
        self.last_refresh = Some(Instant::now());
    }

    pub fn run<B: RatatuiBackend>(&mut self, term: &mut Terminal<B>) -> Result<()> {
        // First refresh up front so the dashboard isn't empty.
        self.refresh();

        let mut last_tick = Instant::now();
        loop {
            term.draw(|f| crate::ui::draw(f, self))?;

            let timeout = self
                .tick
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_millis(0));
            if event::poll(timeout)? {
                match event::read()? {
                    Event::Key(k) => self.handle_key(k),
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }
            if last_tick.elapsed() >= self.tick {
                if matches!(self.mode, InputMode::Normal) {
                    self.refresh();
                }
                last_tick = Instant::now();
            }
            if self.should_quit {
                break;
            }
        }
        Ok(())
    }

    fn handle_key(&mut self, k: KeyEvent) {
        match self.mode {
            InputMode::Normal => input::handle_normal(self, k),
            InputMode::EditingBlock => input::handle_edit(self, k, EditTarget::Block),
            InputMode::EditingTempDomain => {
                input::handle_edit(self, k, EditTarget::TempDomain)
            }
            InputMode::EditingTempDuration { .. } => {
                input::handle_edit(self, k, EditTarget::TempDuration)
            }
            InputMode::EditingAllow => input::handle_edit(self, k, EditTarget::Allow),
            InputMode::EditingUnblock => input::handle_edit(self, k, EditTarget::Unblock),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EditTarget {
    Block,
    TempDomain,
    TempDuration,
    Allow,
    Unblock,
}
