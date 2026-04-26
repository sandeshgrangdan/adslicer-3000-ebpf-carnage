//! Ratatui drawing.

use crate::app::{App, InputMode, View};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table,
        Tabs, Wrap,
    },
    Frame,
};

pub fn draw(f: &mut Frame, app: &mut App) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tab strip
            Constraint::Min(1),    // body
            Constraint::Length(3), // input + status
        ])
        .split(size);

    draw_tabs(f, chunks[0], app);
    match app.view {
        View::Dashboard => draw_dashboard(f, chunks[1], app),
        View::Blocklist => draw_blocklist(f, chunks[1], app),
        View::Allowlist => draw_allowlist(f, chunks[1], app),
        View::Events => draw_events(f, chunks[1], app),
    }
    draw_footer(f, chunks[2], app);

    if app.show_help {
        draw_help_overlay(f, size);
    }
}

fn draw_tabs(f: &mut Frame, area: Rect, app: &App) {
    let titles: Vec<Line> = [View::Dashboard, View::Blocklist, View::Allowlist, View::Events]
        .iter()
        .map(|v| Line::from(v.label()))
        .collect();
    let idx = match app.view {
        View::Dashboard => 0,
        View::Blocklist => 1,
        View::Allowlist => 2,
        View::Events => 3,
    };
    let title = format!(
        " ebpf-adblocker  ·  {} ",
        if app.backend_label().is_empty() {
            "local".to_string()
        } else {
            app.backend_label()
        }
    );
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(title))
        .select(idx)
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, area);
}

fn draw_dashboard(f: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // counters
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
            Row::new(vec!["counter", "value"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title(" counters "));
    f.render_widget(table, cols[0]);

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
        Line::from(format!("    {} entries (capped at 50 in list view)", app.blocklist.len())),
        Line::from(""),
        Line::from(Span::styled(
            "  shortcuts",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("    [r] refresh   [u] update upstream lists   [?] help   [q] quit"),
    ];
    let p = Paragraph::new(summary)
        .block(Block::default().borders(Borders::ALL).title(" summary "))
        .wrap(Wrap { trim: false });
    f.render_widget(p, cols[1]);
}

fn draw_blocklist(f: &mut Frame, area: Rect, app: &mut App) {
    let header = Row::new(vec!["#", "hash", "flags", "expires_at"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = app
        .blocklist
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let exp = match e.expires_at {
                Some(v) => format!("{}", v),
                None => "-".into(),
            };
            Row::new(vec![
                Cell::from(format!("{}", i + 1)),
                Cell::from(format!("{:016x}", e.hash)),
                Cell::from(e.flags.clone()),
                Cell::from(exp),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(4),
        Constraint::Length(18),
        Constraint::Length(7),
        Constraint::Min(12),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" blocklist (first 50)  ·  [a] add  [t] temp-block  [d] unblock  [r] refresh "),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    let mut state = ratatui::widgets::TableState::default();
    state.select(Some(app.blocklist_cursor));
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_allowlist(f: &mut Frame, area: Rect, app: &mut App) {
    let entries: Vec<&crate::backend::BlocklistEntry> = app
        .blocklist
        .iter()
        .filter(|e| e.flags.contains('A'))
        .collect();

    let items: Vec<ListItem> = entries
        .iter()
        .map(|e| ListItem::from(format!("{:016x}    {}", e.hash, e.flags)))
        .collect();

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(app.allowlist_cursor.min(items.len() - 1)));
    }
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" allowlist (ALLOW flag set)  ·  [a] add "),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_events(f: &mut Frame, area: Rect, app: &App) {
    let lines: Vec<ListItem> = app
        .log
        .iter()
        .rev()
        .take(area.height as usize - 2)
        .map(|s| {
            let style = if s.contains("[err]") {
                Style::default().fg(Color::Red)
            } else if s.contains("[ok ]") {
                Style::default().fg(Color::Green)
            } else {
                Style::default()
            };
            ListItem::new(Span::styled(s.clone(), style))
        })
        .collect();
    let list = List::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" events (latest first) "),
    );
    f.render_widget(list, area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    // Two rows: input prompt (when editing) + status bar.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    let prompt = match &app.mode {
        InputMode::Normal => " ".to_string(),
        InputMode::EditingBlock => format!(" block> {}_", app.edit_buffer),
        InputMode::EditingAllow => format!(" allow> {}_", app.edit_buffer),
        InputMode::EditingUnblock => format!(" unblock> {}_", app.edit_buffer),
        InputMode::EditingTempDomain => format!(" temp-block (domain)> {}_", app.edit_buffer),
        InputMode::EditingTempDuration { domain } => {
            format!(" temp-block {} for> {}_", domain, app.edit_buffer)
        }
    };
    let p = Paragraph::new(prompt).style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(p, chunks[0]);

    let status = format!(" {} ", app.status);
    let s = Paragraph::new(status).style(Style::default().fg(Color::White).bg(Color::DarkGray));
    f.render_widget(s, chunks[1]);
}

fn draw_help_overlay(f: &mut Frame, area: Rect) {
    let w = area.width.saturating_sub(8).min(72);
    let h = 18.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect::new(x, y, w, h);
    f.render_widget(Clear, rect);

    let help_text = vec![
        Line::from(Span::styled("  shortcuts", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from("    Tab / →            next view"),
        Line::from("    Shift+Tab / ←      previous view"),
        Line::from("    1 / 2 / 3 / 4      jump to a specific view"),
        Line::from("    j / k or ↓ / ↑     navigate the list"),
        Line::from("    a                  add entry (Block / Allow view)"),
        Line::from("    t                  temp-block (Block view) - prompts for duration"),
        Line::from("    d / Del / U        unblock by cleartext name (hash is one-way)"),
        Line::from("    r                  refresh stats + list"),
        Line::from("    u                  update upstream lists"),
        Line::from("    ?  / F1            toggle this help"),
        Line::from("    q  / Ctrl-C        quit"),
        Line::from(""),
        Line::from(Span::styled("  press any key to dismiss", Style::default().fg(Color::DarkGray))),
    ];
    let p = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title(" help "))
        .wrap(Wrap { trim: false });
    f.render_widget(p, rect);
}

impl App {
    fn backend_label(&self) -> String {
        // Matches the Args fields the user asked to render in the title.
        // We don't keep a copy of Args; reconstruct a label by checking
        // env-like state instead. The TUI doesn't currently expose the
        // ssh target, so just report "local" or "remote".
        String::new()
    }
}
