//! Keyboard handlers split from app.rs to keep the state struct small.

use crate::app::{App, EditTarget, InputMode, View};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;

pub fn handle_normal(app: &mut App, k: KeyEvent) {
    if app.show_help {
        // Any key dismisses the help overlay.
        app.show_help = false;
        return;
    }

    match (k.code, k.modifiers) {
        // global
        (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }
        (KeyCode::Char('?'), _) | (KeyCode::F(1), _) => {
            app.show_help = true;
        }
        (KeyCode::Tab, _) | (KeyCode::Char('l'), _) | (KeyCode::Right, _) => {
            app.view = app.view.next();
        }
        (KeyCode::BackTab, _) | (KeyCode::Char('h'), _) | (KeyCode::Left, _) => {
            app.view = app.view.prev();
        }
        (KeyCode::Char('1'), _) => app.view = View::Dashboard,
        (KeyCode::Char('2'), _) => app.view = View::Blocklist,
        (KeyCode::Char('3'), _) => app.view = View::Allowlist,
        (KeyCode::Char('4'), _) => app.view = View::Events,

        (KeyCode::Char('r'), _) => {
            app.status = "refreshing...".into();
            app.refresh();
            app.status = "refreshed".into();
        }

        (KeyCode::Char('u'), _) => match app.backend.update_lists() {
            Ok(s) => {
                app.push_log(format!("[ok ] update: {}", s.trim()));
                app.status = "list update triggered".into();
            }
            Err(e) => {
                app.push_log(format!("[err] update: {}", e));
                app.status = "update failed (see Events)".into();
            }
        },

        // view-specific
        (KeyCode::Char('a'), _) => match app.view {
            View::Blocklist => {
                app.mode = InputMode::EditingBlock;
                app.edit_buffer.clear();
                app.status = "type a domain to BLOCK, Enter to confirm, Esc to cancel".into();
            }
            View::Allowlist => {
                app.mode = InputMode::EditingAllow;
                app.edit_buffer.clear();
                app.status = "type a domain to ALLOW, Enter to confirm, Esc to cancel".into();
            }
            _ => {
                app.status = "switch to Blocklist or Allowlist first".into();
            }
        },

        (KeyCode::Char('t'), _) if app.view == View::Blocklist => {
            app.mode = InputMode::EditingTempDomain;
            app.edit_buffer.clear();
            app.status = "type a domain for TEMP-BLOCK, Enter, Esc to cancel".into();
        }

        (KeyCode::Char('d'), _) | (KeyCode::Delete, _) | (KeyCode::Char('U'), _)
            if app.view == View::Blocklist =>
        {
            // We can only unblock by cleartext domain - the kernel map is keyed
            // on the FNV-1a hash of the lowercased name, which is one-way. So
            // we prompt the user for the name to unblock; the highlighted row
            // is informational only.
            app.mode = InputMode::EditingUnblock;
            app.edit_buffer.clear();
            if let Some(e) = app.blocklist.get(app.blocklist_cursor) {
                app.status = format!(
                    "type cleartext name to UNBLOCK (highlighted hash: {:016x}), Enter to confirm",
                    e.hash
                );
            } else {
                app.status = "type cleartext name to UNBLOCK, Enter to confirm".into();
            }
        }

        (KeyCode::Up, _) | (KeyCode::Char('k'), _) => match app.view {
            View::Blocklist if app.blocklist_cursor > 0 => {
                app.blocklist_cursor -= 1;
            }
            View::Allowlist if app.allowlist_cursor > 0 => {
                app.allowlist_cursor -= 1;
            }
            _ => {}
        },
        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => match app.view {
            View::Blocklist if app.blocklist_cursor + 1 < app.blocklist.len() => {
                app.blocklist_cursor += 1;
            }
            View::Allowlist => {
                app.allowlist_cursor += 1;
            }
            _ => {}
        },

        _ => {}
    }
}

pub fn handle_edit(app: &mut App, k: KeyEvent, target: EditTarget) {
    match k.code {
        KeyCode::Esc => {
            app.mode = InputMode::Normal;
            app.edit_buffer.clear();
            app.status = "cancelled".into();
        }
        KeyCode::Backspace => {
            app.edit_buffer.pop();
        }
        KeyCode::Char(c) => {
            // No control modifiers; that's how Esc/^C arrive.
            if !k.modifiers.contains(KeyModifiers::CONTROL) {
                app.edit_buffer.push(c);
            } else if c == 'c' {
                app.should_quit = true;
            }
        }
        KeyCode::Enter => {
            let buf = std::mem::take(&mut app.edit_buffer);
            commit(app, target, buf);
        }
        _ => {}
    }
}

fn commit(app: &mut App, target: EditTarget, buf: String) {
    let buf = buf.trim().to_string();
    if buf.is_empty() {
        app.status = "empty input - nothing to do".into();
        app.mode = InputMode::Normal;
        return;
    }
    match target {
        EditTarget::Block => match app.backend.block(&buf) {
            Ok(out) => {
                app.push_log(format!("[ok ] block {}: {}", buf, out.trim()));
                app.status = format!("blocked: {}", buf);
                app.mode = InputMode::Normal;
                app.refresh();
            }
            Err(e) => {
                app.push_log(format!("[err] block {}: {}", buf, e));
                app.status = format!("block failed: {}", e);
                app.mode = InputMode::Normal;
            }
        },
        EditTarget::Unblock => match app.backend.unblock(&buf) {
            Ok(out) => {
                app.push_log(format!("[ok ] unblock {}: {}", buf, out.trim()));
                app.status = format!("unblocked: {}", buf);
                app.mode = InputMode::Normal;
                app.refresh();
            }
            Err(e) => {
                app.push_log(format!("[err] unblock {}: {}", buf, e));
                app.status = format!("unblock failed: {}", e);
                app.mode = InputMode::Normal;
            }
        },
        EditTarget::Allow => match app.backend.allow(&buf) {
            Ok(out) => {
                app.push_log(format!("[ok ] allow {}: {}", buf, out.trim()));
                app.status = format!("allowed: {}", buf);
                app.mode = InputMode::Normal;
                app.refresh();
            }
            Err(e) => {
                app.push_log(format!("[err] allow {}: {}", buf, e));
                app.status = format!("allow failed: {}", e);
                app.mode = InputMode::Normal;
            }
        },
        EditTarget::TempDomain => {
            // Validate domain shape now so the user gets immediate feedback
            // before the duration prompt.
            if let Err(e) = quick_check_domain(&buf) {
                app.status = format!("invalid: {}", e);
                app.mode = InputMode::Normal;
                return;
            }
            app.mode = InputMode::EditingTempDuration { domain: buf };
            app.status = "duration (e.g. 30m or 2h), Enter to confirm".into();
        }
        EditTarget::TempDuration => {
            let domain = match &app.mode {
                InputMode::EditingTempDuration { domain } => domain.clone(),
                _ => return,
            };
            match parse_duration(&buf) {
                Err(e) => {
                    app.status = format!("bad duration {:?}: {}", buf, e);
                    app.mode = InputMode::Normal;
                }
                Ok(dur) => match app.backend.temp_block(&domain, dur) {
                    Ok(out) => {
                        app.push_log(format!(
                            "[ok ] temp-block {} {}: {}",
                            domain,
                            buf,
                            out.trim()
                        ));
                        app.status = format!("temp-blocked {} for {}", domain, buf);
                        app.mode = InputMode::Normal;
                        app.refresh();
                    }
                    Err(e) => {
                        app.push_log(format!("[err] temp-block {} {}: {}", domain, buf, e));
                        app.status = format!("temp-block failed: {}", e);
                        app.mode = InputMode::Normal;
                    }
                },
            }
        }
    }
}

fn quick_check_domain(d: &str) -> Result<(), String> {
    let s = d.trim().to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 || !s.contains('.') {
        return Err("must look like a domain (foo.bar)".into());
    }
    Ok(())
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty".into());
    }
    let (num, unit) = match s.chars().last() {
        Some(c) if c.is_ascii_digit() => (s, "s"),
        Some(_) => s.split_at(s.len() - 1),
        None => return Err("empty".into()),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("not a number: {:?}", num))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        _ => return Err(format!("unknown unit {:?}", unit)),
    };
    if secs == 0 {
        return Err("must be > 0".into());
    }
    Ok(Duration::from_secs(secs))
}
