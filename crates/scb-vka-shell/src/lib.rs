//! # scb-vka-shell
//!
//! ## ARCHITECTURE
//!
//! Interactive shell for vault exploration.
//!
//! Commands:
//! - ls: List objects
//! - cat <id>: Show object content
//! - rm <id>: Delete object
//! - add: Add object (inline or from file)
//! - vacuum: Compact vault
//! - help: Show help
//! - exit: Lock and exit

use std::io::Write;

use anyhow::{Context, Result};
use colored::Colorize;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use scb_vka_orchestrator::{VaultManager, VaultSession};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Parse hex string to 16-byte object ID (delegates to shared common utility)
fn parse_object_id(s: &str) -> Result<[u8; 16]> {
    scb_vka_common::util::parse_hex_object_id(s)
        .map_err(|_| anyhow::anyhow!("ID must be 32 hex characters"))
}

// =============================================================================
// SHELL
// =============================================================================

pub struct Shell<M> {
    manager: M,
    session: VaultSession,
    editor: DefaultEditor,
    path: std::path::PathBuf,
}

impl<M> Shell<M>
where
    M: VaultManager,
{
    pub fn new(manager: M, session: VaultSession, path: std::path::PathBuf) -> Result<Self> {
        let editor = DefaultEditor::new().context("Failed to initialize line editor")?;
        Ok(Self {
            manager,
            session,
            editor,
            path,
        })
    }

    pub fn run(mut self) -> Result<()> {
        println!("{}", "BlackBox Secure Shell".green().bold());
        println!("Type {} for available commands.\n", "help".cyan());

        loop {
            let vid_short = hex::encode(&self.session.vid[..4]);
            let prompt = format!("{} > ", vid_short.cyan());

            match self.editor.readline(&prompt) {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let _ = self.editor.add_history_entry(line);

                    let parts: Vec<&str> = line.split_whitespace().collect();
                    let cmd = parts[0].to_lowercase();

                    match cmd.as_str() {
                        "ls" | "list" => self.cmd_ls(),
                        "cat" | "read" => self.cmd_cat(&parts),
                        "rm" | "del" | "delete" => self.cmd_rm(&parts),
                        "add" => self.cmd_add(&parts),
                        "info" | "status" => self.cmd_info(),
                        "help" | "?" => self.cmd_help(),
                        "vacuum" | "compact" => return self.cmd_vacuum(),
                        "clear" | "cls" => self.cmd_clear(),
                        "exit" | "quit" | "q" => break,
                        _ => println!("{}: {}", "Unknown command".red(), parts[0]),
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("Use {} to exit", "exit".cyan());
                }
                Err(ReadlineError::Eof) => {
                    break;
                }
                Err(err) => {
                    println!("{}: {:?}", "Input error".red(), err);
                    break;
                }
            }
        }

        println!("Locking vault...");
        self.manager
            .lock_vault(self.session)
            .context("Failed to lock vault")?;
        println!("{}", "Vault locked.".green());

        Ok(())
    }

    // =========================================================================
    // COMMANDS
    // =========================================================================

    fn cmd_ls(&self) {
        match self.manager.list_objects(&self.session) {
            Ok(objects) => {
                if objects.is_empty() {
                    println!("{}", "Vault is empty.".yellow());
                    return;
                }

                println!(
                    "{:<34} {:<12} {:>8}  {}",
                    "ID".bold(),
                    "TYPE".bold(),
                    "SIZE".bold(),
                    "PURPOSE".bold()
                );
                println!("{}", "-".repeat(70));

                for obj in objects {
                    println!(
                        "{} {:<12} {:>8}  {}",
                        hex::encode(obj.object_id).yellow(),
                        obj.object_type,
                        format_size(obj.size),
                        obj.purpose
                    );
                }
            }
            Err(e) => {
                println!("{}: {:?}", "Failed to list objects".red(), e.kind);
            }
        }
    }

    fn cmd_cat(&mut self, parts: &[&str]) {
        if parts.len() < 2 {
            println!("{}: cat <object_id>", "Usage".yellow());
            return;
        }

        let object_id = match parse_object_id(parts[1]) {
            Ok(id) => id,
            Err(e) => {
                println!("{}: {}", "Invalid ID".red(), e);
                return;
            }
        };

        let mut buf = Vec::new();
        match self
            .manager
            .read_object(&mut self.session, &object_id, &mut buf)
        {
            Ok(bytes_read) => {
                // Try to display as text, fall back to binary info
                match String::from_utf8(buf) {
                    Ok(text) => {
                        println!("{}", text);
                    }
                    Err(_) => {
                        println!(
                            "{}",
                            format!("[Binary data: {} bytes]", bytes_read).yellow()
                        );
                    }
                }
            }
            Err(e) => {
                println!("{}: {:?}", "Failed to read object".red(), e.kind);
            }
        }
    }

    fn cmd_rm(&mut self, parts: &[&str]) {
        if parts.len() < 2 {
            println!("{}: rm <object_id>", "Usage".yellow());
            return;
        }

        let id_str = parts[1];
        let object_id = match parse_object_id(id_str) {
            Ok(id) => id,
            Err(e) => {
                println!("{}: {}", "Invalid ID".red(), e);
                return;
            }
        };

        match self.manager.delete_object(&mut self.session, &object_id) {
            Ok(_) => {
                println!("{}: {}", "Deleted".green(), id_str);
            }
            Err(e) => {
                println!("{}: {:?}", "Failed to delete".red(), e.kind);
            }
        }
    }

    fn cmd_add(&mut self, parts: &[&str]) {
        // Inline add: add <type> <purpose> <data>
        // File add: add -f <path> <type> <purpose>
        if parts.len() < 4 {
            println!("{}: add <type> <purpose> <data>", "Usage".yellow());
            println!("       add -f <file> <type> <purpose>");
            return;
        }

        if parts[1] == "-f" {
            if parts.len() < 5 {
                println!("{}: add -f <file> <type> <purpose>", "Usage".yellow());
                return;
            }
            let file_path = parts[2];
            let type_name = parts[3];
            let purpose = parts[4];

            // S1: Use streaming I/O instead of reading entire file into memory
            let file = match std::fs::File::open(file_path) {
                Ok(f) => f,
                Err(e) => {
                    println!("{}: {}", "Failed to open file".red(), e);
                    return;
                }
            };
            let len = match file.metadata() {
                Ok(m) => m.len(),
                Err(e) => {
                    println!("{}: {}", "Failed to read file metadata".red(), e);
                    return;
                }
            };

            let mut reader: Box<dyn std::io::Read> = Box::new(file);
            match self
                .manager
                .add_object(&mut self.session, type_name, purpose, len, &mut reader)
            {
                Ok(object_id) => {
                    println!("{}: {}", "Added".green(), hex::encode(object_id));
                }
                Err(e) => {
                    println!("{}: {:?}", "Failed to add object".red(), e.kind);
                }
            }
        } else {
            let type_name = parts[1];
            let purpose = parts[2];
            let data = parts[3..].join(" ").into_bytes();
            let len = data.len() as u64;

            let mut reader = std::io::Cursor::new(data);
            match self
                .manager
                .add_object(&mut self.session, type_name, purpose, len, &mut reader)
            {
                Ok(object_id) => {
                    println!("{}: {}", "Added".green(), hex::encode(object_id));
                }
                Err(e) => {
                    println!("{}: {:?}", "Failed to add object".red(), e.kind);
                }
            }
        }
    }

    fn cmd_info(&self) {
        let vid = hex::encode(&self.session.vid);
        let vid_short = hex::encode(&self.session.vid[..8]);

        println!("{}", "Vault Information".bold());
        println!("{}", "-".repeat(40));
        println!("  {:<12} {}", "VID:".cyan(), vid);
        println!("  {:<12} {}", "VID (short):".cyan(), vid_short);
        println!("  {:<12} {}", "Path:".cyan(), self.path.display());

        match self.manager.list_objects(&self.session) {
            Ok(objects) => {
                let total_size: u64 = objects.iter().map(|o| o.size).sum();
                println!("  {:<12} {}", "Objects:".cyan(), objects.len());
                println!("  {:<12} {}", "Total size:".cyan(), format_size(total_size));
            }
            Err(_) => {
                println!("  {:<12} {}", "Objects:".cyan(), "?");
            }
        }
    }

    fn cmd_help(&self) {
        println!("{}", "Available Commands".bold());
        println!("{}", "-".repeat(50));
        println!("  {:<20} {}", "ls, list".cyan(), "List all objects");
        println!("  {:<20} {}", "cat <id>".cyan(), "Display object content");
        println!("  {:<20} {}", "rm <id>".cyan(), "Delete object");
        println!(
            "  {:<20} {}",
            "add <type> <purp> <data>".cyan(),
            "Add inline data"
        );
        println!(
            "  {:<20} {}",
            "add -f <file> <t> <p>".cyan(),
            "Add from file"
        );
        println!("  {:<20} {}", "info".cyan(), "Show vault information");
        println!(
            "  {:<20} {}",
            "vacuum".cyan(),
            "Compact vault (closes session)"
        );
        println!("  {:<20} {}", "clear".cyan(), "Clear screen");
        println!("  {:<20} {}", "exit, quit, q".cyan(), "Lock and exit");
        println!();
        println!(
            "{}",
            "Note: Object IDs are 32-character hex strings.".bright_black()
        );
    }

    fn cmd_vacuum(self) -> Result<()> {
        println!("{}", "Vacuuming vault (this may take a while)...".yellow());

        match self.manager.vacuum_vault(self.session, &self.path) {
            Ok(_) => {
                println!("{}", "Vault compacted successfully.".green());
                println!(
                    "{}",
                    "Session closed - please restart shell to continue.".yellow()
                );
            }
            Err(e) => {
                println!(
                    "{}: {:?}",
                    "Vacuum failed - vault may need recovery".red().bold(),
                    e.kind
                );
            }
        }

        Ok(())
    }

    fn cmd_clear(&self) {
        // ANSI escape: clear screen and move cursor to top-left
        print!("\x1B[2J\x1B[1;1H");
        let _ = std::io::stdout().flush();
    }
}

// =============================================================================
// UTILITIES
// =============================================================================

/// Format byte size in human-readable form
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}
