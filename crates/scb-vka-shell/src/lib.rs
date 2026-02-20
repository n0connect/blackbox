//! # scb-vka-shell
//!
//! ## MİMARİ GEREKSİNİMLERİ
//!
//! Interactive shell for vault exploration.
//!
//! Komutlar:
//! - ls: List objects
//! - cat <id>: Show object content
//! - rm <id>: Delete object
//! - help: Show help
//! - exit: Lock and exit

use std::io::Write;

use anyhow::{Context, Result};
use colored::Colorize;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use tracing::{error, info, instrument};

use scb_vka_orchestrator::{VaultManager, VaultSession};

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
        let editor = DefaultEditor::new().context("Failed to initialize rustyline editor")?;
        Ok(Self {
            manager,
            session,
            editor,
            path,
        })
    }

    #[instrument(skip(self))]
    pub fn run(mut self) -> Result<()> {
        println!("{}", "BlackBox Secure Shell".green().bold());
        println!("Type 'help' for commands.");

        loop {
            let prompt = format!("{} > ", hex::encode(&self.session.vid[..4]).cyan());
            let readline = self.editor.readline(&prompt);

            match readline {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let _ = self.editor.add_history_entry(line);

                    let parts: Vec<&str> = line.split_whitespace().collect();
                    match parts[0] {
                        "ls" | "list" => self.do_ls()?,
                        "cat" => {
                            if parts.len() < 2 {
                                println!("Usage: cat <object_id_hex>");
                            } else {
                                self.do_cat(parts[1])?;
                            }
                        }
                        "rm" | "del" => {
                            if parts.len() < 2 {
                                println!("Usage: rm <object_id_hex>");
                            } else {
                                self.do_rm(parts[1])?;
                            }
                        }
                        "help" | "?" => self.print_help(),
                        "vacuum" => return self.do_vacuum(),
                        "clear" => {
                            print!("\x1B[2J\x1B[1;1H");
                            let _ = std::io::stdout().flush();
                        }
                        "exit" | "quit" => {
                            println!("Exiting shell...");
                            break;
                        }
                        _ => println!("Unknown command: {}", parts[0]),
                    }
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                    break;
                }
                Err(err) => {
                    println!("Error: {err:?}");
                    break;
                }
            }
        }

        println!("Locking vault...");
        self.manager
            .lock_vault(self.session)
            .context("Failed to securely lock vault during exit")?;
        Ok(())
    }

    fn do_ls(&self) -> Result<()> {
        let objects = self
            .manager
            .list_objects(&self.session)
            .context("Failed to read virtual file table")?;
        if objects.is_empty() {
            println!("Vault is empty.");
            return Ok(());
        }

        println!("{:<34} {:<10} {:<8} PURPOSE", "ID", "TYPE", "SIZE");
        for obj in objects {
            println!(
                "{} {:<10} {:<8} {}",
                hex::encode(obj.object_id).yellow(),
                obj.object_type,
                obj.size,
                obj.purpose
            );
        }
        Ok(())
    }

    fn do_cat(&mut self, id_hex: &str) -> Result<()> {
        let object_id = self.parse_id(id_hex)?;
        let mut buf = Vec::new();
        match self
            .manager
            .read_object(&mut self.session, &object_id, &mut buf)
        {
            Ok(bytes_read) => match String::from_utf8(buf) {
                Ok(s) => println!("{s}"),
                Err(_) => println!("(Binary Data: {bytes_read} bytes)"),
            },
            Err(e) => error!(error = ?e, "Failed to read vault object"),
        }
        Ok(())
    }

    fn do_rm(&mut self, id_hex: &str) -> Result<()> {
        let object_id = self.parse_id(id_hex)?;
        match self.manager.delete_object(&mut self.session, &object_id) {
            Ok(_) => info!(object_id = %id_hex, "Object securely deleted"),
            Err(e) => error!(error = ?e, "Failed to delete vault object"),
        }
        Ok(())
    }

    fn do_vacuum(self) -> Result<()> {
        println!("Vacuuming vault out-of-place (this may take a while)...");
        match self.manager.vacuum_vault(self.session, &self.path) {
            Ok(_) => {
                println!("{}", "Vault successfully compacted.".green());
                println!("{}", "VaultSession is now closed. Exiting shell.".yellow());
            }
            Err(e) => {
                error!(error = ?e, "Critical vacuum error");
                println!(
                    "{}",
                    "Vault lock dropped due to error. Exiting shell.".yellow()
                );
            }
        }
        Ok(())
    }

    fn parse_id(&self, s: &str) -> Result<[u8; 16]> {
        let s = s.trim().trim_start_matches("0x");
        if s.len() != 32 {
            anyhow::bail!("ID must be 32 hex characters");
        }
        let bytes = hex::decode(s).context("Invalid hex characters in ID string")?;
        if bytes.len() != 16 {
            anyhow::bail!("Decoded ID must be exactly 16 bytes");
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&bytes);
        Ok(buf)
    }

    fn print_help(&self) {
        println!("{}", "Commands:".bold());
        println!("  {}     - List objects", "ls".cyan());
        println!("  {} - Show object", "cat <id>".cyan());
        println!("  {}  - Delete object", "rm <id>".cyan());
        println!("  {}   - Compact vault out-of-place", "vacuum".cyan());
        println!("  {}   - This help", "help".cyan());
        println!("  {}  - Clear screen", "clear".cyan());
        println!("  {}   - Lock and exit", "exit".cyan());
    }
}
