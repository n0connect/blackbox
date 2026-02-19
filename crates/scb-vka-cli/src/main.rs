//! # scb-vka-cli
//!
//! ## MİMARİ GEREKSİNİMLERİ
//!
//! CLI arayüzü. Tüm operasyonlar VaultManager üzerinden yapılır.
//!
//! Komutlar:
//! - create: Yeni vault oluştur
//! - add: Object ekle
//! - read: Object oku
//! - list: Object listele
//! - delete: Object sil
//! - shell: Interactive shell
//!

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use colored::Colorize;

use scb_vka_common::log::SimpleLogger;
use scb_vka_orchestrator::{DefaultVaultManager, VaultManager};

const DEFAULT_VAULT_PATH: &str = "sandbox/vault.bbx";

#[derive(Parser)]
#[command(
    name = "blackbox",
    about = "BlackBox Encrypted Vault",
    version = "2.0.0"
)]
struct Cli {
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new vault
    Create,

    /// Add an object to vault
    Add {
        #[arg(long, short = 't', default_value = "text")]
        type_name: String,
        #[arg(long, short = 'p', required = true)]
        purpose: String,
        #[arg(long, short = 'd')]
        data: Option<String>,
        #[arg(long, short = 'f')]
        file: Option<PathBuf>,
    },

    /// Read an object from vault
    Read {
        #[arg(long, short = 'i', required = true)]
        id: String,
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// List all objects
    List,

    /// Delete an object
    Delete {
        #[arg(long, short = 'i', required = true)]
        id: String,
    },

    /// Open interactive shell
    Shell,

    /// Vacuum (compact) the vault, permanently removing space from deleted objects
    Vacuum,
}

fn msg(s: &str, quiet: bool) {
    if !quiet {
        println!("{}", s.cyan());
    }
}

fn ok(s: &str, quiet: bool) {
    if !quiet {
        println!("{}", s.green());
    }
}

fn err(s: &str) {
    eprintln!("{}", s.red().bold());
}

fn parse_id(s: &str) -> Result<[u8; 16], String> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 32 {
        return Err("ID must be 32 hex chars".to_string());
    }
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    // Validate decoded length to prevent panic
    if bytes.len() != 16 {
        return Err("Decoded ID must be exactly 16 bytes".to_string());
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes);
    Ok(buf)
}

fn prompt_password(confirm: bool) -> Result<String, String> {
    if confirm {
        println!(
            "{}",
            "WARNING: Password cannot be changed after vault creation."
                .yellow()
                .bold()
        );
        println!(
            "{}",
            "WARNING: If you forget this password, your data is permanently lost."
                .yellow()
                .bold()
        );
        println!("{}", "There is no recovery mechanism by design.".yellow());
        println!();
    }

    let password = rpassword::prompt_password("Password: ")
        .map_err(|e| format!("Failed to read password: {e}"))?;

    if password.is_empty() {
        return Err("Password cannot be empty".to_string());
    }

    if confirm {
        let confirm = rpassword::prompt_password("Confirm password: ")
            .map_err(|e| format!("Failed to read password: {e}"))?;
        if password != confirm {
            return Err("Passwords do not match".to_string());
        }
    }

    Ok(password)
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let quiet = cli.quiet;
    let logger = SimpleLogger::new();
    let manager = DefaultVaultManager::new(logger);

    // Resolve path once, before consuming `cli.cmd`.
    let path = cli
        .vault
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VAULT_PATH));

    match cli.cmd {
        Commands::Create => {
            let password = prompt_password(true)?;
            if let Some(p) = path.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            msg("Creating vault...", quiet);
            let info = manager
                .create_vault(&path, password.as_bytes())
                .map_err(|e| format!("Create failed: {e:?}"))?;
            ok(
                &format!(
                    "Vault created: {} (vid: {})",
                    path.display(),
                    hex::encode(&info.vid[..8])
                ),
                quiet,
            );
        }

        Commands::Add {
            type_name,
            purpose,
            data,
            file,
        } => {
            let password = prompt_password(false)?;

            use std::io::{Cursor, Read};
            let (mut reader, len): (Box<dyn Read>, u64) = match (file, data) {
                (Some(f), _) => {
                    let file = std::fs::File::open(&f).map_err(|e| format!("Open file: {e}"))?;
                    let len = file.metadata().map_err(|e| format!("Metadata: {e}"))?.len();
                    (Box::new(file), len)
                }
                (_, Some(d)) => {
                    let len = d.len() as u64;
                    (Box::new(Cursor::new(d.into_bytes())), len)
                }
                _ => return Err("Need --data or --file".to_string()),
            };

            msg("Opening vault...", quiet);
            let mut session = manager
                .unlock_vault(&path, password.as_bytes())
                .map_err(|e| format!("Unlock: {e:?}"))?;
            msg("Adding object...", quiet);
            let id = manager
                .add_object(&mut session, &type_name, &purpose, len, &mut reader)
                .map_err(|e| format!("Add: {e:?}"))?;
            manager.lock_vault(session).ok();
            ok(&format!("Added: {}", hex::encode(id)), quiet);
            if quiet {
                println!("{}", hex::encode(id));
            }
        }

        Commands::Read { id, output } => {
            let password = prompt_password(false)?;
            let oid = parse_id(&id)?;
            msg("Opening vault...", quiet);
            let mut session = manager
                .unlock_vault(&path, password.as_bytes())
                .map_err(|e| format!("Unlock: {e:?}"))?;
            msg("Reading object...", quiet);

            use std::io::Write;
            let mut writer: Box<dyn Write> = if let Some(out) = output {
                Box::new(std::fs::File::create(&out).map_err(|e| format!("Create file: {e}"))?)
            } else {
                Box::new(std::io::stdout())
            };

            let bytes_read = manager
                .read_object(&mut session, &oid, &mut writer)
                .map_err(|e| format!("Read: {e:?}"))?;

            manager.lock_vault(session).ok();
            ok(&format!("Read {bytes_read} bytes"), quiet);
        }

        Commands::List => {
            let password = prompt_password(false)?;
            msg("Opening vault...", quiet);
            let session = manager
                .unlock_vault(&path, password.as_bytes())
                .map_err(|e| format!("Unlock: {e:?}"))?;
            let list = manager
                .list_objects(&session)
                .map_err(|e| format!("List: {e:?}"))?;
            manager.lock_vault(session).ok();
            ok(&format!("{} objects", list.len()), quiet);
            println!("{:<34} {:<10} {:<8} PURPOSE", "ID", "TYPE", "SIZE");
            for m in list {
                println!(
                    "{} {:<10} {:<8} {}",
                    hex::encode(m.object_id),
                    m.object_type,
                    m.size,
                    m.purpose
                );
            }
        }

        Commands::Delete { id } => {
            let password = prompt_password(false)?;
            let oid = parse_id(&id)?;
            msg("Opening vault...", quiet);
            let mut session = manager
                .unlock_vault(&path, password.as_bytes())
                .map_err(|e| format!("Unlock: {e:?}"))?;
            msg("Deleting object...", quiet);
            manager
                .delete_object(&mut session, &oid)
                .map_err(|e| format!("Delete: {e:?}"))?;
            manager.lock_vault(session).ok();
            ok("Deleted", quiet);
        }

        Commands::Vacuum => {
            let password = prompt_password(false)?;
            msg("Opening vault...", quiet);
            let session = manager
                .unlock_vault(&path, password.as_bytes())
                .map_err(|e| format!("Unlock: {e:?}"))?;
            msg(
                "Vacuuming vault (this may take a while depending on size)...",
                quiet,
            );
            manager
                .vacuum_vault(session, &path)
                .map_err(|e| format!("Vacuum: {e:?}"))?;
            ok("Vault successfully compacted.", quiet);
        }

        Commands::Shell => {
            let password = prompt_password(false)?;
            msg("Starting shell...", quiet);
            let session = manager
                .unlock_vault(&path, password.as_bytes())
                .map_err(|e| format!("Unlock: {e:?}"))?;
            let shell = scb_vka_shell::Shell::new(manager, session, path.clone())
                .map_err(|e| format!("Shell: {e}"))?;
            shell.run().map_err(|e| format!("Shell: {e}"))?;
        }
    }

    Ok(())
}

fn main() {
    println!("{}", "BlackBox CLI v2.0".bright_white().bold());
    if let Err(e) = run() {
        err(&e);
        std::process::exit(1);
    }
}
