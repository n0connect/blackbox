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

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing_subscriber::EnvFilter;

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

    #[arg(long, short = 'q', global = true, conflicts_with = "verbose")]
    quiet: bool,

    #[arg(long, short = 'v', global = true, action = clap::ArgAction::Count)]
    verbose: u8,

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

fn parse_id(s: &str) -> Result<[u8; 16]> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 32 {
        anyhow::bail!("ID must be 32 hex chars");
    }
    let bytes = hex::decode(s).context("Invalid hex characters in ID")?;
    if bytes.len() != 16 {
        anyhow::bail!("Decoded ID must be exactly 16 bytes");
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes);
    Ok(buf)
}

fn prompt_password(confirm: bool) -> Result<String> {
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

    let password = rpassword::prompt_password("Password: ").context("Failed to read password")?;

    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    if confirm {
        let confirm = rpassword::prompt_password("Confirm password: ")
            .context("Failed to read password confirmation")?;
        if password != confirm {
            anyhow::bail!("Passwords do not match");
        }
    }

    Ok(password)
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Configure Tracing Context
    let log_level = match (cli.quiet, cli.verbose) {
        (true, _) => "warn",
        (false, 0) => "info",
        (false, 1) => "debug",
        (false, _) => "trace",
    };

    let filter = EnvFilter::new(log_level);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    let quiet = cli.quiet;
    let manager = DefaultVaultManager::new();

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
                .context("Failed to create vault geometry and headers")?;
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
                    let file = std::fs::File::open(&f).context("Failed to open source file")?;
                    let len = file
                        .metadata()
                        .context("Failed to read file metadata")?
                        .len();
                    (Box::new(file), len)
                }
                (_, Some(d)) => {
                    let len = d.len() as u64;
                    (Box::new(Cursor::new(d.into_bytes())), len)
                }
                _ => anyhow::bail!("You must provide either --data or --file"),
            };

            msg("Opening vault...", quiet);
            let mut session = manager
                .unlock_vault(&path, password.as_bytes())
                .context("Failed to unlock and verify vault header")?;
            msg("Adding object...", quiet);
            let id = manager
                .add_object(&mut session, &type_name, &purpose, len, &mut reader)
                .context("Failed to encrypt and add object to vault space")?;
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
                .context("Failed to unlock and verify vault header")?;
            msg("Reading object...", quiet);

            use std::io::Write;
            let mut writer: Box<dyn Write> = if let Some(out) = output {
                Box::new(std::fs::File::create(&out).context("Failed to create destination file")?)
            } else {
                Box::new(std::io::stdout())
            };

            let bytes_read = manager
                .read_object(&mut session, &oid, &mut writer)
                .context("Failed to decrypt and read object from vault")?;

            manager.lock_vault(session).ok();
            ok(&format!("Read {bytes_read} bytes"), quiet);
        }

        Commands::List => {
            let password = prompt_password(false)?;
            msg("Opening vault...", quiet);
            let session = manager
                .unlock_vault(&path, password.as_bytes())
                .context("Failed to unlock and verify vault header")?;
            let list = manager
                .list_objects(&session)
                .context("Failed to read virtual file table")?;
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
                .context("Failed to unlock and verify vault header")?;
            msg("Deleting object...", quiet);
            manager
                .delete_object(&mut session, &oid)
                .context("Failed to shred and remove object from vault")?;
            manager.lock_vault(session).ok();
            ok("Deleted", quiet);
        }

        Commands::Vacuum => {
            let password = prompt_password(false)?;
            msg("Opening vault...", quiet);
            let session = manager
                .unlock_vault(&path, password.as_bytes())
                .context("Failed to unlock and verify vault header")?;
            msg(
                "Vacuuming vault (this may take a while depending on size)...",
                quiet,
            );
            manager.vacuum_vault(session, &path).context(
                "Vacuum operation failed critically. File integrity may be compromised.",
            )?;
            ok("Vault successfully compacted.", quiet);
        }

        Commands::Shell => {
            let password = prompt_password(false)?;
            msg("Starting shell...", quiet);
            let session = manager
                .unlock_vault(&path, password.as_bytes())
                .context("Failed to unlock vault for shell session")?;
            let shell = scb_vka_shell::Shell::new(manager, session, path.clone())
                .context("Failed to initialize shell")?;
            shell.run().context("Shell encountered a fatal exception")?;
        }
    }

    Ok(())
}

fn main() {
    println!("{}", "BlackBox CLI v2.0".bright_white().bold());
    if let Err(e) = run() {
        // Anyhow provides an ergonomic way to print the full error chain context.
        err(&format!("{e:?}"));
        std::process::exit(1);
    }
}
