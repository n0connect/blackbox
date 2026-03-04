//! # scb-vka-cli
//!
//! ## ARCHITECTURE
//!
//! CLI interface. All operations go through VaultManager.
//!
//! Commands:
//! - create: Create new vault
//! - add: Add object
//! - read: Read object
//! - list: List objects
//! - delete: Delete object
//! - shell: Interactive shell
//! - vacuum: Compact vault

use std::io::{Read as IoRead, Write as IoWrite};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use scb_vka_orchestrator::{DefaultVaultManager, VaultManager, VaultSession};

#[cfg(any(test, debug_assertions))]
struct MockEnclave;

#[cfg(any(test, debug_assertions))]
impl scb_vka_hsp::HardwareEnclave for MockEnclave {
    fn sign_with_hardware_key(
        &self,
        ur: &[u8; 64],
    ) -> Result<[u8; 64], scb_vka_common::error::VaultError> {
        // Return a dummy derived key
        let mut out = [0u8; 64];
        out.copy_from_slice(ur);
        Ok(out)
    }

    fn provider_name(&self) -> &'static str {
        "MockEnclave"
    }

    fn init_hardware_keys(&self) -> Result<(), scb_vka_common::error::VaultError> {
        Ok(())
    }

    fn clear_hardware_keys(&self) -> Result<(), scb_vka_common::error::VaultError> {
        Ok(())
    }
}

const DEFAULT_VAULT_PATH: &str = scb_vka_common::config::DEFAULT_VAULT_PATH;

// =============================================================================
// CLI DEFINITION
// =============================================================================

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

    #[arg(long = "CLEANHWKEYS")]
    cleanhwkeys: bool,

    #[cfg(any(test, debug_assertions))]
    #[arg(long = "test-mock-enclave", hide = true)]
    test_mock_enclave: bool,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize hardware security modules
    Init,

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

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Parse hex string to 16-byte object ID (delegates to shared common utility)
pub fn parse_object_id(s: &str) -> Result<[u8; 16]> {
    scb_vka_common::util::parse_hex_object_id(s)
        .map_err(|_| anyhow::anyhow!("ID must be 32 hex characters"))
}

/// Prompt for password with optional confirmation.
/// Returns Zeroizing<String> to ensure password is cleared from memory.
fn prompt_password(confirm: bool) -> Result<Zeroizing<String>> {
    if confirm {
        eprintln!(
            "{}",
            "WARNING: If you lose your password, ALL data is permanently unrecoverable."
                .red()
                .bold()
        );
        eprintln!(
            "{}",
            "WARNING: Password cannot be changed. There are NO backdoors."
                .red()
                .bold()
        );
        eprintln!();
    }

    use std::io::{IsTerminal, Write};
    let read_pwd = |prompt: &str| -> Result<String> {
        if std::io::stdin().is_terminal() {
            eprint!("{prompt} ");
            std::io::stderr().flush().unwrap();
            rpassword::read_password().context("Failed to read password")
        } else {
            let mut buffer = String::new();
            std::io::stdin()
                .read_line(&mut buffer)
                .context("Failed to read piped password")?;
            Ok(buffer.trim_end_matches(['\r', '\n']).to_string())
        }
    };

    let password = Zeroizing::new(read_pwd("Password:")?);

    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    if password.len() < 8 {
        anyhow::bail!("Password must be at least 8 characters");
    }

    if confirm {
        let confirm = Zeroizing::new(read_pwd("Confirm password:")?);
        if *password != *confirm {
            anyhow::bail!("Passwords do not match");
        }
    }

    Ok(password)
}

/// Unlock vault with standardized logging
fn unlock_vault(
    manager: &DefaultVaultManager,
    path: &std::path::Path,
    password: &Zeroizing<String>,
    quiet: bool,
) -> Result<VaultSession> {
    if !quiet {
        info!("Opening vault at {}", path.display());
    }
    info!("Deriving keys (requires ~1GB RAM, please wait)...");

    manager
        .unlock_vault(path, password.as_bytes())
        .context("Failed to unlock vault - check password and file integrity")
}

/// Lock vault with proper error handling
fn lock_vault(manager: &DefaultVaultManager, session: VaultSession) -> Result<()> {
    manager
        .lock_vault(session)
        .context("Failed to securely lock vault - key material may not be fully zeroized")
}

// =============================================================================
// COMMAND HANDLERS
// =============================================================================

fn cmd_create(manager: &DefaultVaultManager, path: &std::path::Path, quiet: bool) -> Result<()> {
    // Force hardware initialization check before prompting password
    manager
        .init_hardware()
        .context("Hardware initialization failed. Vault creation aborted.")?;

    let password = prompt_password(true)?;

    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).context("Failed to create vault directory")?;
    }

    if !quiet {
        info!("Creating vault at {}", path.display());
    }
    info!("Deriving keys (It may take time, requires ~1GB RAM, please wait)...");

    let vault_info = manager
        .create_vault(path, password.as_bytes())
        .context("Failed to create vault")?;

    info!(
        "Vault created successfully: {} (vid: {})",
        path.display(),
        hex::encode(&vault_info.vid[..8])
    );

    Ok(())
}

fn cmd_add(
    manager: &DefaultVaultManager,
    path: &PathBuf,
    type_name: String,
    purpose: String,
    data: Option<String>,
    file: Option<PathBuf>,
    quiet: bool,
) -> Result<()> {
    let password = prompt_password(false)?;

    let (mut reader, len): (Box<dyn IoRead>, u64) = match (file, data) {
        (Some(f), _) => {
            let file = std::fs::File::open(&f).context("Failed to open source file")?;
            let len = file
                .metadata()
                .context("Failed to read file metadata")?
                .len();
            debug!("Reading from file: {} ({} bytes)", f.display(), len);
            (Box::new(file), len)
        }
        (_, Some(d)) => {
            let len = u64::try_from(d.len()).context("Data too large")?;
            debug!("Reading from inline data ({} bytes)", len);
            (Box::new(std::io::Cursor::new(d.into_bytes())), len)
        }
        _ => anyhow::bail!("You must provide either --data or --file"),
    };

    let mut session = unlock_vault(manager, path, &password, quiet)?;

    debug!("Adding object: type={}, purpose={}", type_name, purpose);
    let object_id = manager
        .add_object(&mut session, &type_name, &purpose, len, &mut reader)
        .context("Failed to add object to vault")?;

    lock_vault(manager, session)?;

    let id_hex = hex::encode(object_id);
    info!("Object added: {}", id_hex);

    if quiet {
        println!("{id_hex}");
    }

    Ok(())
}

fn cmd_read(
    manager: &DefaultVaultManager,
    path: &PathBuf,
    id: String,
    output: Option<PathBuf>,
    quiet: bool,
) -> Result<()> {
    let password = prompt_password(false)?;
    let object_id = parse_object_id(&id)?;

    let mut session = unlock_vault(manager, path, &password, quiet)?;

    debug!("Reading object: {}", id);

    let mut writer: Box<dyn IoWrite> = if let Some(ref out) = output {
        Box::new(std::fs::File::create(out).context("Failed to create output file")?)
    } else {
        Box::new(std::io::stdout())
    };

    let bytes_read = manager
        .read_object(&mut session, &object_id, &mut writer)
        .context("Failed to read object from vault")?;

    lock_vault(manager, session)?;

    if let Some(out) = output {
        info!("Read {} bytes to {}", bytes_read, out.display());
    } else {
        debug!("Read {} bytes to stdout", bytes_read);
    }

    Ok(())
}

fn cmd_list(manager: &DefaultVaultManager, path: &PathBuf, quiet: bool) -> Result<()> {
    let password = prompt_password(false)?;

    let session = unlock_vault(manager, path, &password, quiet)?;

    let objects = manager
        .list_objects(&session)
        .context("Failed to list objects")?;

    lock_vault(manager, session)?;

    if objects.is_empty() {
        info!("Vault is empty");
        return Ok(());
    }

    info!("{} object(s) in vault", objects.len());
    println!("{:<34} {:<10} {:<8} PURPOSE", "ID", "TYPE", "SIZE");
    for obj in objects {
        println!(
            "{} {:<10} {:<8} {}",
            hex::encode(obj.object_id),
            obj.object_type,
            obj.size,
            obj.purpose
        );
    }

    Ok(())
}

fn cmd_delete(
    manager: &DefaultVaultManager,
    path: &PathBuf,
    id: String,
    quiet: bool,
) -> Result<()> {
    let password = prompt_password(false)?;
    let object_id = parse_object_id(&id)?;

    let mut session = unlock_vault(manager, path, &password, quiet)?;

    debug!("Deleting object: {}", id);
    manager
        .delete_object(&mut session, &object_id)
        .context("Failed to delete object")?;

    lock_vault(manager, session)?;

    info!("Object deleted: {}", id);

    Ok(())
}

fn cmd_vacuum(manager: &DefaultVaultManager, path: &PathBuf, quiet: bool) -> Result<()> {
    let password = prompt_password(false)?;

    let session = unlock_vault(manager, path, &password, quiet)?;

    warn!("Vacuuming vault - this may take a while for large vaults");
    manager
        .vacuum_vault(session, path)
        .context("Vacuum failed - vault integrity may be compromised, check backup")?;

    info!("Vault compacted successfully");

    Ok(())
}

fn cmd_init(manager: &DefaultVaultManager, quiet: bool) -> Result<()> {
    if !quiet {
        info!("Initializing hardware security keys...");
    }
    manager
        .init_hardware()
        .context("Failed to initialize hardware keys")?;
    if !quiet {
        info!("Hardware security keys successfully initialized.");
    }
    Ok(())
}

fn cmd_shell(manager: DefaultVaultManager, path: &PathBuf, quiet: bool) -> Result<()> {
    let password = prompt_password(false)?;

    let session = unlock_vault(&manager, path, &password, quiet)?;

    debug!("Starting interactive shell");
    let shell = scb_vka_shell::Shell::new(manager, session, path.clone())
        .context("Failed to initialize shell")?;

    shell.run().context("Shell error")?;

    Ok(())
}

// =============================================================================
// MAIN
// =============================================================================

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Configure tracing
    let log_level = match (cli.quiet, cli.verbose) {
        (true, _) => "warn",
        (false, 0) => "info",
        (false, 1) => "debug",
        (false, _) => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(log_level))
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    #[cfg(any(test, debug_assertions))]
    let manager = if cli.test_mock_enclave {
        DefaultVaultManager::new_with(Box::new(MockEnclave))
    } else {
        DefaultVaultManager::new()
    };

    #[cfg(not(any(test, debug_assertions)))]
    let manager = DefaultVaultManager::new();

    if cli.cleanhwkeys {
        if !cli.quiet {
            eprintln!(
                "{}",
                "WARNING: This will permanently delete the hardware keys."
                    .red()
                    .bold()
            );
            eprintln!(
                "{}",
                "All vaults relying on this hardware will become unrecoverable."
                    .red()
                    .bold()
            );
        }
        manager
            .clear_hardware_keys()
            .context("Failed to clear hardware keys")?;
        info!("Hardware keys successfully cleaned.");
        return Ok(());
    }

    let path = cli
        .vault
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VAULT_PATH));

    let quiet = cli.quiet;

    if let Some(cmd) = cli.cmd {
        match cmd {
            Commands::Init => cmd_init(&manager, quiet),
            Commands::Create => cmd_create(&manager, &path, quiet),
            Commands::Add {
                type_name,
                purpose,
                data,
                file,
            } => cmd_add(&manager, &path, type_name, purpose, data, file, quiet),
            Commands::Read { id, output } => cmd_read(&manager, &path, id, output, quiet),
            Commands::List => cmd_list(&manager, &path, quiet),
            Commands::Delete { id } => cmd_delete(&manager, &path, id, quiet),
            Commands::Vacuum => cmd_vacuum(&manager, &path, quiet),
            Commands::Shell => cmd_shell(manager, &path, quiet),
        }
    } else {
        // Fallback if no command provided (useful if only running flags like --CLEANHWKEYS is expected)
        println!("No command specified. Use --help for usage.");
        Ok(())
    }
}

fn main() {
    scb_vka_memory::harden_process();
    println!("{}", "BlackBox CLI".bright_white().bold());

    if let Err(e) = run() {
        // Print user-friendly error message (not full debug chain)
        error!("{:#}", e);
        std::process::exit(1);
    }
}
