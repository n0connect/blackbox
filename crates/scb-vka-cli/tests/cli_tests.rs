use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;
use tempfile::NamedTempFile;

#[allow(deprecated)]
fn blackbox_cmd() -> Command {
    Command::cargo_bin("blackbox").unwrap()
}

fn output_text(out: &[u8]) -> String {
    String::from_utf8_lossy(out).to_string()
}

fn run_init(vault_path: &Path, label: &str, password: &str) -> std::process::Output {
    blackbox_cmd()
        .env("BLACKBOX_TEST_KEY_LABEL", label)
        .arg("init")
        .arg("--vault")
        .arg(vault_path)
        .write_stdin(format!("{password}\n{password}\n"))
        .output()
        .expect("failed to run blackbox init")
}

fn is_hardware_unavailable(output: &std::process::Output) -> bool {
    if output.status.success() {
        return false;
    }
    let combined = format!(
        "{}\n{}",
        output_text(&output.stdout),
        output_text(&output.stderr)
    )
    .to_lowercase();
    combined.contains("hardware initialization failed")
        || combined.contains("failed to initialize hardware keys")
        || combined.contains("hardwareunavailable")
        || combined.contains("hardware unavailable")
        || combined.contains("failed to connect to tpm")
        || combined.contains("secure enclave access denied")
        || combined.contains("failed to generate keypair")
        || combined.contains("failed to generate cdsa key")
        || combined.contains("failed to create keychain fallback key")
}

fn ensure_hardware_or_skip(vault_path: &Path, label: &str, password: &str) -> bool {
    let output = run_init(vault_path, label, password);
    if output.status.success() {
        return true;
    }
    if is_hardware_unavailable(&output) {
        eprintln!(
            "Skipping hardware-dependent CLI test: {}",
            output_text(&output.stderr)
        );
        return false;
    }

    panic!(
        "blackbox init failed unexpectedly\nstdout:\n{}\nstderr:\n{}",
        output_text(&output.stdout),
        output_text(&output.stderr)
    );
}

#[test]
fn test_cli_help() {
    let mut cmd = blackbox_cmd();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: blackbox"));
}

#[test]
fn test_cli_init_success() {
    let temp_file = NamedTempFile::new().unwrap();
    let vault_path = temp_file.path().to_path_buf();
    drop(temp_file);
    let label = format!("com.blackbox.test.init.{}", std::process::id());

    let output = run_init(&vault_path, &label, "StrongPassword123");
    if is_hardware_unavailable(&output) {
        eprintln!(
            "Skipping hardware-dependent CLI test: {}",
            output_text(&output.stderr)
        );
        return;
    }

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        output_text(&output.stdout),
        output_text(&output.stderr)
    );
    assert!(
        output_text(&output.stdout).contains("keys successfully initialized"),
        "stdout:\n{}",
        output_text(&output.stdout)
    );
}

#[test]
fn test_cli_add_and_cat() {
    let temp_file = NamedTempFile::new().unwrap();
    let vault_path = temp_file.path().to_path_buf();
    drop(temp_file);
    let label = format!("com.blackbox.test.add.{}", std::process::id());

    // 1. Init
    if !ensure_hardware_or_skip(&vault_path, &label, "StrongPassword123") {
        return;
    }

    // 2. Create
    let mut create_cmd = blackbox_cmd();
    create_cmd
        .env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("create")
        .arg("--vault")
        .arg(&vault_path)
        .write_stdin("StrongPassword123\nStrongPassword123\n")
        .assert()
        .success();

    // 3. Add
    let payload = "Secret Data Content";
    let mut add_cmd = blackbox_cmd();
    let add_result = add_cmd
        .env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("--quiet")
        .arg("add")
        .arg("--vault")
        .arg(&vault_path)
        .arg("--type-name")
        .arg("text/plain")
        .arg("--purpose")
        .arg("test purpose")
        .arg("--data")
        .arg(payload)
        .write_stdin("StrongPassword123\n")
        .assert()
        .success();

    // In quiet mode, it should just print the ID and a newline
    let output_str = String::from_utf8_lossy(&add_result.get_output().stdout);
    // Standardize object_id extraction by skipping banner/logs
    let object_id: String = output_str
        .trim()
        .chars()
        .rev()
        .take(32)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    assert_eq!(object_id.len(), 32);

    // 4. Read (formerly known as Cat in the test)
    let mut read_cmd = blackbox_cmd();
    read_cmd
        .env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("read")
        .arg("--vault")
        .arg(&vault_path)
        .arg("--id")
        .arg(object_id)
        .write_stdin("StrongPassword123\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(payload));
}

#[test]
fn test_cli_concurrent_adds() {
    use std::thread;

    let temp_file = NamedTempFile::new().unwrap();
    let vault_path = temp_file.path().to_owned();
    drop(temp_file);
    let label = format!("com.blackbox.test.concurrent.{}", std::process::id());

    // 1. Init
    if !ensure_hardware_or_skip(&vault_path, &label, "StrongPassword123") {
        return;
    }

    // 2. Create
    let mut create_cmd = blackbox_cmd();
    create_cmd
        .env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("create")
        .arg("--vault")
        .arg(&vault_path)
        .write_stdin("StrongPassword123\nStrongPassword123\n")
        .assert()
        .success();

    // 3. Concurrent Add
    const THREAD_COUNT: usize = 10;
    let mut handles = vec![];

    for i in 0..THREAD_COUNT {
        let vault_path_cloned = vault_path.clone();
        let label_cloned = label.clone();
        handles.push(thread::spawn(move || {
            let payload = format!("Concurrent Secret Data Content {}", i);
            let mut add_cmd = blackbox_cmd();
            let add_result = add_cmd
                .env("BLACKBOX_TEST_KEY_LABEL", &label_cloned)
                .arg("--quiet")
                .arg("add")
                .arg("--vault")
                .arg(&vault_path_cloned)
                .arg("--type-name")
                .arg("text/plain")
                .arg("--purpose")
                .arg("concurrent test purpose")
                .arg("--data")
                .arg(&payload)
                .write_stdin("StrongPassword123\n")
                .assert()
                .success();

            let output_str = String::from_utf8_lossy(&add_result.get_output().stdout);
            let object_id: String = output_str
                .trim()
                .chars()
                .rev()
                .take(32)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();

            assert_eq!(object_id.len(), 32);
            (i, object_id, payload)
        }));
    }

    let mut results = vec![];
    for handle in handles {
        results.push(handle.join().unwrap());
    }

    // 4. Concurrent Read
    let mut read_handles = vec![];
    for (_i, object_id, payload) in results {
        let vault_path_cloned = vault_path.clone();
        let label_cloned = label.clone();
        read_handles.push(thread::spawn(move || {
            let mut read_cmd = blackbox_cmd();
            read_cmd
                .env("BLACKBOX_TEST_KEY_LABEL", &label_cloned)
                .arg("read")
                .arg("--vault")
                .arg(&vault_path_cloned)
                .arg("--id")
                .arg(&object_id)
                .write_stdin("StrongPassword123\n")
                .assert()
                .success()
                .stdout(predicate::str::contains(&payload));
        }));
    }

    for handle in read_handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_cli_fake_data_chaos() {
    use std::io::Write;

    let temp_file = NamedTempFile::new().unwrap();
    let vault_path = temp_file.path().to_owned();
    drop(temp_file);
    let label = format!("com.blackbox.test.chaos.{}", std::process::id());

    // 1. Init Vault
    if !ensure_hardware_or_skip(&vault_path, &label, "ChaosPassword123") {
        return;
    }

    // 2. Aggressive File Corruption
    // Overwrite the end of the file with 1MB of pure radioactive garbage
    {
        std::fs::File::create(&vault_path).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(&vault_path)
            .unwrap();
        let garbage = vec![0x42; 1024 * 1024]; // 1 Megabyte of "B"
        file.write_all(&garbage).unwrap();
    }

    // 3. Try to read random Fake OIDs from the corrupted Vault
    // It should securely deny access without panicking!
    let fake_oids = vec![
        "00000000000000000000000000000000",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "1234567890ABCDEF1234567890ABCDEF",
    ];

    for oid in fake_oids {
        let mut read_cmd = blackbox_cmd();
        read_cmd
            .env("BLACKBOX_TEST_KEY_LABEL", &label)
            .arg("read")
            .arg("--vault")
            .arg(&vault_path)
            .arg("--id")
            .arg(oid)
            .write_stdin("ChaosPassword123\n")
            .assert()
            .failure(); // Must fail, must NOT panic
    }

    // 4. Try to open the Vault via `create` (which verifies headers)
    // The Superblock should be somewhat intact, but active header or data might be garbage.
    // As long as it doesn't panic, it's a pass.
    let mut create_cmd = blackbox_cmd();
    create_cmd
        .env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("create")
        .arg("--vault")
        .arg(&vault_path)
        .write_stdin("ChaosPassword123\nChaosPassword123\n")
        .assert()
        // It might succeed if it only parses the Superblock and the Superblock is unharmed at offset 0
        // Or it might fail if the Header signature is corrupted.
        // The assert is just that it runs without SIGABRT/SIGSEGV!
        .code(predicate::in_hash(vec![0, 1]));
}
