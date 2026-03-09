use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;

#[test]
fn test_cli_help() {
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("blackbox").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: blackbox"));
}

#[test]
fn test_cli_init_success() {
    let temp_file = NamedTempFile::new().unwrap();
    let vault_path = temp_file.path();
    let label = format!("com.blackbox.test.init.{}", std::process::id());

    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("blackbox").unwrap();

    cmd.env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("init")
        .arg("--vault")
        .arg(vault_path)
        .write_stdin("StrongPassword123\nStrongPassword123\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("keys successfully initialized"));
}

#[test]
fn test_cli_add_and_cat() {
    let temp_file = NamedTempFile::new().unwrap();
    let vault_path = temp_file.path();
    let label = format!("com.blackbox.test.add.{}", std::process::id());

    // 1. Init
    #[allow(deprecated)]
    let mut init_cmd = Command::cargo_bin("blackbox").unwrap();
    init_cmd
        .env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("init")
        .arg("--vault")
        .arg(vault_path)
        .write_stdin("StrongPassword123\nStrongPassword123\n")
        .assert()
        .success();

    // 2. Create
    #[allow(deprecated)]
    let mut create_cmd = Command::cargo_bin("blackbox").unwrap();
    create_cmd
        .env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("create")
        .arg("--vault")
        .arg(vault_path)
        .write_stdin("StrongPassword123\nStrongPassword123\n")
        .assert()
        .success();

    // 3. Add
    let payload = "Secret Data Content";
    #[allow(deprecated)]
    let mut add_cmd = Command::cargo_bin("blackbox").unwrap();
    let add_result = add_cmd
        .env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("--quiet")
        .arg("add")
        .arg("--vault")
        .arg(vault_path)
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
    #[allow(deprecated)]
    let mut read_cmd = Command::cargo_bin("blackbox").unwrap();
    read_cmd
        .env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("read")
        .arg("--vault")
        .arg(vault_path)
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
    let label = format!("com.blackbox.test.concurrent.{}", std::process::id());

    // 1. Init
    #[allow(deprecated)]
    let mut init_cmd = Command::cargo_bin("blackbox").unwrap();
    init_cmd
        .env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("init")
        .arg("--vault")
        .arg(&vault_path)
        .write_stdin("StrongPassword123\nStrongPassword123\n")
        .assert()
        .success();

    // 2. Create
    #[allow(deprecated)]
    let mut create_cmd = Command::cargo_bin("blackbox").unwrap();
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
            #[allow(deprecated)]
            let mut add_cmd = Command::cargo_bin("blackbox").unwrap();
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
            #[allow(deprecated)]
            let mut read_cmd = Command::cargo_bin("blackbox").unwrap();
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
    let label = format!("com.blackbox.test.chaos.{}", std::process::id());

    // 1. Init Vault
    #[allow(deprecated)]
    let mut init_cmd = Command::cargo_bin("blackbox").unwrap();
    init_cmd
        .env("BLACKBOX_TEST_KEY_LABEL", &label)
        .arg("init")
        .arg("--vault")
        .arg(&vault_path)
        .write_stdin("ChaosPassword123\nChaosPassword123\n")
        .assert()
        .success();

    // 2. Aggressive File Corruption
    // Overwrite the end of the file with 1MB of pure radioactive garbage
    {
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
        #[allow(deprecated)]
        let mut read_cmd = Command::cargo_bin("blackbox").unwrap();
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
    #[allow(deprecated)]
    let mut create_cmd = Command::cargo_bin("blackbox").unwrap();
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
