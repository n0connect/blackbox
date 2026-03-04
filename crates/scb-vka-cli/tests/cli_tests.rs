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

    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("blackbox").unwrap();

    cmd.arg("--test-mock-enclave")
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

    // 1. Init
    #[allow(deprecated)]
    let mut init_cmd = Command::cargo_bin("blackbox").unwrap();
    init_cmd
        .arg("--test-mock-enclave")
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
        .arg("--test-mock-enclave")
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
        .arg("--test-mock-enclave")
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
        .arg("--test-mock-enclave")
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
