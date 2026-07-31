use std::process::Command;

fn xsync() -> Command {
    Command::new(env!("CARGO_BIN_EXE_xsync"))
}

#[test]
fn help_and_version_succeed() {
    let help = xsync().arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage:"));

    let version = xsync().arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("xsync "));
}

#[test]
fn usage_errors_exit_two_without_terminal_injection() {
    let output = xsync().arg("host").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("at least one directory"));

    let output = xsync()
        .args(["host", "/tmp/a\n\x1b", "/tmp/a\n\x1b/b"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("\\x0a\\x1b"));
    assert!(!stderr.contains('\n') || stderr.lines().count() <= 2);
}
