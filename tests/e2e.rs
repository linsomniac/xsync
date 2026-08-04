use std::{
    ffi::OsString,
    fs,
    os::unix::ffi::OsStringExt,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::Path,
    process::{Command, Output},
};

use filetime::{FileTime, set_file_mtime};
use tempfile::tempdir;

fn run_xsync(arguments: &[&std::ffi::OsStr]) -> Output {
    let binary = env!("CARGO_BIN_EXE_xsync");
    let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_ssh.sh");
    let ssh = format!("sh {}", shlex::try_quote(fake.to_str().unwrap()).unwrap());
    let mut command = Command::new(binary);
    command
        .arg("fake")
        .arg("--ssh")
        .arg(ssh)
        .arg("--remote-program")
        .arg(binary);
    command.args(arguments);
    command.output().unwrap()
}

fn xsync_command(remote_program: &Path, ssh: &str) -> Command {
    let binary = env!("CARGO_BIN_EXE_xsync");
    let mut command = Command::new(binary);
    command
        .arg("fake")
        .arg("--ssh")
        .arg(ssh)
        .arg("--remote-program")
        .arg(remote_program);
    command
}

fn os(value: &Path) -> &std::ffi::OsStr {
    value.as_os_str()
}

fn json_stderr(output: &Output) -> Vec<serde_json::Value> {
    String::from_utf8(output.stderr.clone())
        .unwrap()
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("stderr line is not JSON ({error}): {line:?}"))
        })
        .collect()
}

fn contains_xsync_temp(root: &Path) -> bool {
    fs::read_dir(root).is_ok_and(|entries| {
        entries.filter_map(std::result::Result::ok).any(|entry| {
            entry
                .file_name()
                .as_encoded_bytes()
                .starts_with(b".xsync.tmp.")
        })
    })
}

fn wait_for_temp(root: &Path) {
    for _ in 0..200 {
        if contains_xsync_temp(root) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!(
        "timed out waiting for xsync temporary in {}",
        root.display()
    );
}

fn wait_for_nonempty_temp(root: &Path) {
    for _ in 0..400 {
        let has_data = fs::read_dir(root).is_ok_and(|entries| {
            entries.filter_map(std::result::Result::ok).any(|entry| {
                entry
                    .file_name()
                    .as_encoded_bytes()
                    .starts_with(b".xsync.tmp.")
                    && entry.metadata().is_ok_and(|metadata| metadata.len() != 0)
            })
        });
        if has_data {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!(
        "timed out waiting for nonempty xsync temporary in {}",
        root.display()
    );
}

#[test]
fn single_file_root_copies_to_the_exact_destination_path() {
    let local_parent = tempdir().unwrap();
    let remote_parent = tempdir().unwrap();
    let local = local_parent.path().join("xsync_0.1.1_amd64.deb");
    let remote = remote_parent.path().join("renamed.deb");
    fs::write(&local, b"package bytes").unwrap();
    fs::set_permissions(&local, fs::Permissions::from_mode(0o640)).unwrap();
    set_file_mtime(&local, FileTime::from_unix_time(1_700_000_000, 123)).unwrap();

    let output = run_xsync(&["--out".as_ref(), os(&local), "--dest".as_ref(), os(&remote)]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(remote.is_file());
    assert_eq!(fs::read(&remote).unwrap(), b"package bytes");
    let local_metadata = fs::metadata(&local).unwrap();
    let remote_metadata = fs::metadata(&remote).unwrap();
    assert_eq!(
        local_metadata.permissions().mode() & 0o777,
        remote_metadata.permissions().mode() & 0o777
    );
    assert_eq!(
        (local_metadata.mtime(), local_metadata.mtime_nsec()),
        (remote_metadata.mtime(), remote_metadata.mtime_nsec())
    );
}

#[test]
fn single_file_root_supports_inbound_missing_and_bidirectional_updates() {
    let local_parent = tempdir().unwrap();
    let remote_parent = tempdir().unwrap();
    let local = local_parent.path().join("local-name");
    let remote = remote_parent.path().join("remote-name");
    fs::write(&remote, b"remote source").unwrap();
    set_file_mtime(&remote, FileTime::from_unix_time(100, 0)).unwrap();

    let inbound = run_xsync(&["--in".as_ref(), os(&local), "--dest".as_ref(), os(&remote)]);
    assert!(
        inbound.status.success(),
        "{}",
        String::from_utf8_lossy(&inbound.stderr)
    );
    assert_eq!(fs::read(&local).unwrap(), b"remote source");

    fs::write(&local, b"newer local source").unwrap();
    set_file_mtime(&local, FileTime::from_unix_time(200, 0)).unwrap();
    let bidirectional = run_xsync(&[os(&local), "--dest".as_ref(), os(&remote)]);
    assert!(
        bidirectional.status.success(),
        "{}",
        String::from_utf8_lossy(&bidirectional.stderr)
    );
    assert_eq!(fs::read(&remote).unwrap(), b"newer local source");
}

#[test]
fn selected_symlink_root_is_copied_without_following_or_scanning_siblings() {
    let local_parent = tempdir().unwrap();
    let remote_parent = tempdir().unwrap();
    let local = local_parent.path().join("selected-link");
    let remote = remote_parent.path().join("renamed-link");
    fs::write(local_parent.path().join("target"), b"target contents").unwrap();
    fs::write(local_parent.path().join("sibling"), b"do not copy").unwrap();
    symlink("target", &local).unwrap();

    let output = run_xsync(&[
        "--out".as_ref(),
        os(&local),
        "--dest".as_ref(),
        os(&remote),
        "--exclude".as_ref(),
        "selected-link".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_link(&remote).unwrap(), Path::new("target"));
    assert!(!remote_parent.path().join("target").exists());
    assert!(!remote_parent.path().join("sibling").exists());
}

#[test]
fn legacy_feature_set_keeps_directory_jobs_and_rejects_file_jobs_before_mutation() {
    let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_ssh.sh");
    let ssh = format!("sh {}", shlex::try_quote(fake.to_str().unwrap()).unwrap());
    let binary = Path::new(env!("CARGO_BIN_EXE_xsync"));

    let local_directory = tempdir().unwrap();
    let remote_directory = tempdir().unwrap();
    fs::write(local_directory.path().join("file"), b"directory job").unwrap();
    let directory = xsync_command(binary, &ssh)
        .env("XSYNC_TEST_AGENT_DISABLE_FILE_ROOT", "1")
        .args([
            "--out".as_ref(),
            os(local_directory.path()),
            "--dest".as_ref(),
            os(remote_directory.path()),
        ])
        .output()
        .unwrap();
    assert!(
        directory.status.success(),
        "{}",
        String::from_utf8_lossy(&directory.stderr)
    );
    assert_eq!(
        fs::read(remote_directory.path().join("file")).unwrap(),
        b"directory job"
    );

    let local_parent = tempdir().unwrap();
    let remote_parent = tempdir().unwrap();
    let local_file = local_parent.path().join("file");
    let remote_file = remote_parent.path().join("file");
    fs::write(&local_file, b"must not transfer").unwrap();
    let file = xsync_command(binary, &ssh)
        .env("XSYNC_TEST_AGENT_DISABLE_FILE_ROOT", "1")
        .args([
            "--out".as_ref(),
            os(&local_file),
            "--dest".as_ref(),
            os(&remote_file),
        ])
        .output()
        .unwrap();
    assert_eq!(file.status.code(), Some(3));
    assert!(!remote_file.exists());
    assert!(String::from_utf8_lossy(&file.stderr).contains("lacks single-file root support"));
}

#[test]
fn single_file_dry_run_and_root_type_conflicts_do_not_mutate() {
    let local_parent = tempdir().unwrap();
    let remote_parent = tempdir().unwrap();
    let local = local_parent.path().join("source");
    let remote = remote_parent.path().join("missing");
    fs::write(&local, b"source").unwrap();

    let dry_run = run_xsync(&[
        "--dry-run".as_ref(),
        "--progress=always".as_ref(),
        "--out".as_ref(),
        os(&local),
        "--dest".as_ref(),
        os(&remote),
    ]);
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    assert!(!remote.exists());
    assert!(String::from_utf8_lossy(&dry_run.stderr).contains("xsync: would "));

    fs::create_dir(&remote).unwrap();
    fs::write(remote.join("preserved"), b"keep").unwrap();
    let conflict = run_xsync(&[os(&local), "--dest".as_ref(), os(&remote)]);
    assert_eq!(conflict.status.code(), Some(1));
    assert!(local.is_file());
    assert!(remote.is_dir());
    assert_eq!(fs::read(remote.join("preserved")).unwrap(), b"keep");
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("conflict"));
}

#[test]
fn copies_out_with_metadata_symlinks_excludes_and_no_delete() {
    let local = tempdir().unwrap();
    let parent = tempdir().unwrap();
    let remote = parent.path().join("new-remote");
    fs::create_dir(local.path().join("nested")).unwrap();
    fs::write(local.path().join("nested/file"), b"hello").unwrap();
    fs::set_permissions(
        local.path().join("nested/file"),
        fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    symlink("nested/file", local.path().join("link")).unwrap();
    fs::create_dir(local.path().join("target")).unwrap();
    fs::write(local.path().join("target/ignored"), b"ignored").unwrap();

    let output = run_xsync(&[
        "--out".as_ref(),
        "--owner".as_ref(),
        "--group".as_ref(),
        "--numeric-ids".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(&remote),
        "--exclude".as_ref(),
        "target".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(remote.join("nested/file")).unwrap(), b"hello");
    let local_time = fs::metadata(local.path().join("nested/file")).unwrap();
    let remote_time = fs::metadata(remote.join("nested/file")).unwrap();
    assert_eq!(
        (local_time.mtime(), local_time.mtime_nsec()),
        (remote_time.mtime(), remote_time.mtime_nsec())
    );
    assert_eq!(
        (local_time.uid(), local_time.gid()),
        (remote_time.uid(), remote_time.gid())
    );
    assert_eq!(
        fs::metadata(remote.join("nested/file"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert_eq!(
        fs::read_link(remote.join("link")).unwrap(),
        Path::new("nested/file")
    );
    assert!(!remote.join("target").exists());

    fs::write(remote.join("remote-only"), b"keep").unwrap();
    let output = run_xsync(&[
        "--out".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(&remote),
        "--exclude".as_ref(),
        "target".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(remote.join("remote-only")).unwrap(), b"keep");
}

#[test]
fn delete_out_removes_receiver_only_entries_and_preserves_excludes() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(local.path().join("keep"), b"sender").unwrap();
    fs::write(remote.path().join("extra-file"), b"remove").unwrap();
    symlink("nowhere", remote.path().join("extra-link")).unwrap();
    fs::create_dir(remote.path().join("old-directory")).unwrap();
    fs::write(remote.path().join("old-directory/child"), b"remove").unwrap();
    fs::write(remote.path().join("excluded"), b"preserve").unwrap();

    let output = run_xsync(&[
        "--out".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
        "--delete".as_ref(),
        "--exclude".as_ref(),
        "excluded".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(remote.path().join("keep")).unwrap(), b"sender");
    assert!(!remote.path().join("extra-file").exists());
    assert!(fs::symlink_metadata(remote.path().join("extra-link")).is_err());
    assert!(!remote.path().join("old-directory").exists());
    assert_eq!(
        fs::read(remote.path().join("excluded")).unwrap(),
        b"preserve"
    );
}

#[test]
fn delete_in_removes_local_receiver_only_entries() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(local.path().join("local-only"), b"remove").unwrap();
    fs::write(remote.path().join("remote-only"), b"copy").unwrap();

    let output = run_xsync(&[
        "--in".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
        "--delete".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!local.path().join("local-only").exists());
    assert_eq!(fs::read(local.path().join("remote-only")).unwrap(), b"copy");
}

#[test]
fn delete_dry_run_reports_removals_without_mutation() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(remote.path().join("extra"), b"preserve for dry run").unwrap();
    fs::create_dir(remote.path().join("old-directory")).unwrap();

    let output = run_xsync(&[
        "--dry-run".as_ref(),
        "--progress=always".as_ref(),
        "--out".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
        "--delete".as_ref(),
    ]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read(remote.path().join("extra")).unwrap(),
        b"preserve for dry run"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("would delete-remote file extra"));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("would delete-remote directory old-directory")
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("finalize directory metadata old"));
}

#[test]
fn excluded_descendant_makes_directory_delete_fail_closed() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::create_dir(remote.path().join("protected")).unwrap();
    fs::write(remote.path().join("protected/keep"), b"keep").unwrap();
    fs::write(remote.path().join("z-remove"), b"remove").unwrap();

    let output = run_xsync(&[
        "--progress=always".as_ref(),
        "--out".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
        "--delete".as_ref(),
        "--exclude".as_ref(),
        "protected/keep".as_ref(),
    ]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read(remote.path().join("protected/keep")).unwrap(),
        b"keep"
    );
    assert!(!remote.path().join("z-remove").exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("directory retained"));
    assert!(!fs::read_dir(remote.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .as_encoded_bytes()
            .starts_with(b".xsync.recovery.")
    }));
}

#[test]
fn recovery_artifacts_are_never_automatically_deleted() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    let recovery = remote.path().join(".xsync.recovery.interrupted");
    fs::write(&recovery, b"displaced user data").unwrap();

    let output = run_xsync(&[
        "--progress=always".as_ref(),
        "--out".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
        "--delete".as_ref(),
    ]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(recovery).unwrap(), b"displaced user data");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("recovery artifact is protected"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn missing_delete_feature_fails_before_any_job_mutation() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(local.path().join("new"), b"must not transfer").unwrap();
    fs::write(remote.path().join("extra"), b"must not delete").unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_xsync"));
    let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_ssh.sh");
    let ssh = format!("sh {}", shlex::try_quote(fake.to_str().unwrap()).unwrap());

    let output = xsync_command(binary, &ssh)
        .env("XSYNC_TEST_AGENT_DISABLE_DELETE", "1")
        .args([
            "--out".as_ref(),
            os(local.path()),
            "--dest".as_ref(),
            os(remote.path()),
            "--delete".as_ref(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(!remote.path().join("new").exists());
    assert_eq!(
        fs::read(remote.path().join("extra")).unwrap(),
        b"must not delete"
    );
}

#[test]
fn sender_appearance_fails_delete_and_suppresses_later_deletions() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(local.path().join("large"), vec![b'x'; 8 * 1024 * 1024]).unwrap();
    fs::write(remote.path().join("extra"), b"keep after race").unwrap();
    fs::write(remote.path().join("z-delete"), b"suppressed").unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_xsync"));
    let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_ssh.sh");
    let ssh = format!("sh {}", shlex::try_quote(fake.to_str().unwrap()).unwrap());

    let child = xsync_command(binary, &ssh)
        .env("XSYNC_TEST_AGENT_AFTER_DATA_DELAY_MS", "500")
        .args([
            "--progress=always".as_ref(),
            "--out".as_ref(),
            os(local.path()),
            "--dest".as_ref(),
            os(remote.path()),
            "--delete".as_ref(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_nonempty_temp(remote.path());
    fs::write(local.path().join("extra"), b"appeared on sender").unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        fs::read(remote.path().join("extra")).unwrap(),
        b"keep after race"
    );
    assert_eq!(
        fs::read(remote.path().join("z-delete")).unwrap(),
        b"suppressed"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("deletions suppressed after an earlier operation failed")
    );
}

#[test]
fn newer_side_wins_in_both_directions_and_delta_reuses_data() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    let old = vec![b'a'; 256 * 1024];
    let mut changed = old.clone();
    changed.splice(1000..1000, b"inserted".iter().copied());
    fs::write(local.path().join("large"), &changed).unwrap();
    fs::write(remote.path().join("large"), &old).unwrap();
    set_file_mtime(
        local.path().join("large"),
        FileTime::from_unix_time(2_000, 0),
    )
    .unwrap();
    set_file_mtime(
        remote.path().join("large"),
        FileTime::from_unix_time(1_000, 0),
    )
    .unwrap();

    let output = run_xsync(&[
        "--progress=always".as_ref(),
        "--modify-window".as_ref(),
        "0".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(remote.path().join("large")).unwrap(), changed);
    let progress = String::from_utf8_lossy(&output.stderr);
    assert!(progress.contains("reused"));
    assert!(progress.contains(" KiB/s") || progress.contains(" MiB/s"));

    let mut remote_changed = changed.clone();
    remote_changed.splice(5000..5000, b"remote-change".iter().copied());
    fs::write(remote.path().join("large"), &remote_changed).unwrap();
    set_file_mtime(
        remote.path().join("large"),
        FileTime::from_unix_time(3_000, 0),
    )
    .unwrap();
    let output = run_xsync(&[
        "--progress=always".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
    ]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read(local.path().join("large")).unwrap(),
        remote_changed
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("reused"));

    fs::write(remote.path().join("from-remote"), b"incoming").unwrap();
    let output = run_xsync(&[os(local.path()), "--dest".as_ref(), os(remote.path())]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(local.path().join("from-remote")).unwrap(),
        b"incoming"
    );
}

#[test]
fn subsecond_newer_mtime_wins_with_default_settings() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(local.path().join("file"), b"newer").unwrap();
    fs::write(remote.path().join("file"), b"older").unwrap();
    set_file_mtime(
        local.path().join("file"),
        FileTime::from_unix_time(10_000, 750_000_000),
    )
    .unwrap();
    set_file_mtime(
        remote.path().join("file"),
        FileTime::from_unix_time(10_000, 250_000_000),
    )
    .unwrap();
    let output = run_xsync(&[os(local.path()), "--dest".as_ref(), os(remote.path())]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(remote.path().join("file")).unwrap(), b"newer");
}

#[test]
fn equal_time_divergence_conflicts_without_mutation_and_dry_run_is_clean() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(local.path().join("file"), b"left").unwrap();
    fs::write(remote.path().join("file"), b"right-longer").unwrap();
    let time = FileTime::from_unix_time(1_000, 0);
    set_file_mtime(local.path().join("file"), time).unwrap();
    set_file_mtime(remote.path().join("file"), time).unwrap();
    let output = run_xsync(&[
        "--progress=json".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
    ]);
    assert_eq!(output.status.code(), Some(1));
    let events = json_stderr(&output);
    assert!(
        events
            .iter()
            .any(|event| { event["event"] == "error" && event["exit_code"] == 1 })
    );
    assert_eq!(fs::read(local.path().join("file")).unwrap(), b"left");
    assert_eq!(
        fs::read(remote.path().join("file")).unwrap(),
        b"right-longer"
    );

    fs::write(local.path().join("dry"), b"planned").unwrap();
    let output = run_xsync(&[
        "-n".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!remote.path().join("dry").exists());
}

#[test]
fn dry_run_displays_bidirectional_plan_and_mutates_neither_side() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(local.path().join("local-only"), b"from-local").unwrap();
    fs::write(remote.path().join("remote-only"), b"from-remote").unwrap();

    let output = run_xsync(&[
        "--dry-run".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
    ]);
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("would local-to-remote transfer file local-only"),
        "{stderr}"
    );
    assert!(
        stderr.contains("would remote-to-local transfer file remote-only"),
        "{stderr}"
    );
    assert!(!remote.path().join("local-only").exists());
    assert!(!local.path().join("remote-only").exists());
    assert_eq!(
        fs::read(local.path().join("local-only")).unwrap(),
        b"from-local"
    );
    assert_eq!(
        fs::read(remote.path().join("remote-only")).unwrap(),
        b"from-remote"
    );

    let json = run_xsync(&[
        "--dry-run".as_ref(),
        "--progress=json".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
    ]);
    assert!(json.status.success(), "{json:?}");
    let events = json_stderr(&json);
    assert!(events.iter().any(|event| {
        event["event"] == "planned_operation"
            && event["direction"] == "local-to-remote"
            && event["kind"] == "file"
            && event["path"] == "local-only"
    }));
    assert!(events.iter().any(|event| {
        event["event"] == "planned_operation"
            && event["direction"] == "remote-to-local"
            && event["kind"] == "file"
            && event["path"] == "remote-only"
    }));

    let quiet = run_xsync(&[
        "--dry-run".as_ref(),
        "--quiet".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
    ]);
    assert!(quiet.status.success(), "{quiet:?}");
    assert!(quiet.stderr.is_empty(), "{quiet:?}");
    assert!(!remote.path().join("local-only").exists());
    assert!(!local.path().join("remote-only").exists());
}

#[test]
fn one_session_handles_multiple_jobs() {
    let local_a = tempdir().unwrap();
    let local_b = tempdir().unwrap();
    let remote_a = tempdir().unwrap();
    let remote_b = tempdir().unwrap();
    fs::write(local_a.path().join("a"), b"a").unwrap();
    fs::write(local_b.path().join("b"), b"b").unwrap();
    let count_dir = tempdir().unwrap();
    let count_file = count_dir.path().join("connections");
    let binary = Path::new(env!("CARGO_BIN_EXE_xsync"));
    let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_ssh.sh");
    let ssh = format!("sh {}", shlex::try_quote(fake.to_str().unwrap()).unwrap());
    let output = xsync_command(binary, &ssh)
        .env("XSYNC_FAKE_COUNT_FILE", &count_file)
        .args([
            "--out".as_ref(),
            os(local_a.path()),
            "--dest".as_ref(),
            os(remote_a.path()),
            os(local_b.path()),
            "--dest".as_ref(),
            os(remote_b.path()),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(remote_a.path().join("a")).unwrap(), b"a");
    assert_eq!(fs::read(remote_b.path().join("b")).unwrap(), b"b");
    assert_eq!(fs::read_to_string(count_file).unwrap().lines().count(), 1);
}

#[test]
fn root_classification_failure_does_not_prevent_later_jobs() {
    let missing_parent = tempdir().unwrap();
    let missing = missing_parent.path().join("gone");
    let failed_remote = tempdir().unwrap();
    let good_local = tempdir().unwrap();
    let good_remote = tempdir().unwrap();
    fs::write(good_local.path().join("copied"), b"good job").unwrap();

    let output = run_xsync(&[
        "--out".as_ref(),
        os(&missing),
        "--dest".as_ref(),
        os(failed_remote.path()),
        os(good_local.path()),
        "--dest".as_ref(),
        os(good_remote.path()),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        fs::read(good_remote.path().join("copied")).unwrap(),
        b"good job"
    );
}

#[test]
fn receiver_setup_failures_are_drained_before_later_entries() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::create_dir(local.path().join("locked-in")).unwrap();
    fs::create_dir(remote.path().join("locked-in")).unwrap();
    fs::create_dir(local.path().join("locked-out")).unwrap();
    fs::create_dir(remote.path().join("locked-out")).unwrap();
    fs::write(local.path().join("locked-in/file"), b"old-local").unwrap();
    fs::write(remote.path().join("locked-in/file"), b"new-remote").unwrap();
    fs::write(local.path().join("locked-out/file"), b"new-local").unwrap();
    fs::write(remote.path().join("locked-out/file"), b"old-remote").unwrap();
    fs::write(local.path().join("z-out-ok"), b"out-ok").unwrap();
    fs::write(remote.path().join("z-in-ok"), b"in-ok").unwrap();
    let old = FileTime::from_unix_time(1_000, 0);
    let new = FileTime::from_unix_time(2_000, 0);
    set_file_mtime(local.path().join("locked-in/file"), old).unwrap();
    set_file_mtime(remote.path().join("locked-in/file"), new).unwrap();
    set_file_mtime(local.path().join("locked-out/file"), new).unwrap();
    set_file_mtime(remote.path().join("locked-out/file"), old).unwrap();
    fs::set_permissions(
        local.path().join("locked-in"),
        fs::Permissions::from_mode(0o555),
    )
    .unwrap();
    fs::set_permissions(
        remote.path().join("locked-out"),
        fs::Permissions::from_mode(0o555),
    )
    .unwrap();

    let output = run_xsync(&[os(local.path()), "--dest".as_ref(), os(remote.path())]);

    fs::set_permissions(
        local.path().join("locked-in"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(
        remote.path().join("locked-out"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(fs::read(remote.path().join("z-out-ok")).unwrap(), b"out-ok");
    assert_eq!(fs::read(local.path().join("z-in-ok")).unwrap(), b"in-ok");
    assert_eq!(
        fs::read(local.path().join("locked-in/file")).unwrap(),
        b"old-local"
    );
    assert_eq!(
        fs::read(remote.path().join("locked-out/file")).unwrap(),
        b"old-remote"
    );
}

#[test]
fn clock_skew_refusal_override_and_transport_death_map_to_exit_three() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(local.path().join("file"), b"clock-safe").unwrap();
    let tools = tempdir().unwrap();
    let binary = Path::new(env!("CARGO_BIN_EXE_xsync"));
    let skewed = tools.path().join("skewed agent");
    fs::write(
        &skewed,
        format!(
            "#!/bin/sh\nexport XSYNC_TEST_AGENT_CLOCK_OFFSET_NS=120000000000\nexec {} \"$@\"\n",
            shlex::try_quote(binary.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    fs::set_permissions(&skewed, fs::Permissions::from_mode(0o755)).unwrap();
    let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_ssh.sh");
    let ssh = format!("sh {}", shlex::try_quote(fake.to_str().unwrap()).unwrap());

    let refused = xsync_command(&skewed, &ssh)
        .args([
            "--max-clock-skew".as_ref(),
            "1".as_ref(),
            "--out".as_ref(),
            os(local.path()),
            "--dest".as_ref(),
            os(remote.path()),
        ])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(3), "{refused:?}");
    assert!(!remote.path().join("file").exists());

    let overridden = xsync_command(&skewed, &ssh)
        .args([
            "--progress=json".as_ref(),
            "--max-clock-skew".as_ref(),
            "1".as_ref(),
            "--ignore-clock-skew".as_ref(),
            "--out".as_ref(),
            os(local.path()),
            "--dest".as_ref(),
            os(remote.path()),
        ])
        .output()
        .unwrap();
    assert!(overridden.status.success(), "{overridden:?}");
    let events = json_stderr(&overridden);
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "clock_skew_warning")
    );
    assert_eq!(fs::read(remote.path().join("file")).unwrap(), b"clock-safe");

    let dead = tools.path().join("dead-agent");
    fs::write(&dead, "#!/bin/sh\nexit 7\n").unwrap();
    fs::set_permissions(&dead, fs::Permissions::from_mode(0o755)).unwrap();
    let died = xsync_command(&dead, &ssh)
        .args([
            "--progress=json".as_ref(),
            os(local.path()),
            "--dest".as_ref(),
            os(remote.path()),
        ])
        .output()
        .unwrap();
    assert_eq!(died.status.code(), Some(3), "{died:?}");
    let events = json_stderr(&died);
    assert!(
        events
            .iter()
            .any(|event| { event["event"] == "error" && event["exit_code"] == 3 })
    );
}

#[test]
fn reduced_frames_incompatible_endpoint_checksum_noop_and_warning_exit() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    let payload = vec![b'a'; 256 * 1024];
    fs::write(local.path().join("file"), &payload).unwrap();
    let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_ssh.sh");
    let ssh = format!("sh {}", shlex::try_quote(fake.to_str().unwrap()).unwrap());
    let binary = Path::new(env!("CARGO_BIN_EXE_xsync"));
    let output = xsync_command(binary, &ssh)
        .env("XSYNC_TEST_AGENT_MAX_FRAME", "2048")
        .args([
            "--out".as_ref(),
            os(local.path()),
            "--dest".as_ref(),
            os(remote.path()),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(remote.path().join("file")).unwrap(), payload);

    let deep_local = tempdir().unwrap();
    let deep_remote = tempdir().unwrap();
    let mut deep = deep_local.path().to_path_buf();
    for _ in 0..4 {
        deep.push("x".repeat(200));
    }
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("file"), b"bounded").unwrap();
    let bounded_failure = xsync_command(binary, &ssh)
        .env("XSYNC_TEST_AGENT_MAX_FRAME", "2048")
        .args([
            "--out".as_ref(),
            os(deep_local.path()),
            "--dest".as_ref(),
            os(deep_remote.path()),
        ])
        .output()
        .unwrap();
    assert_eq!(
        bounded_failure.status.code(),
        Some(1),
        "{bounded_failure:?}"
    );
    assert!(!String::from_utf8_lossy(&bounded_failure.stderr).contains("outgoing frame"));

    let long_root_base = tempdir().unwrap();
    let mut missing_long_root = long_root_base.path().to_path_buf();
    for index in 0..8 {
        missing_long_root.push(format!("{index}-{}", "r".repeat(217)));
    }
    let abort_remote = tempdir().unwrap();
    let bounded_abort = xsync_command(binary, &ssh)
        .env("XSYNC_TEST_AGENT_MAX_FRAME", "2048")
        .args([
            "--out".as_ref(),
            os(&missing_long_root),
            "--dest".as_ref(),
            os(abort_remote.path()),
        ])
        .output()
        .unwrap();
    assert_eq!(bounded_abort.status.code(), Some(1), "{bounded_abort:?}");
    let stderr = String::from_utf8_lossy(&bounded_abort.stderr);
    assert!(!stderr.contains("outgoing frame"), "{stderr}");
    assert!(!stderr.contains("request/job ID mismatch"), "{stderr}");

    let exclude_remote = tempdir().unwrap();
    let mut exclude_command = xsync_command(binary, &ssh);
    exclude_command
        .env("XSYNC_TEST_AGENT_MAX_FRAME", "2048")
        .args([
            "--out".as_ref(),
            os(local.path()),
            "--dest".as_ref(),
            os(exclude_remote.path()),
        ]);
    for index in 0..100 {
        exclude_command
            .arg("--exclude")
            .arg(format!("generated-pattern-{index:03}-*.temporary"));
    }
    let exclude_failure = exclude_command.output().unwrap();
    assert_eq!(
        exclude_failure.status.code(),
        Some(1),
        "{exclude_failure:?}"
    );
    assert!(!String::from_utf8_lossy(&exclude_failure.stderr).contains("outgoing frame"));

    let symlink_local = tempdir().unwrap();
    let symlink_remote = tempdir().unwrap();
    symlink(
        OsString::from_vec(vec![b't'; 300]),
        symlink_local.path().join("long-link"),
    )
    .unwrap();
    let symlink_failure = xsync_command(binary, &ssh)
        .env("XSYNC_TEST_AGENT_MAX_FRAME", "2048")
        .args([
            "--out".as_ref(),
            os(symlink_local.path()),
            "--dest".as_ref(),
            os(symlink_remote.path()),
        ])
        .output()
        .unwrap();
    assert_eq!(
        symlink_failure.status.code(),
        Some(1),
        "{symlink_failure:?}"
    );
    assert!(!String::from_utf8_lossy(&symlink_failure.stderr).contains("outgoing frame"));

    let incompatible = xsync_command(binary, &ssh)
        .env("XSYNC_TEST_AGENT_INCOMPATIBLE", "1")
        .args([os(local.path()), "--dest".as_ref(), os(remote.path())])
        .output()
        .unwrap();
    assert_eq!(incompatible.status.code(), Some(3), "{incompatible:?}");

    let identical_local = tempdir().unwrap();
    let identical_remote = tempdir().unwrap();
    fs::write(identical_local.path().join("same"), b"identical").unwrap();
    fs::copy(
        identical_local.path().join("same"),
        identical_remote.path().join("same"),
    )
    .unwrap();
    fs::write(identical_local.path().join("different"), b"transfer me").unwrap();
    let metadata = fs::metadata(identical_local.path().join("same")).unwrap();
    set_file_mtime(
        identical_remote.path().join("same"),
        FileTime::from_unix_time(metadata.mtime(), metadata.mtime_nsec() as u32),
    )
    .unwrap();
    let identical = run_xsync(&[
        "--progress=json".as_ref(),
        "--checksum".as_ref(),
        os(identical_local.path()),
        "--dest".as_ref(),
        os(identical_remote.path()),
    ]);
    assert!(identical.status.success(), "{identical:?}");
    let events = json_stderr(&identical);
    assert!(events.iter().any(|event| {
        event["event"] == "entry_start" && event["kind"] == "file" && event["path"] == "different"
    }));
    assert!(!events.iter().any(|event| {
        event["event"] == "entry_start" && event["kind"] == "file" && event["path"] == "same"
    }));

    let warning_local = tempdir().unwrap();
    let warning_remote = tempdir().unwrap();
    let special_path = warning_local.path().join("special-mode");
    fs::create_dir(&special_path).unwrap();
    // A sticky directory exercises the same clearing-and-warning path without
    // creating a setuid file, which Nix forbids and Darwin restricts.
    fs::set_permissions(&special_path, fs::Permissions::from_mode(0o1755)).unwrap();
    let warning = run_xsync(&[
        "--progress=always".as_ref(),
        "--out".as_ref(),
        os(warning_local.path()),
        "--dest".as_ref(),
        os(warning_remote.path()),
    ]);
    assert!(warning.status.success(), "{warning:?}");
    assert!(String::from_utf8_lossy(&warning.stderr).contains("special permission bits"));
}

#[test]
fn direction_filters_and_checksum_semantics_are_safe() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(local.path().join("local-only"), b"local").unwrap();
    fs::write(remote.path().join("remote-only"), b"remote").unwrap();
    let output = run_xsync(&[
        "--in".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!remote.path().join("local-only").exists());
    assert_eq!(
        fs::read(local.path().join("remote-only")).unwrap(),
        b"remote"
    );

    fs::write(local.path().join("ambiguous"), b"left").unwrap();
    fs::write(remote.path().join("ambiguous"), b"rght").unwrap();
    let time = FileTime::from_unix_time(5_000, 0);
    set_file_mtime(local.path().join("ambiguous"), time).unwrap();
    set_file_mtime(remote.path().join("ambiguous"), time).unwrap();
    let output = run_xsync(&[
        "--checksum".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(local.path().join("ambiguous")).unwrap(), b"left");
    assert_eq!(fs::read(remote.path().join("ambiguous")).unwrap(), b"rght");
}

#[test]
fn unreadable_bases_fall_back_to_a_literal_transfer_in_both_directions() {
    let local_in = tempdir().unwrap();
    let remote_in = tempdir().unwrap();
    fs::write(local_in.path().join("file"), b"old-local-basis").unwrap();
    fs::write(remote_in.path().join("file"), b"new-remote-source").unwrap();
    set_file_mtime(
        local_in.path().join("file"),
        FileTime::from_unix_time(1_000, 0),
    )
    .unwrap();
    fs::set_permissions(
        local_in.path().join("file"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    set_file_mtime(
        remote_in.path().join("file"),
        FileTime::from_unix_time(2_000, 0),
    )
    .unwrap();
    let inbound = run_xsync(&[
        "--in".as_ref(),
        os(local_in.path()),
        "--dest".as_ref(),
        os(remote_in.path()),
    ]);
    assert!(inbound.status.success(), "{inbound:?}");
    assert_eq!(
        fs::read(local_in.path().join("file")).unwrap(),
        b"new-remote-source"
    );

    let local_out = tempdir().unwrap();
    let remote_out = tempdir().unwrap();
    fs::write(local_out.path().join("file"), b"new-local-source").unwrap();
    fs::write(remote_out.path().join("file"), b"old-remote-basis").unwrap();
    set_file_mtime(
        local_out.path().join("file"),
        FileTime::from_unix_time(2_000, 0),
    )
    .unwrap();
    set_file_mtime(
        remote_out.path().join("file"),
        FileTime::from_unix_time(1_000, 0),
    )
    .unwrap();
    fs::set_permissions(
        remote_out.path().join("file"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let outbound = run_xsync(&[
        "--out".as_ref(),
        os(local_out.path()),
        "--dest".as_ref(),
        os(remote_out.path()),
    ]);
    assert!(outbound.status.success(), "{outbound:?}");
    assert_eq!(
        fs::read(remote_out.path().join("file")).unwrap(),
        b"new-local-source"
    );
}

#[test]
fn non_utf8_names_and_missing_root_policies_work() {
    let local = tempdir().unwrap();
    let remote_parent = tempdir().unwrap();
    let remote = remote_parent.path().join("created");
    let name = OsString::from_vec(vec![b'f', 0xff]);
    fs::write(local.path().join(&name), b"bytes").unwrap();
    let output = run_xsync(&[
        "--out".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(&remote),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(remote.join(&name)).unwrap(), b"bytes");

    let absent = remote_parent.path().join("absent-read-side");
    let output = run_xsync(&[
        "--in".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(&absent),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!absent.exists());

    let no_parent = remote_parent.path().join("missing-parent/root");
    let output = run_xsync(&[
        "--out".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(&no_parent),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!no_parent.exists());
}

#[test]
fn quoted_remote_program_and_json_progress_are_valid() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(local.path().join("file"), b"data").unwrap();
    let tools = tempdir().unwrap();
    let quoted_binary = tools.path().join("x'sync tool");
    fs::copy(env!("CARGO_BIN_EXE_xsync"), &quoted_binary).unwrap();
    fs::set_permissions(&quoted_binary, fs::Permissions::from_mode(0o755)).unwrap();
    let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_ssh.sh");
    let ssh = format!("sh {}", shlex::try_quote(fake.to_str().unwrap()).unwrap());
    let output = xsync_command(&quoted_binary, &ssh)
        .args([
            "--progress=json".as_ref(),
            "--out".as_ref(),
            os(local.path()),
            "--dest".as_ref(),
            os(remote.path()),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events: Vec<_> = String::from_utf8(output.stderr)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect();
    assert!(events.iter().any(|event| event["event"] == "session_start"));
    assert!(
        events
            .iter()
            .any(|event| event["event"] == "entry_progress")
    );
    assert!(events.iter().any(|event| {
        event["event"] == "entry_progress"
            && event["direction"] == "local-to-remote"
            && event.get("logical_bytes").is_some()
            && event.get("literal_bytes").is_some()
            && event.get("reused_bytes").is_some()
            && event.get("rate_bytes_per_second").is_some()
            && event.get("eta_seconds").is_some()
    }));
    assert!(events.iter().any(|event| event["event"] == "entry_done"));
    assert!(events.iter().any(|event| event["event"] == "session_done"));
}

#[test]
fn verbose_enables_diagnostics_and_quiet_suppresses_progress() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    fs::write(local.path().join("file"), b"data").unwrap();
    let verbose = run_xsync(&[
        "-v".as_ref(),
        "--out".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(remote.path()),
    ]);
    assert!(verbose.status.success(), "{verbose:?}");
    assert!(String::from_utf8_lossy(&verbose.stderr).contains("xsync: starting"));

    let quiet_remote = tempdir().unwrap();
    let quiet = run_xsync(&[
        "--quiet".as_ref(),
        "--progress=always".as_ref(),
        "--out".as_ref(),
        os(local.path()),
        "--dest".as_ref(),
        os(quiet_remote.path()),
    ]);
    assert!(quiet.status.success(), "{quiet:?}");
    assert!(quiet.stderr.is_empty(), "{quiet:?}");
}

#[test]
fn corrupt_banner_is_exit_three_and_sigint_is_exit_130() {
    let local = tempdir().unwrap();
    let remote = tempdir().unwrap();
    let scripts = tempdir().unwrap();
    let banner = scripts.path().join("banner.sh");
    fs::write(&banner, "#!/bin/sh\nprintf 'login banner'\nsleep 1\n").unwrap();
    let ssh = format!("sh {}", shlex::try_quote(banner.to_str().unwrap()).unwrap());
    let output = xsync_command(Path::new(env!("CARGO_BIN_EXE_xsync")), &ssh)
        .args([os(local.path()), "--dest".as_ref(), os(remote.path())])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("protocol stdout"));

    let slow = scripts.path().join("slow.sh");
    fs::write(&slow, "#!/bin/sh\nsleep 30\n").unwrap();
    let ssh = format!("sh {}", shlex::try_quote(slow.to_str().unwrap()).unwrap());
    let mut child = xsync_command(Path::new(env!("CARGO_BIN_EXE_xsync")), &ssh)
        .args([os(local.path()), "--dest".as_ref(), os(remote.path())])
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::INT).unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(130));
}

#[test]
fn active_interrupt_cleans_temporaries_in_both_directions() {
    let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/fake_ssh.sh");
    let ssh = format!("sh {}", shlex::try_quote(fake.to_str().unwrap()).unwrap());
    let binary = Path::new(env!("CARGO_BIN_EXE_xsync"));

    let local_out = tempdir().unwrap();
    let remote_out = tempdir().unwrap();
    fs::write(local_out.path().join("large"), vec![b'x'; 8 * 1024 * 1024]).unwrap();
    let mut child = xsync_command(binary, &ssh)
        .env("XSYNC_TEST_AGENT_AFTER_DATA_DELAY_MS", "500")
        .args([
            "--progress=never".as_ref(),
            "--out".as_ref(),
            os(local_out.path()),
            "--dest".as_ref(),
            os(remote_out.path()),
        ])
        .spawn()
        .unwrap();
    wait_for_nonempty_temp(remote_out.path());
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::INT).unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(130));
    assert!(!contains_xsync_temp(remote_out.path()));
    assert!(!remote_out.path().join("large").exists());

    let local_in = tempdir().unwrap();
    let remote_in = tempdir().unwrap();
    fs::write(remote_in.path().join("large"), vec![b'y'; 8 * 1024 * 1024]).unwrap();
    let mut child = xsync_command(binary, &ssh)
        .env("XSYNC_TEST_CONTROLLER_APPLY_DELAY_MS", "500")
        .args([
            "--progress=never".as_ref(),
            "--in".as_ref(),
            os(local_in.path()),
            "--dest".as_ref(),
            os(remote_in.path()),
        ])
        .spawn()
        .unwrap();
    wait_for_temp(local_in.path());
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::INT).unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(130));
    assert!(!contains_xsync_temp(local_in.path()));
    assert!(!local_in.path().join("large").exists());
}
