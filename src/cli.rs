use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    exclude::Excludes,
    path::{lexical_absolute, paths_overlap},
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum Direction {
    #[default]
    InOut,
    In,
    Out,
}

impl Direction {
    #[must_use]
    pub const fn permits_local_to_remote(self) -> bool {
        matches!(self, Self::InOut | Self::Out)
    }

    #[must_use]
    pub const fn permits_remote_to_local(self) -> bool {
        matches!(self, Self::InOut | Self::In)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProgressMode {
    #[default]
    Auto,
    Always,
    Never,
    Json,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobConfig {
    pub local: PathBuf,
    pub remote: PathBuf,
    pub direction: Direction,
    pub excludes: Vec<String>,
    dest_explicit: bool,
    direction_explicit: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub server: String,
    pub ssh: Vec<String>,
    pub remote_program: String,
    pub direction: Direction,
    pub progress: ProgressMode,
    pub dry_run: bool,
    pub checksum: bool,
    pub modify_window_ns: i128,
    pub max_clock_skew_ns: i128,
    pub ignore_clock_skew: bool,
    pub preserve_owner: bool,
    pub preserve_group: bool,
    pub numeric_ids: bool,
    pub verbose: u8,
    pub quiet: bool,
    pub jobs: Vec<JobConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Invocation {
    Help,
    Version,
    Agent,
    Run(Config),
}

pub fn parse_env() -> Result<Invocation> {
    parse(
        std::env::args_os().skip(1).collect(),
        std::env::current_dir().map_err(|e| Error::io(None, e))?,
    )
}

pub fn parse(args: Vec<OsString>, cwd: PathBuf) -> Result<Invocation> {
    if args.is_empty() {
        return Err(Error::Usage("missing SERVER and directory".into()));
    }
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        return Ok(Invocation::Help);
    }
    if args.len() == 1 && (args[0] == "--version" || args[0] == "-V") {
        return Ok(Invocation::Version);
    }
    if args.len() == 1 && args[0] == "--agent" {
        return Ok(Invocation::Agent);
    }
    if args[0].as_bytes().starts_with(b"-") {
        return Err(Error::Usage("SERVER cannot begin with '-'".into()));
    }
    let server = text_value(&args[0], "SERVER")?.to_owned();
    let mut ssh = vec!["ssh".to_owned()];
    let mut remote_program = "xsync".to_owned();
    let mut direction = Direction::InOut;
    let mut direction_explicit = false;
    let mut progress = ProgressMode::Auto;
    let mut dry_run = false;
    let mut checksum = false;
    let mut modify_window_ns = 0i128;
    let mut max_clock_skew_ns = 60_000_000_000i128;
    let mut ignore_clock_skew = false;
    let mut preserve_owner = false;
    let mut preserve_group = false;
    let mut numeric_ids = false;
    let mut verbose = 0u8;
    let mut quiet = false;
    let mut jobs = Vec::<JobConfig>::new();
    let mut current: Option<JobConfig> = None;
    let mut index = 1usize;
    let mut positional_only = false;

    while index < args.len() {
        let arg = &args[index];
        if positional_only {
            push_job(&mut current, &mut jobs);
            current = Some(new_job(arg, direction, &cwd)?);
            index += 1;
            continue;
        }
        if arg == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if arg == "--dir" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| Error::Usage("--dir requires PATH".into()))?;
            push_job(&mut current, &mut jobs);
            current = Some(new_job(value, direction, &cwd)?);
            index += 1;
            continue;
        }
        if !arg.as_bytes().starts_with(b"-") {
            push_job(&mut current, &mut jobs);
            current = Some(new_job(arg, direction, &cwd)?);
            index += 1;
            continue;
        }
        let arg_text = text_value(arg, "option")?;
        if let Some(job) = current.as_mut() {
            match arg_text {
                "--dest" => {
                    index += 1;
                    let value = args
                        .get(index)
                        .ok_or_else(|| Error::Usage("--dest requires PATH".into()))?;
                    if job.dest_explicit {
                        return Err(Error::Usage("duplicate --dest for directory".into()));
                    }
                    let remote = PathBuf::from(value);
                    if !remote.is_absolute() {
                        return Err(Error::Usage("--dest must be absolute".into()));
                    }
                    job.remote = lexical_absolute(&remote, &cwd)?;
                    job.dest_explicit = true;
                }
                "--exclude" => {
                    index += 1;
                    let value = args
                        .get(index)
                        .ok_or_else(|| Error::Usage("--exclude requires PATTERN".into()))?;
                    job.excludes
                        .push(text_value(value, "--exclude pattern")?.to_owned());
                }
                "--in" => set_job_direction(job, Direction::In)?,
                "--out" => set_job_direction(job, Direction::Out)?,
                "--in-out" => set_job_direction(job, Direction::InOut)?,
                _ => {
                    return Err(Error::Usage(format!("unknown directory option {arg_text}")));
                }
            }
            index += 1;
            continue;
        }

        match arg_text {
            "--in" => set_direction(
                &mut direction,
                &mut direction_explicit,
                Direction::In,
                "global",
            )?,
            "--out" => set_direction(
                &mut direction,
                &mut direction_explicit,
                Direction::Out,
                "global",
            )?,
            "--in-out" => set_direction(
                &mut direction,
                &mut direction_explicit,
                Direction::InOut,
                "global",
            )?,
            "--dry-run" | "-n" => dry_run = true,
            "--checksum" => checksum = true,
            "--ignore-clock-skew" => ignore_clock_skew = true,
            "--owner" => preserve_owner = true,
            "--group" => preserve_group = true,
            "--numeric-ids" => numeric_ids = true,
            "--verbose" | "-v" => verbose = verbose.saturating_add(1),
            "--quiet" | "-q" => quiet = true,
            "--progress" => progress = ProgressMode::Always,
            "--ssh" | "--remote-program" | "--modify-window" | "--max-clock-skew" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| Error::Usage(format!("{arg_text} requires a value")))?;
                let value = text_value(value, arg_text)?;
                match arg_text {
                    "--ssh" => {
                        ssh = shlex::split(value)
                            .ok_or_else(|| Error::Usage("invalid quoting in --ssh".into()))?;
                        if ssh.is_empty() {
                            return Err(Error::Usage("--ssh cannot be empty".into()));
                        }
                    }
                    "--remote-program" => {
                        if value.is_empty() || value.contains('\0') {
                            return Err(Error::Usage("invalid --remote-program".into()));
                        }
                        remote_program = value.to_owned();
                    }
                    "--modify-window" => modify_window_ns = parse_seconds(value, arg_text)?,
                    "--max-clock-skew" => max_clock_skew_ns = parse_seconds(value, arg_text)?,
                    _ => unreachable!(),
                }
            }
            _ if arg_text.starts_with("--progress=") => {
                progress = match &arg_text[11..] {
                    "auto" => ProgressMode::Auto,
                    "always" => ProgressMode::Always,
                    "never" => ProgressMode::Never,
                    "json" => ProgressMode::Json,
                    value => return Err(Error::Usage(format!("invalid progress mode {value:?}"))),
                };
            }
            _ => return Err(Error::Usage(format!("unknown global option {arg_text}"))),
        }
        index += 1;
    }
    push_job(&mut current, &mut jobs);
    if jobs.is_empty() {
        return Err(Error::Usage(
            "SERVER requires at least one directory".into(),
        ));
    }
    validate_no_overlap(&jobs)?;
    for job in &jobs {
        Excludes::compile(&job.excludes)?;
    }
    if numeric_ids && !(preserve_owner || preserve_group) {
        return Err(Error::Usage(
            "--numeric-ids requires --owner or --group".into(),
        ));
    }
    Ok(Invocation::Run(Config {
        server,
        ssh,
        remote_program,
        direction,
        progress,
        dry_run,
        checksum,
        modify_window_ns,
        max_clock_skew_ns,
        ignore_clock_skew,
        preserve_owner,
        preserve_group,
        numeric_ids,
        verbose,
        quiet,
        jobs,
    }))
}

fn parse_seconds(value: &str, option: &str) -> Result<i128> {
    let seconds: f64 = value
        .parse()
        .map_err(|_| Error::Usage(format!("{option} requires nonnegative seconds")))?;
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(Error::Usage(format!(
            "{option} requires nonnegative seconds"
        )));
    }
    Ok((seconds * 1_000_000_000.0).round() as i128)
}

fn new_job(value: &OsStr, direction: Direction, cwd: &std::path::Path) -> Result<JobConfig> {
    let local = lexical_absolute(&PathBuf::from(value), cwd)?;
    Ok(JobConfig {
        remote: local.clone(),
        local,
        direction,
        excludes: Vec::new(),
        dest_explicit: false,
        direction_explicit: false,
    })
}

fn text_value<'a>(value: &'a OsStr, description: &str) -> Result<&'a str> {
    value
        .to_str()
        .ok_or_else(|| Error::Usage(format!("{description} must be valid UTF-8")))
}

fn set_job_direction(job: &mut JobConfig, value: Direction) -> Result<()> {
    let mut explicit = job.direction_explicit;
    set_direction(&mut job.direction, &mut explicit, value, "directory")?;
    job.direction_explicit = explicit;
    Ok(())
}

fn set_direction(
    current: &mut Direction,
    explicit: &mut bool,
    value: Direction,
    scope: &str,
) -> Result<()> {
    if *explicit && *current != value {
        return Err(Error::Usage(format!(
            "conflicting {scope} direction options"
        )));
    }
    *current = value;
    *explicit = true;
    Ok(())
}

fn push_job(current: &mut Option<JobConfig>, jobs: &mut Vec<JobConfig>) {
    if let Some(job) = current.take() {
        jobs.push(job);
    }
}

fn validate_no_overlap(jobs: &[JobConfig]) -> Result<()> {
    for (index, left) in jobs.iter().enumerate() {
        for right in &jobs[index + 1..] {
            if paths_overlap(&left.local, &right.local) {
                return Err(Error::Usage(format!(
                    "local job roots overlap: {} and {}",
                    crate::path::display_absolute(&left.local),
                    crate::path::display_absolute(&right.local)
                )));
            }
            if paths_overlap(&left.remote, &right.remote) {
                return Err(Error::Usage(format!(
                    "remote job roots overlap: {} and {}",
                    crate::path::display_absolute(&left.remote),
                    crate::path::display_absolute(&right.remote)
                )));
            }
        }
    }
    Ok(())
}

#[must_use]
pub fn help() -> &'static str {
    "xsync - stateless bidirectional directory synchronization\n\n\
Usage:\n  xsync SERVER [GLOBAL_OPTIONS] DIR [DIRECTORY_OPTIONS]...\n  xsync --agent\n\n\
Global options (before the first directory):\n  --in | --out | --in-out       Allowed transfer direction (default: in-out)\n  --ssh COMMAND                 SSH command (default: ssh)\n  --remote-program PATH         Remote xsync executable (default: xsync)\n  --progress[=MODE]             auto, always, never, or json\n  -n, --dry-run                 Show planned changes without modifying files\n  --checksum                    Hash metadata-equal files\n  --modify-window SECONDS       Mtime equality window (default: 0)\n  --max-clock-skew SECONDS      Refuse unsafe clock skew (default: 60)\n  --ignore-clock-skew           Warn but do not refuse for clock skew\n  --owner --group --numeric-ids Ownership preservation controls\n  -v, --verbose | -q, --quiet   Diagnostic verbosity\n  --dir PATH                    Explicit directory (including leading '-')\n\n\
Directory options:\n  --dest ABSOLUTE_PATH          Override the remote root\n  --exclude PATTERN             Repeatable symmetric exclusion\n  --in | --out | --in-out       Override direction for this directory\n\n\
Absence never implies deletion. Equal-time divergent files are conflicts.\n"
}

#[cfg(test)]
mod tests {
    use std::{os::unix::ffi::OsStringExt, path::Path};

    use super::*;

    fn strings(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn run(values: &[&str]) -> Config {
        match parse(strings(values), PathBuf::from("/work")).unwrap() {
            Invocation::Run(config) => config,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn groups_multiple_directories_and_inherits_direction() {
        let config = run(&[
            "host",
            "--out",
            "a",
            "--exclude",
            "target",
            "--in",
            "b",
            "--dest",
            "/remote/b",
        ]);
        assert_eq!(config.jobs[0].local, Path::new("/work/a"));
        assert_eq!(config.jobs[0].remote, Path::new("/work/a"));
        assert_eq!(config.jobs[0].direction, Direction::In);
        assert_eq!(config.jobs[0].excludes, ["target"]);
        assert_eq!(config.jobs[1].direction, Direction::Out);
        assert_eq!(config.jobs[1].remote, Path::new("/remote/b"));
    }

    #[test]
    fn bare_progress_does_not_consume_directory() {
        let config = run(&["host", "--progress", "/data"]);
        assert_eq!(config.progress, ProgressMode::Always);
        assert_eq!(config.jobs[0].local, Path::new("/data"));
    }

    #[test]
    fn explicit_dir_allows_leading_dash() {
        let config = run(&["host", "--dir", "-data", "--exclude", "x"]);
        assert_eq!(config.jobs[0].local, Path::new("/work/-data"));
    }

    #[test]
    fn invalid_groupings_are_usage_errors() {
        for values in [
            vec!["host"],
            vec!["-host", "/data"],
            vec!["host", "--dest", "/x"],
            vec!["host", "/a", "--dest", "relative"],
            vec!["host", "/a", "--dest", "/x", "--dest", "/y"],
            vec!["host", "/a", "--dest", "/a", "--dest", "/a"],
            vec!["host", "--numeric-ids", "/a"],
            vec!["host", "--in", "--out", "/a"],
            vec!["host", "/a", "--in", "--out"],
        ] {
            assert!(
                parse(strings(&values), PathBuf::from("/work")).is_err(),
                "{values:?}"
            );
        }
    }

    #[test]
    fn rejects_overlapping_roots() {
        assert!(parse(strings(&["host", "/a", "/a/b"]), PathBuf::from("/work")).is_err());
    }

    #[test]
    fn preserves_non_utf8_directory_and_destination_paths() {
        let local = OsString::from_vec(b"local-\xff".to_vec());
        let destination = OsString::from_vec(b"/remote-\xfe".to_vec());
        let invocation = parse(
            vec![
                OsString::from("host"),
                local,
                OsString::from("--dest"),
                destination,
            ],
            PathBuf::from("/work"),
        )
        .unwrap();
        let Invocation::Run(config) = invocation else {
            panic!("expected run invocation");
        };
        assert_eq!(
            config.jobs[0].local.as_os_str().as_bytes(),
            b"/work/local-\xff"
        );
        assert_eq!(
            config.jobs[0].remote.as_os_str().as_bytes(),
            b"/remote-\xfe"
        );
    }

    #[test]
    fn rejects_invalid_excludes_during_cli_validation() {
        for pattern in ["", "!keep", "["] {
            assert!(
                parse(
                    strings(&["host", "/data", "--exclude", pattern]),
                    PathBuf::from("/work")
                )
                .is_err()
            );
        }
    }

    #[test]
    fn parses_ssh_progress_and_numeric_options() {
        let config = run(&[
            "host",
            "--ssh",
            "ssh -p '2222'",
            "--progress=json",
            "--modify-window",
            "0.5",
            "--max-clock-skew",
            "2",
            "--owner",
            "--numeric-ids",
            "--dry-run",
            "/data",
        ]);
        assert_eq!(config.ssh, ["ssh", "-p", "2222"]);
        assert_eq!(config.progress, ProgressMode::Json);
        assert_eq!(config.modify_window_ns, 500_000_000);
        assert_eq!(config.max_clock_skew_ns, 2_000_000_000);
        assert!(config.preserve_owner && config.numeric_ids);
        assert!(config.dry_run);
    }

    #[test]
    fn parses_short_dry_run_option() {
        assert!(run(&["host", "-n", "/data"]).dry_run);
    }

    #[test]
    fn option_terminator_turns_following_tokens_into_paths() {
        let config = run(&["host", "--", "--out", "--dest"]);
        assert_eq!(config.jobs.len(), 2);
        assert_eq!(config.jobs[0].local, Path::new("/work/--out"));
        assert_eq!(config.jobs[1].local, Path::new("/work/--dest"));
    }

    #[test]
    fn extended_invalid_option_matrix() {
        for values in [
            vec!["host", "--ssh", "", "/data"],
            vec!["host", "--ssh", "'unterminated", "/data"],
            vec!["host", "--progress=bars", "/data"],
            vec!["host", "--modify-window", "-1", "/data"],
            vec!["host", "--max-clock-skew", "NaN", "/data"],
            vec!["host", "--unknown", "/data"],
            vec!["host", "/data", "--unknown"],
            vec![
                "host", "--group", "/a", "--dest", "/r", "/b", "--dest", "/r/sub",
            ],
        ] {
            assert!(
                parse(strings(&values), PathBuf::from("/work")).is_err(),
                "{values:?}"
            );
        }
    }
}
