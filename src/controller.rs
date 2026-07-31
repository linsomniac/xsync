use std::{
    collections::BTreeMap,
    io::{IsTerminal, Read, Seek, SeekFrom, Write as _},
    os::fd::AsFd,
    os::unix::ffi::OsStrExt,
    os::unix::process::CommandExt,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{TrySendError, sync_channel},
    },
    thread::JoinHandle,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    Error, Result,
    cli::{Config, JobConfig, ProgressMode},
    delta,
    exclude::Excludes,
    filesystem::{OwnershipPolicy, RootDir},
    manifest::Manifest,
    planner::{Digests, Operation, Side, ambiguous_paths, build_plan_with_budget},
    protocol::{
        DigestRecord, EntryResult, Envelope, Framed, JobSummary, Limits, Message, PROTOCOL_MAJOR,
        PROTOCOL_MINOR,
    },
};

const MAX_JOB_MEMORY: usize = 512 * 1024 * 1024;

#[derive(Debug)]
struct JobMemoryBudget {
    used: usize,
}

impl JobMemoryBudget {
    fn charge(&mut self, amount: usize, what: &str) -> Result<()> {
        self.used = self
            .used
            .checked_add(amount)
            .ok_or_else(|| Error::entry("limit", None, "job memory accounting overflow"))?;
        if self.used > MAX_JOB_MEMORY {
            return Err(Error::entry(
                "limit",
                None,
                format!("job memory limit exceeded while retaining {what}"),
            ));
        }
        Ok(())
    }

    fn remaining(&self) -> usize {
        MAX_JOB_MEMORY.saturating_sub(self.used)
    }
}

pub fn run(config: &Config) -> Result<JobSummary> {
    let interrupted = Arc::new(AtomicBool::new(false));
    let signal_id = signal_hook::flag::register(signal_hook::consts::SIGINT, interrupted.clone())
        .map_err(|error| Error::io(None, error))?;
    let mut session = RemoteSession::spawn(config, interrupted.clone())?;
    let done = Arc::new(AtomicBool::new(false));
    let watchdog = spawn_interrupt_watchdog(session.child.id(), interrupted.clone(), done.clone());
    let result = (|| {
        let mut progress = ProgressReporter::new(config);
        progress.session_start(config.jobs.len());
        session.handshake(config)?;
        let mut total = JobSummary::default();
        for (index, job) in config.jobs.iter().enumerate() {
            check_interrupted(&interrupted)?;
            let job_id = index as u64 + 1;
            let summary = match run_job(&mut session, config, job, job_id, index + 1, &mut progress)
            {
                Ok(summary) => summary,
                Err(error @ (Error::Io { .. } | Error::Entry { .. })) => {
                    let message = error.to_string();
                    progress.job_error(job, &message);
                    if session.active_job == Some(job_id) {
                        let reason = session.bounded_abort_reason(job_id, &message)?;
                        match session.rpc(job_id, Message::AbortJob { reason })? {
                            Message::JobAborted => session.active_job = None,
                            other => {
                                return Err(Error::Protocol(format!(
                                    "unexpected abort response: {other:?}"
                                )));
                            }
                        }
                    }
                    JobSummary {
                        errors: 1,
                        ..JobSummary::default()
                    }
                }
                Err(error) => return Err(error),
            };
            add_summary(&mut total, &summary);
        }
        session.finish()?;
        progress.session_done(&total);
        if total.conflicts > 0 || total.errors > 0 {
            Err(Error::Partial)
        } else {
            Ok(total)
        }
    })();
    if interrupted.load(Ordering::Acquire) {
        session.stop_after_interrupt();
    }
    done.store(true, Ordering::Release);
    let _ = watchdog.join();
    signal_hook::low_level::unregister(signal_id);
    if interrupted.load(Ordering::Acquire) {
        Err(Error::Interrupted)
    } else {
        result
    }
}

struct InterruptibleIo<T> {
    inner: Option<T>,
    interrupted: Arc<AtomicBool>,
}

impl<T> InterruptibleIo<T> {
    fn new(inner: T, interrupted: Arc<AtomicBool>) -> Self {
        Self {
            inner: Some(inner),
            interrupted,
        }
    }

    fn interruption(&self) -> std::io::Error {
        // `read_exact` and `write_all` retry ErrorKind::Interrupted, so use a
        // terminal I/O kind and map the outer operation to exit 130 instead.
        std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "xsync interrupted")
    }

    fn close(&mut self) {
        self.inner.take();
    }
}

impl<T: Read> Read for InterruptibleIo<T> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.interrupted.load(Ordering::Acquire) {
                return Err(self.interruption());
            }
            let Some(inner) = self.inner.as_mut() else {
                return Ok(0);
            };
            match inner.read(buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                result => return result,
            }
        }
    }
}

impl<T: std::io::Write> std::io::Write for InterruptibleIo<T> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        loop {
            if self.interrupted.load(Ordering::Acquire) {
                return Err(self.interruption());
            }
            let Some(inner) = self.inner.as_mut() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "xsync transport input is closed",
                ));
            };
            match inner.write(buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.interrupted.load(Ordering::Acquire) {
            return Err(self.interruption());
        }
        self.inner
            .as_mut()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "xsync transport input is closed",
                )
            })?
            .flush()
    }
}

fn set_nonblocking(fd: &impl AsFd) -> Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd)
        .map_err(|error| Error::io(None, std::io::Error::from(error)))?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|error| Error::io(None, std::io::Error::from(error)))
}

struct RemoteSession {
    framed: Framed<InterruptibleIo<ChildStdout>, InterruptibleIo<ChildStdin>>,
    child: Child,
    stderr_thread: Option<JoinHandle<()>>,
    next_request: u64,
    features: u64,
    limits: Limits,
    finished: bool,
    active_job: Option<u64>,
}

impl RemoteSession {
    fn spawn(config: &Config, interrupted: Arc<AtomicBool>) -> Result<Self> {
        let program = config
            .ssh
            .first()
            .ok_or_else(|| Error::Usage("empty SSH command".into()))?;
        let remote_command = format!("{} --agent", quote_shell_word(&config.remote_program));
        let mut command = Command::new(program);
        command
            .args(&config.ssh[1..])
            .arg("--")
            .arg(&config.server)
            .arg(remote_command)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| Error::Transport(format!("could not start SSH transport: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Transport("transport stdin unavailable".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Transport("transport stdout unavailable".into()))?;
        set_nonblocking(&stdin)?;
        set_nonblocking(&stdout)?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::Transport("transport stderr unavailable".into()))?;
        let stderr_thread = spawn_stderr_drain(stderr, config.progress == ProgressMode::Json);
        Ok(Self {
            framed: Framed::new(
                InterruptibleIo::new(stdout, interrupted.clone()),
                InterruptibleIo::new(stdin, interrupted),
            ),
            child,
            stderr_thread: Some(stderr_thread),
            next_request: 1,
            features: 0,
            limits: Limits::default(),
            finished: false,
            active_job: None,
        })
    }

    fn handshake(&mut self, config: &Config) -> Result<()> {
        self.framed.write_magic()?;
        self.framed.read_magic()?;
        let request_id = self.allocate_request();
        let nonce = rand::random::<[u8; 16]>();
        let local_wall = wall_time_ns();
        let started = Instant::now();
        self.framed.send(&Envelope {
            request_id,
            job_id: 0,
            message: Message::Hello {
                major: PROTOCOL_MAJOR,
                min_minor: PROTOCOL_MINOR,
                max_minor: PROTOCOL_MINOR,
                implementation: env!("CARGO_PKG_VERSION").into(),
                features: crate::protocol::SUPPORTED_FEATURES,
                nonce,
                wall_time_ns: local_wall,
                monotonic_stamp: request_id,
                limits: Limits::default(),
            },
        })?;
        let response = self.receive_for(request_id, 0)?;
        match response {
            Message::HelloAck {
                major,
                minor,
                nonce: echoed,
                wall_time_ns: remote_wall,
                features,
                limits,
                ..
            } if major == PROTOCOL_MAJOR && minor == PROTOCOL_MINOR && echoed == nonce => {
                limits.validate()?;
                if features & !crate::protocol::SUPPORTED_FEATURES != 0
                    || features & crate::protocol::FEATURE_DELTA == 0
                    || (config.checksum && features & crate::protocol::FEATURE_CHECKSUM == 0)
                    || ((config.preserve_owner || config.preserve_group)
                        && features & crate::protocol::FEATURE_OWNERSHIP == 0)
                {
                    return Err(Error::Transport(
                        "remote endpoint lacks a required protocol feature".into(),
                    ));
                }
                self.features = features;
                self.limits = limits;
                self.framed.set_max_frame(limits.max_frame as usize);
                let half_rtt =
                    i128::try_from(started.elapsed().as_nanos() / 2).unwrap_or(i128::MAX);
                let skew = i128::from(remote_wall) - (i128::from(local_wall) + half_rtt);
                if skew.abs() > 2_000_000_000 && !config.quiet {
                    let seconds = skew as f64 / 1_000_000_000.0;
                    if config.progress == ProgressMode::Json {
                        eprintln!(
                            "{}",
                            serde_json::json!({
                                "version": 1,
                                "event": "clock_skew_warning",
                                "skew_seconds": seconds,
                            })
                        );
                    } else {
                        eprintln!("xsync: warning: estimated remote clock skew is {seconds:.3}s");
                    }
                }
                if skew.abs() > config.max_clock_skew_ns && !config.ignore_clock_skew {
                    return Err(Error::Transport(format!(
                        "estimated clock skew {:.3}s exceeds --max-clock-skew",
                        skew as f64 / 1_000_000_000.0
                    )));
                }
                Ok(())
            }
            Message::Incompatible { reason, .. } => Err(Error::Transport(format!(
                "incompatible remote xsync: {reason}"
            ))),
            other => Err(Error::Protocol(format!(
                "unexpected handshake response: {other:?}"
            ))),
        }
    }

    fn rpc(&mut self, job_id: u64, message: Message) -> Result<Message> {
        let request_id = self.allocate_request();
        self.framed.send(&Envelope {
            request_id,
            job_id,
            message,
        })?;
        self.receive_for(request_id, job_id)
    }

    fn bounded_abort_reason(&self, job_id: u64, reason: &str) -> Result<String> {
        let mut budget = reason.len().min(self.limits.max_frame as usize);
        loop {
            let candidate = crate::protocol::truncate_diagnostic(reason, budget);
            let envelope = Envelope {
                request_id: self.next_request,
                job_id,
                message: Message::AbortJob {
                    reason: candidate.clone(),
                },
            };
            let encoded = crate::protocol::encoded_envelope_len(&envelope)?;
            if encoded <= self.limits.max_frame as usize {
                return Ok(candidate);
            }
            if budget == 0 {
                return Err(Error::Protocol(
                    "negotiated frame cannot encode an empty abort reason".into(),
                ));
            }
            budget = budget.saturating_sub((encoded - self.limits.max_frame as usize).max(1));
        }
    }

    fn allocate_request(&mut self) -> u64 {
        let id = self.next_request;
        self.next_request = self.next_request.saturating_add(1);
        id
    }

    fn receive_for(&mut self, request_id: u64, job_id: u64) -> Result<Message> {
        let envelope = self.framed.receive()?;
        if envelope.request_id != request_id || envelope.job_id != job_id {
            return Err(Error::Protocol("response request/job ID mismatch".into()));
        }
        match envelope.message {
            Message::Error(error) => {
                if error.fatal {
                    Err(Error::Protocol(format!(
                        "{}: {}",
                        error.class, error.message
                    )))
                } else {
                    Err(Error::entry(error.class, None, error.message))
                }
            }
            message => Ok(message),
        }
    }

    fn finish(&mut self) -> Result<()> {
        match self.rpc(0, Message::EndSession)? {
            Message::Goodbye(_) => {}
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected session-end response: {other:?}"
                )));
            }
        }
        let status = self
            .child
            .wait()
            .map_err(|e| Error::Transport(format!("could not wait for transport: {e}")))?;
        if let Some(thread) = self.stderr_thread.take() {
            let _ = thread.join();
        }
        self.finished = true;
        if !status.success() {
            return Err(Error::Transport(format!(
                "SSH transport exited with {status}"
            )));
        }
        Ok(())
    }

    fn stop_after_interrupt(&mut self) {
        // Closing the controller-to-agent pipe lets the agent unwind any
        // in-flight receiver and remove its guarded temporary file. Escalate
        // only after a bounded grace period so an unresponsive transport can
        // never make SIGINT hang the controller.
        self.framed.writer_mut().close();
        if self.wait_for_exit(std::time::Duration::from_secs(1)) {
            return;
        }
        self.signal_group(rustix::process::Signal::TERM);
        if self.wait_for_exit(std::time::Duration::from_secs(1)) {
            return;
        }
        self.signal_group(rustix::process::Signal::KILL);
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.finish_interrupted_child();
    }

    fn wait_for_exit(&mut self, timeout: std::time::Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.finish_interrupted_child();
                    return true;
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Ok(None) | Err(_) => return false,
            }
        }
    }

    fn signal_group(&self, signal: rustix::process::Signal) {
        if let Ok(raw) = i32::try_from(self.child.id())
            && let Some(pid) = rustix::process::Pid::from_raw(raw)
        {
            let _ = rustix::process::kill_process_group(pid, signal);
        }
    }

    fn finish_interrupted_child(&mut self) {
        self.finished = true;
        if let Some(thread) = self.stderr_thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for RemoteSession {
    fn drop(&mut self) {
        if !self.finished {
            if let Ok(raw) = i32::try_from(self.child.id())
                && let Some(pid) = rustix::process::Pid::from_raw(raw)
            {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(thread) = self.stderr_thread.take() {
            let _ = thread.join();
        }
    }
}

fn spawn_stderr_drain(stderr: std::process::ChildStderr, json: bool) -> JoinHandle<()> {
    let (sender, receiver) = sync_channel::<Vec<u8>>(128);
    let reader = std::thread::spawn(move || {
        let mut stderr = stderr;
        let mut buffer = [0u8; 4096];
        let mut dropped = 0u64;
        loop {
            let count = match stderr.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            match sender.try_send(buffer[..count].to_vec()) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => dropped = dropped.saturating_add(1),
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
        if dropped != 0 {
            let _ = sender.send(format!("[{dropped} remote diagnostic chunks dropped]\n").into());
        }
    });
    std::thread::spawn(move || {
        while let Ok(chunk) = receiver.recv() {
            let message = escape_diagnostic(&chunk);
            if json {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "version": 1,
                        "event": "remote_diagnostic",
                        "message": message,
                    })
                );
            } else {
                eprintln!("remote: {message}");
            }
        }
        let _ = reader.join();
    })
}

fn escape_diagnostic(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| match byte {
            b'\n' => "\\n".to_owned(),
            b'\r' => "\\r".to_owned(),
            b'\t' => "\\t".to_owned(),
            0x20..=0x7e => char::from(*byte).to_string(),
            _ => format!("\\x{byte:02x}"),
        })
        .collect()
}

fn spawn_interrupt_watchdog(
    child_id: u32,
    interrupted: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        while !done.load(Ordering::Acquire) {
            if interrupted.load(Ordering::Acquire) {
                // Give the interruptible protocol pipes time to return to the
                // controller, which closes stdin and lets the agent unwind its
                // temporary-file guards on EOF.
                for _ in 0..100 {
                    if done.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                if let Ok(raw) = i32::try_from(child_id)
                    && let Some(pid) = rustix::process::Pid::from_raw(raw)
                {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
                    for _ in 0..100 {
                        if done.load(Ordering::Acquire) {
                            return;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    })
}

fn check_interrupted(interrupted: &AtomicBool) -> Result<()> {
    if interrupted.load(Ordering::Acquire) {
        Err(Error::Interrupted)
    } else {
        Ok(())
    }
}

fn run_job(
    session: &mut RemoteSession,
    config: &Config,
    job: &JobConfig,
    job_id: u64,
    job_number: usize,
    progress: &mut ProgressReporter,
) -> Result<JobSummary> {
    if session.features & crate::protocol::FEATURE_DELTA == 0 {
        return Err(Error::Protocol("delta feature was not negotiated".into()));
    }
    let remote_root = job.remote.as_os_str().as_bytes().to_vec();
    if remote_root.len() > session.limits.max_path as usize {
        return Err(Error::entry(
            "limit",
            Some(job.remote.clone()),
            "remote root exceeds the negotiated path/frame limit",
        ));
    }
    let begin_job = Message::BeginJob {
        root: remote_root,
        direction: job.direction,
        excludes: job.excludes.clone(),
        dry_run: config.dry_run,
        preserve_owner: config.preserve_owner,
        preserve_group: config.preserve_group,
        numeric_ids: config.numeric_ids,
    };
    if crate::protocol::encoded_envelope_len(&Envelope {
        request_id: session.next_request,
        job_id,
        message: begin_job.clone(),
    })? > session.limits.max_frame as usize
    {
        return Err(Error::entry(
            "limit",
            Some(job.remote.clone()),
            "job root and exclude options exceed the negotiated frame limit",
        ));
    }
    match session.rpc(job_id, begin_job)? {
        Message::JobAccepted => {}
        other => {
            return Err(Error::Protocol(format!(
                "unexpected BeginJob response: {other:?}"
            )));
        }
    }
    progress.job_start(job_number, job);
    session.active_job = Some(job_id);
    progress.phase("inventory", None);

    let manifest_request = session.allocate_request();
    session.framed.send(&Envelope {
        request_id: manifest_request,
        job_id,
        message: Message::ManifestRequest,
    })?;

    let excludes = Excludes::compile(&job.excludes)?;
    let mut memory = JobMemoryBudget { used: 0 };
    let local_inventory = open_local(
        job,
        config.dry_run,
        &excludes,
        session.limits,
        memory.remaining(),
    );
    let (local_root, local_manifest) = match local_inventory {
        Ok(inventory) => inventory,
        Err(error) => {
            drain_manifest_response(session, manifest_request, job_id)?;
            return Err(error);
        }
    };
    memory.charge(local_manifest.estimated_memory_bytes(), "local manifest")?;
    if let Some(root) = &local_root {
        memory.charge(
            root.directory_identity_memory_bytes()?,
            "local directory identity map",
        )?;
    }
    let remote_manifest = receive_manifest(session, manifest_request, job_id, memory.remaining())?;
    memory.charge(remote_manifest.estimated_memory_bytes(), "remote manifest")?;

    let (digests, checksum_failures) = if config.checksum {
        let (digests, failures) = resolve_digests(
            session,
            job_id,
            local_root.as_ref(),
            &local_manifest,
            &remote_manifest,
            config.modify_window_ns,
            &mut memory,
        )?;
        (Some(digests), failures)
    } else {
        (None, Vec::new())
    };
    let plan = build_plan_with_budget(
        &local_manifest,
        &remote_manifest,
        job.direction,
        config.modify_window_ns,
        digests.as_ref(),
        memory.remaining(),
    )?;
    memory.charge(plan.estimated_memory_bytes(), "reconciliation plan")?;
    progress.plan_ready(&plan);
    progress.phase("transfer", None);
    let mut summary = JobSummary {
        conflicts: plan.conflicts.len() as u64,
        warnings: plan.warnings.len().saturating_add(checksum_failures.len()) as u64,
        ..JobSummary::default()
    };
    let mut created_directories = BTreeMap::new();
    let ownership = OwnershipPolicy {
        owner: config.preserve_owner,
        group: config.preserve_group,
        numeric_ids: config.numeric_ids,
    };
    for conflict in &plan.conflicts {
        progress.conflict(conflict);
    }
    for (path, warning) in &plan.warnings {
        progress.warning(path, warning);
    }
    for (path, warning) in &checksum_failures {
        progress.warning(path, warning);
    }

    if config.dry_run {
        for operation in &plan.operations {
            progress.planned_operation(operation);
        }
    } else {
        for operation in &plan.operations {
            progress.entry_start(operation);
            if let Err(error) = execute_operation(
                session,
                job_id,
                local_root
                    .as_ref()
                    .ok_or_else(|| Error::Protocol("local root unavailable".into()))?,
                &local_manifest,
                &remote_manifest,
                operation,
                &mut summary,
                &mut created_directories,
                ownership,
                progress,
            ) {
                match error {
                    Error::Io { .. } | Error::Entry { .. } => {
                        progress.entry_error(operation, &error.to_string());
                        summary.errors += 1;
                    }
                    error => return Err(error),
                }
            } else {
                progress.entry_done(operation, &summary);
            }
        }
    }
    match session.rpc(job_id, Message::FinishJob)? {
        Message::JobResult(_) => session.active_job = None,
        other => {
            return Err(Error::Protocol(format!(
                "unexpected FinishJob response: {other:?}"
            )));
        }
    }
    progress.job_done(job, &summary, plan.operations.len());
    Ok(summary)
}

fn open_local(
    job: &JobConfig,
    dry_run: bool,
    excludes: &Excludes,
    limits: Limits,
    max_memory: usize,
) -> Result<(Option<RootDir>, Manifest)> {
    match std::fs::symlink_metadata(&job.local) {
        Ok(metadata) if metadata.is_dir() => {
            let root = RootDir::open(&job.local)?;
            let manifest = root.scan_with_budget(excludes, limits, max_memory)?;
            Ok((Some(root), manifest))
        }
        Ok(_) => Err(Error::Io {
            path: Some(job.local.clone()),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "local root is not a directory",
            ),
        }),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && job.direction.permits_remote_to_local() =>
        {
            if dry_run {
                Ok((None, Manifest::default()))
            } else {
                Ok((
                    Some(RootDir::create_and_open(&job.local)?),
                    Manifest::default(),
                ))
            }
        }
        Err(error) => Err(Error::io(Some(job.local.clone()), error)),
    }
}

fn receive_manifest(
    session: &mut RemoteSession,
    request_id: u64,
    job_id: u64,
    max_memory: usize,
) -> Result<Manifest> {
    let mut manifest = Manifest::default();
    let mut bytes = 0usize;
    let (declared_records, declared_bytes) = match session.receive_for(request_id, job_id)? {
        Message::StreamStart { records, bytes } => (records, bytes),
        other => {
            return Err(Error::Protocol(format!(
                "unexpected manifest stream start: {other:?}"
            )));
        }
    };
    if declared_records.is_some_and(|count| count > session.limits.max_entries) {
        return Err(Error::Protocol(
            "declared manifest stream exceeds negotiated limits".into(),
        ));
    }
    let mut limit_error = declared_bytes
        .is_some_and(|count| count > max_memory as u64)
        .then(|| "remote manifest exceeds the remaining job memory budget".to_string());
    let mut received_records = 0u64;
    loop {
        match session.receive_for(request_id, job_id)? {
            Message::ManifestChunk(entries) => {
                for entry in entries {
                    entry.validate()?;
                    received_records = received_records.saturating_add(1);
                    bytes = bytes.saturating_add(entry.estimated_wire_bytes());
                    if entry.path.as_bytes().len() > session.limits.max_path as usize
                        || entry.symlink_target.len() > session.limits.max_path as usize
                        || entry.path.depth() > session.limits.max_depth as usize
                        || received_records > session.limits.max_entries
                    {
                        return Err(Error::Protocol(
                            "remote manifest resource limit exceeded".into(),
                        ));
                    }
                    if bytes > max_memory {
                        limit_error.get_or_insert_with(|| {
                            "remote manifest exceeds the remaining job memory budget".into()
                        });
                        continue;
                    }
                    if limit_error.is_none()
                        && manifest.entries.insert(entry.path.clone(), entry).is_some()
                    {
                        return Err(Error::Protocol("duplicate remote manifest path".into()));
                    }
                }
            }
            Message::StreamEnd {
                records,
                bytes: ending_bytes,
                status: crate::protocol::StreamStatus::Ok,
            } => {
                if records != received_records
                    || ending_bytes != bytes as u64
                    || declared_records.is_some_and(|declared| declared != records)
                    || declared_bytes.is_some_and(|declared| declared != ending_bytes)
                {
                    return Err(Error::Protocol(
                        "manifest stream counts do not match".into(),
                    ));
                }
                if let Some(error) = limit_error {
                    return Err(Error::entry("limit", None, error));
                }
                manifest.validate(true)?;
                return Ok(manifest);
            }
            Message::StreamEnd {
                status: crate::protocol::StreamStatus::Failed(error),
                ..
            } => {
                return Err(Error::Io {
                    path: None,
                    source: std::io::Error::other(error),
                });
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected manifest record: {other:?}"
                )));
            }
        }
    }
}

fn drain_manifest_response(
    session: &mut RemoteSession,
    request_id: u64,
    job_id: u64,
) -> Result<()> {
    match session.receive_for(request_id, job_id)? {
        Message::StreamStart { .. } => {}
        other => {
            return Err(Error::Protocol(format!(
                "unexpected manifest stream start while draining: {other:?}"
            )));
        }
    }
    loop {
        match session.receive_for(request_id, job_id)? {
            Message::ManifestChunk(_) => {}
            Message::StreamEnd { .. } => return Ok(()),
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected manifest record while draining: {other:?}"
                )));
            }
        }
    }
}

fn resolve_digests(
    session: &mut RemoteSession,
    job_id: u64,
    local_root: Option<&RootDir>,
    local: &Manifest,
    remote: &Manifest,
    window: i128,
    memory: &mut JobMemoryBudget,
) -> Result<(Digests, Vec<(crate::path::RelativePath, String)>)> {
    let ambiguous: Vec<_> = ambiguous_paths(local, remote, window).into_iter().collect();
    memory.charge(
        ambiguous.iter().fold(0usize, |bytes, path| {
            bytes.saturating_add(64 + path.as_bytes().len())
        }),
        "checksum ambiguity set",
    )?;
    if ambiguous.is_empty() {
        return Ok((Digests::new(), Vec::new()));
    }
    let root = local_root.ok_or_else(|| Error::Protocol("checksum needs local root".into()))?;
    let mut digests = Digests::new();
    let mut failures = BTreeMap::<crate::path::RelativePath, String>::new();
    for path in &ambiguous {
        let entry = local
            .get(path)
            .ok_or_else(|| Error::Protocol("ambiguous local path missing".into()))?;
        match root.digest_source(entry) {
            Ok(digest) => {
                digests.insert((Side::Local, path.clone()), digest);
            }
            Err(error) => {
                let message = format!("checksum failed locally: {error}");
                memory.charge(message.len() + 64 + path.as_bytes().len(), "checksum error")?;
                failures.insert(path.clone(), message);
                digests.insert((Side::Local, path.clone()), [0; 32]);
            }
        }
        memory.charge(96 + path.as_bytes().len(), "local checksum digest")?;
    }
    let mut offset = 0usize;
    while offset < ambiguous.len() {
        let mut chunk = Vec::new();
        while offset + chunk.len() < ambiguous.len()
            && chunk.len() < crate::protocol::MAX_RECORDS_PER_FRAME
        {
            chunk.push(ambiguous[offset + chunk.len()].clone());
            let envelope = Envelope {
                request_id: session.next_request,
                job_id,
                message: Message::DigestRequest(chunk.clone()),
            };
            if crate::protocol::encoded_envelope_len(&envelope)? > session.limits.max_frame as usize
            {
                chunk.pop();
                break;
            }
        }
        if chunk.is_empty() {
            return Err(Error::Protocol(
                "one digest request path exceeds negotiated frame size".into(),
            ));
        }
        let request_id = session.allocate_request();
        session.framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::DigestRequest(chunk.clone()),
        })?;
        let mut received = vec![false; chunk.len()];
        let mut received_count = 0usize;
        while received_count < chunk.len() {
            let records = match session.receive_for(request_id, job_id)? {
                Message::DigestResponse(records) if !records.is_empty() => records,
                other => {
                    return Err(Error::Protocol(format!(
                        "unexpected digest response: {other:?}"
                    )));
                }
            };
            for DigestRecord {
                path,
                digest,
                error,
            } in records
            {
                let index = chunk.binary_search(&path).map_err(|_| {
                    Error::Protocol("digest response contains an unexpected path".into())
                })?;
                if std::mem::replace(&mut received[index], true) {
                    return Err(Error::Protocol(
                        "digest response contains a duplicate path".into(),
                    ));
                }
                received_count += 1;
                let path_bytes = path.as_bytes().len();
                if let Some(error) = error {
                    let message = format!("checksum failed remotely: {error}");
                    memory.charge(message.len() + 64 + path_bytes, "checksum error")?;
                    failures.entry(path.clone()).or_insert(message);
                    digests.insert((Side::Remote, path), [1; 32]);
                } else {
                    let digest =
                        digest.ok_or_else(|| Error::Protocol("empty digest response".into()))?;
                    digests.insert((Side::Remote, path), digest);
                }
                memory.charge(96 + path_bytes, "remote checksum digest")?;
            }
        }
        offset += chunk.len();
    }
    for path in failures.keys() {
        digests.insert((Side::Local, path.clone()), [0; 32]);
        digests.insert((Side::Remote, path.clone()), [1; 32]);
    }
    Ok((digests, failures.into_iter().collect()))
}

#[allow(clippy::too_many_arguments)]
fn execute_operation(
    session: &mut RemoteSession,
    job_id: u64,
    local_root: &RootDir,
    local_manifest: &Manifest,
    remote_manifest: &Manifest,
    operation: &Operation,
    summary: &mut JobSummary,
    created_directories: &mut BTreeMap<
        (Side, crate::path::RelativePath),
        crate::manifest::Fingerprint,
    >,
    ownership: OwnershipPolicy,
    progress: &mut ProgressReporter,
) -> Result<()> {
    match operation {
        Operation::CreateDirectory {
            target: Side::Local,
            entry,
        } => {
            let fingerprint = local_root.create_directory(
                entry,
                local_manifest
                    .get(&entry.path)
                    .map(|entry| entry.fingerprint),
            )?;
            created_directories.insert((Side::Local, entry.path.clone()), fingerprint);
        }
        Operation::CreateDirectory {
            target: Side::Remote,
            entry,
        } => {
            let result = account_apply(
                session.rpc(
                    job_id,
                    Message::ApplyDirectory {
                        entry: entry.clone(),
                        expected_destination: remote_manifest
                            .get(&entry.path)
                            .map(|entry| entry.fingerprint),
                    },
                )?,
                summary,
            )?;
            if let Some(warning) = &result.warning {
                progress.warning(&entry.path, warning);
            }
            let fingerprint = result.fingerprint.ok_or_else(|| {
                Error::Protocol("remote directory result omitted its fingerprint".into())
            })?;
            created_directories.insert((Side::Remote, entry.path.clone()), fingerprint);
        }
        Operation::TransferFile {
            source: Side::Local,
            entry,
        } => {
            transfer_out(
                session,
                job_id,
                local_root,
                remote_manifest,
                entry,
                summary,
                progress,
            )?;
        }
        Operation::TransferFile {
            source: Side::Remote,
            entry,
        } => {
            transfer_in(
                session,
                job_id,
                local_root,
                local_manifest,
                entry,
                summary,
                ownership,
                progress,
            )?;
        }
        Operation::WriteSymlink {
            source: Side::Local,
            entry,
        } => {
            local_root.validate_symlink_source(entry)?;
            let result = account_apply(
                session.rpc(
                    job_id,
                    Message::ApplySymlink {
                        entry: entry.clone(),
                        expected_destination: remote_manifest
                            .get(&entry.path)
                            .map(|entry| entry.fingerprint),
                    },
                )?,
                summary,
            )?;
            if let Some(warning) = &result.warning {
                progress.warning(&entry.path, warning);
            }
        }
        Operation::WriteSymlink {
            source: Side::Remote,
            entry,
        } => {
            let target = match session.rpc(
                job_id,
                Message::SymlinkSourceRequest {
                    path: entry.path.clone(),
                    expected_source: entry.fingerprint,
                },
            )? {
                Message::SymlinkSourceResponse { target } => target,
                other => {
                    return Err(Error::Protocol(format!(
                        "unexpected symlink source response: {other:?}"
                    )));
                }
            };
            if target != entry.symlink_target {
                return Err(Error::Protocol(
                    "remote symlink response does not match its manifest".into(),
                ));
            }
            if let Some(warning) = local_root.write_symlink_atomic_with_policy(
                entry,
                local_manifest
                    .get(&entry.path)
                    .map(|entry| entry.fingerprint),
                ownership,
            )? {
                summary.warnings = summary.warnings.saturating_add(1);
                progress.warning(&entry.path, &warning);
            }
        }
        Operation::FinalizeDirectory {
            target: Side::Remote,
            entry,
        } => {
            let expected_destination = remote_manifest
                .get(&entry.path)
                .map(|entry| entry.fingerprint)
                .or_else(|| {
                    created_directories
                        .get(&(Side::Remote, entry.path.clone()))
                        .copied()
                })
                .ok_or_else(|| {
                    Error::Protocol("remote finalization target has no recorded identity".into())
                })?;
            let result = account_apply(
                session.rpc(
                    job_id,
                    Message::FinalizeDirectory {
                        entry: entry.clone(),
                        expected_destination,
                    },
                )?,
                summary,
            )?;
            if let Some(warning) = &result.warning {
                progress.warning(&entry.path, warning);
            }
        }
        Operation::FinalizeDirectory {
            target: Side::Local,
            entry,
        } => {
            let expected = local_manifest
                .get(&entry.path)
                .map(|entry| entry.fingerprint)
                .or_else(|| {
                    created_directories
                        .get(&(Side::Local, entry.path.clone()))
                        .copied()
                })
                .ok_or_else(|| {
                    Error::Protocol("local finalization target has no recorded identity".into())
                })?;
            if let Some(warning) = local_root.finalize_directory(entry, expected, ownership)? {
                summary.warnings = summary.warnings.saturating_add(1);
                progress.warning(&entry.path, &warning);
            }
        }
    }
    Ok(())
}

fn transfer_out(
    session: &mut RemoteSession,
    job_id: u64,
    local_root: &RootDir,
    remote_manifest: &Manifest,
    entry: &crate::manifest::ManifestEntry,
    summary: &mut JobSummary,
    progress: &mut ProgressReporter,
) -> Result<()> {
    let ((), retried) = retry_basis_once(|force_literal| {
        transfer_out_attempt(
            session,
            job_id,
            local_root,
            remote_manifest,
            entry,
            summary,
            progress,
            force_literal,
        )
    })?;
    if retried {
        summary.warnings = summary.warnings.saturating_add(1);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn transfer_out_attempt(
    session: &mut RemoteSession,
    job_id: u64,
    local_root: &RootDir,
    remote_manifest: &Manifest,
    entry: &crate::manifest::ManifestEntry,
    summary: &mut JobSummary,
    progress: &mut ProgressReporter,
    force_literal: bool,
) -> Result<()> {
    let expected = remote_manifest
        .get(&entry.path)
        .map(|entry| entry.fingerprint);
    let (block_size, signatures, fallback) =
        request_remote_signatures(session, job_id, entry.path.clone(), expected, force_literal)?;
    if fallback {
        summary.warnings = summary.warnings.saturating_add(1);
    }
    let block_size = usize::try_from(block_size)
        .map_err(|_| Error::Protocol("remote block size does not fit this platform".into()))?;
    if signatures.len().saturating_mul(40) > delta::WIRE_SIGNATURE_BUDGET {
        return Err(Error::Protocol(
            "remote signature response exceeds negotiated budget".into(),
        ));
    }
    let mut source = local_root.source_file(entry)?;
    let request_id = session.allocate_request();
    session.framed.send(&Envelope {
        request_id,
        job_id,
        message: Message::ApplyStart {
            entry: entry.clone(),
            expected_destination: expected,
            block_size: u32::try_from(block_size)
                .map_err(|_| Error::Protocol("block size overflow".into()))?,
            literal_only: force_literal || fallback,
        },
    })?;
    match session.receive_for(request_id, job_id)? {
        Message::ApplyReady => {}
        Message::ApplyResult(result) => {
            return expect_apply(Message::ApplyResult(result)).map(|_| ());
        }
        other => {
            return Err(Error::Protocol(format!(
                "unexpected apply readiness response: {other:?}"
            )));
        }
    }
    let mut pending = Vec::with_capacity(8);
    let mut literal_bytes = 0u64;
    let mut logical_progress = 0u64;
    let max_literal = (session.limits.max_literal as usize).min(
        (session.limits.max_frame as usize)
            .saturating_sub(256)
            .max(1),
    );
    let generated = delta::generate_stream(&mut source, &signatures, block_size, |instruction| {
        let outbound = split_literal_instruction(instruction, max_literal);
        for instruction in outbound {
            if let crate::delta::Instruction::Literal(bytes) = &instruction {
                literal_bytes = literal_bytes.saturating_add(bytes.len() as u64);
                logical_progress = logical_progress.saturating_add(bytes.len() as u64);
            } else if let crate::delta::Instruction::Copy { block_count, .. } = &instruction {
                logical_progress = logical_progress
                    .saturating_add(u64::from(*block_count).saturating_mul(block_size as u64));
            }
            progress.entry_progress(
                &entry.path,
                "local-to-remote",
                logical_progress.min(entry.size),
                entry.size,
                literal_bytes,
            );
            push_instruction_record_controller(
                session,
                request_id,
                job_id,
                &mut pending,
                instruction,
            )?;
        }
        Ok(())
    });
    let mut trailer = match generated {
        Ok(trailer) => trailer,
        Err(error) => {
            // The agent has acknowledged ApplyReady, so finish the stream even
            // when the local source fails. The deliberately invalid trailer
            // makes the receiver discard its temporary.
            session.framed.send(&Envelope {
                request_id,
                job_id,
                message: Message::ApplyEnd(crate::delta::Trailer {
                    length: 0,
                    digest: [0; 32],
                }),
            })?;
            let _ = session.receive_for(request_id, job_id)?;
            return Err(error);
        }
    };
    if !pending.is_empty() {
        session.framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::InstructionChunk(pending),
        })?;
    }
    let source_validation = local_root.validate_source(entry, &source);
    if source_validation.is_err() {
        trailer.digest[0] ^= 0xff;
    }
    session.framed.send(&Envelope {
        request_id,
        job_id,
        message: Message::ApplyEnd(trailer),
    })?;
    let response = account_apply(session.receive_for(request_id, job_id)?, summary);
    source_validation?;
    let response = response?;
    if let Some(warning) = &response.warning {
        progress.warning(&entry.path, warning);
    }
    account_transfer(summary, trailer, literal_bytes);
    Ok(())
}

fn request_remote_signatures(
    session: &mut RemoteSession,
    job_id: u64,
    path: crate::path::RelativePath,
    expected: Option<crate::manifest::Fingerprint>,
    force_literal: bool,
) -> Result<(u32, Vec<crate::delta::Signature>, bool)> {
    let request_id = session.allocate_request();
    session.framed.send(&Envelope {
        request_id,
        job_id,
        message: Message::SignatureRequest {
            path,
            expected,
            force_literal,
        },
    })?;
    let (block_size, declared, fallback) = match session.receive_for(request_id, job_id)? {
        Message::SignatureStreamStart {
            block_size,
            signatures,
            fallback,
        } => (block_size, signatures, fallback),
        other => {
            return Err(Error::Protocol(format!(
                "unexpected signature stream start: {other:?}"
            )));
        }
    };
    if declared.saturating_mul(40) > delta::WIRE_SIGNATURE_BUDGET as u64 {
        return Err(Error::Protocol(
            "remote signature response exceeds negotiated budget".into(),
        ));
    }
    let mut signatures = Vec::with_capacity(usize::try_from(declared).unwrap_or(0));
    loop {
        match session.receive_for(request_id, job_id)? {
            Message::SignatureChunk(chunk) => {
                if signatures.len().saturating_add(chunk.len()) > declared as usize {
                    return Err(Error::Protocol(
                        "remote signature stream exceeds declared count".into(),
                    ));
                }
                signatures.extend(chunk);
            }
            Message::StreamEnd {
                records,
                bytes,
                status: crate::protocol::StreamStatus::Ok,
            } => {
                if records != declared
                    || records != signatures.len() as u64
                    || bytes != declared.saturating_mul(40)
                {
                    return Err(Error::Protocol(
                        "remote signature stream counts do not match".into(),
                    ));
                }
                return Ok((block_size, signatures, fallback));
            }
            Message::StreamEnd {
                status: crate::protocol::StreamStatus::Failed(error),
                ..
            } => return Err(Error::entry("basis-changed", None, error)),
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected signature stream record: {other:?}"
                )));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn transfer_in(
    session: &mut RemoteSession,
    job_id: u64,
    local_root: &RootDir,
    local_manifest: &Manifest,
    entry: &crate::manifest::ManifestEntry,
    summary: &mut JobSummary,
    ownership: OwnershipPolicy,
    progress: &mut ProgressReporter,
) -> Result<()> {
    let ((), retried) = retry_basis_once(|force_literal| {
        transfer_in_attempt(
            session,
            job_id,
            local_root,
            local_manifest,
            entry,
            summary,
            ownership,
            progress,
            force_literal,
        )
    })?;
    if retried {
        summary.warnings = summary.warnings.saturating_add(1);
    }
    Ok(())
}

fn retry_basis_once<T>(mut attempt: impl FnMut(bool) -> Result<T>) -> Result<(T, bool)> {
    match attempt(false) {
        Err(Error::Entry { class, .. }) if class == "basis-changed" => {
            attempt(true).map(|value| (value, true))
        }
        result => result.map(|value| (value, false)),
    }
}

#[allow(clippy::too_many_arguments)]
fn transfer_in_attempt(
    session: &mut RemoteSession,
    job_id: u64,
    local_root: &RootDir,
    local_manifest: &Manifest,
    entry: &crate::manifest::ManifestEntry,
    summary: &mut JobSummary,
    ownership: OwnershipPolicy,
    progress: &mut ProgressReporter,
    force_literal: bool,
) -> Result<()> {
    let expected = local_manifest
        .get(&entry.path)
        .map(|entry| entry.fingerprint);
    let (mut basis, basis_length) = if force_literal {
        (crate::filesystem::BasisReader::empty(), 0)
    } else {
        match local_root.basis_reader(&entry.path, expected) {
            Ok(basis) => basis,
            Err(Error::Io { path, source }) => {
                return Err(Error::entry(
                    "basis-changed",
                    path,
                    format!("could not read the local basis: {source}"),
                ));
            }
            Err(error) => return Err(error),
        }
    };
    let mut block_size = delta::choose_block_size(basis_length, delta::WIRE_SIGNATURE_BUDGET);
    let signatures = if force_literal {
        Vec::new()
    } else {
        match delta::signatures_from_reader(&mut basis, block_size, delta::WIRE_SIGNATURE_BUDGET) {
            Ok(signatures) => signatures,
            Err(_) => {
                block_size = 4096;
                summary.warnings = summary.warnings.saturating_add(1);
                Vec::new()
            }
        }
    };
    if force_literal {
        if let Some(expected) = expected {
            local_root.validate_expected_path(&entry.path, expected)?;
        }
    } else {
        local_root.validate_basis(&entry.path, expected, &basis)?;
    }
    basis
        .seek(SeekFrom::Start(0))
        .map_err(|error| Error::io(None, error))?;
    let request_id = session.allocate_request();
    session.framed.send(&Envelope {
        request_id,
        job_id,
        message: Message::DeltaRequestStart {
            path: entry.path.clone(),
            expected_source: entry.fingerprint,
            block_size: u32::try_from(block_size)
                .map_err(|_| Error::Protocol("block size overflow".into()))?,
            signatures: signatures.len() as u64,
        },
    })?;
    send_signature_request_chunks(session, request_id, job_id, &signatures)?;
    session.framed.send(&Envelope {
        request_id,
        job_id,
        message: Message::StreamEnd {
            records: signatures.len() as u64,
            bytes: signatures.len().saturating_mul(40) as u64,
            status: crate::protocol::StreamStatus::Ok,
        },
    })?;
    match session.receive_for(request_id, job_id)? {
        Message::DeltaStart => {}
        other => {
            return Err(Error::Protocol(format!(
                "unexpected delta start: {other:?}"
            )));
        }
    }
    let proceeded = std::cell::Cell::new(false);
    let write_result = local_root.write_file_atomic_with(
        entry,
        expected,
        ownership,
        |output| {
        session.framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::DeltaProceed(true),
        })?;
        proceeded.set(true);
        fault_delay("XSYNC_TEST_CONTROLLER_APPLY_DELAY_MS");
        let mut deferred_error = None;
        let mut reconstructor = match delta::Reconstructor::new(
            &mut basis,
            basis_length,
            block_size,
            output,
            entry.size,
        ) {
            Ok(reconstructor) => Some(reconstructor),
            Err(error) => {
                deferred_error = Some(error);
                None
            }
        };
        let trailer = loop {
            match session.receive_for(request_id, job_id)? {
                Message::InstructionChunk(chunk) => {
                    if deferred_error.is_none() {
                        for instruction in &chunk {
                            if matches!(instruction, crate::delta::Instruction::Literal(bytes) if bytes.len() > session.limits.max_literal as usize)
                            {
                                deferred_error = Some(Error::Protocol(
                                    "remote literal exceeds negotiated limit".into(),
                                ));
                                break;
                            }
                            if let Some(reconstructor) = reconstructor.as_mut()
                                && let Err(error) = reconstructor.apply(instruction)
                            {
                                deferred_error = Some(error);
                                break;
                            }
                        }
                        if let Some(reconstructor) = reconstructor.as_ref() {
                            progress.entry_progress(
                                &entry.path,
                                "remote-to-local",
                                reconstructor.bytes_written(),
                                entry.size,
                                reconstructor.literal_bytes(),
                            );
                        }
                    }
                }
                Message::DeltaEnd(trailer) => break trailer,
                Message::StreamEnd {
                    status: crate::protocol::StreamStatus::Failed(error),
                    ..
                } => return Err(Error::entry("source-read", None, error)),
                other => {
                    return Err(Error::Protocol(format!(
                        "unexpected delta record: {other:?}"
                    )));
                }
            }
        };
        if let Some(error) = deferred_error {
            return Err(error);
        }
        let stats = reconstructor
            .ok_or_else(|| Error::Protocol("delta reconstructor unavailable".into()))?
            .finish(trailer)?;
        if force_literal {
            local_root.validate_expected_path(
                &entry.path,
                expected.ok_or_else(|| Error::Protocol("basis identity missing".into()))?,
            )?;
        } else {
            local_root.validate_basis(&entry.path, expected, &basis)?;
        }
        Ok((stats, trailer))
        },
    );
    let ((stats, trailer), warning) = match write_result {
        Ok(result) => result,
        Err(error) if !proceeded.get() => {
            session.framed.send(&Envelope {
                request_id,
                job_id,
                message: Message::DeltaProceed(false),
            })?;
            match session.receive_for(request_id, job_id)? {
                Message::DeltaCancelled => return Err(error),
                other => {
                    return Err(Error::Protocol(format!(
                        "unexpected delta cancellation response: {other:?}"
                    )));
                }
            }
        }
        Err(error) => return Err(error),
    };
    if let Some(warning) = warning {
        summary.warnings = summary.warnings.saturating_add(1);
        progress.warning(&entry.path, &warning);
    }
    account_transfer(summary, trailer, stats.literal_bytes);
    Ok(())
}

fn expect_apply(message: Message) -> Result<EntryResult> {
    match message {
        Message::ApplyResult(result) if result.ok => Ok(result),
        Message::ApplyResult(result) => Err(Error::entry(
            result.error_class.unwrap_or_else(|| "apply-failed".into()),
            None,
            result.error.unwrap_or_else(|| "remote apply failed".into()),
        )),
        other => Err(Error::Protocol(format!(
            "unexpected apply response: {other:?}"
        ))),
    }
}

fn account_apply(message: Message, summary: &mut JobSummary) -> Result<EntryResult> {
    let result = expect_apply(message)?;
    if result.warning.is_some() {
        summary.warnings = summary.warnings.saturating_add(1);
    }
    Ok(result)
}

fn account_transfer(summary: &mut JobSummary, trailer: crate::delta::Trailer, literal: u64) {
    summary.files += 1;
    summary.logical_bytes = summary.logical_bytes.saturating_add(trailer.length);
    summary.literal_bytes = summary.literal_bytes.saturating_add(literal);
    summary.reused_bytes = summary
        .reused_bytes
        .saturating_add(trailer.length.saturating_sub(literal));
}

fn split_literal_instruction(
    instruction: crate::delta::Instruction,
    max_literal: usize,
) -> Vec<crate::delta::Instruction> {
    match instruction {
        crate::delta::Instruction::Literal(bytes) if bytes.len() > max_literal => bytes
            .chunks(max_literal)
            .map(|chunk| crate::delta::Instruction::Literal(chunk.to_vec()))
            .collect(),
        instruction => vec![instruction],
    }
}

fn send_signature_request_chunks(
    session: &mut RemoteSession,
    request_id: u64,
    job_id: u64,
    signatures: &[crate::delta::Signature],
) -> Result<()> {
    let mut chunk = Vec::new();
    for signature in signatures {
        chunk.push(signature.clone());
        let envelope = Envelope {
            request_id,
            job_id,
            message: Message::SignatureChunk(chunk.clone()),
        };
        if crate::protocol::encoded_envelope_len(&envelope)? > session.limits.max_frame as usize {
            let last = chunk.pop().expect("just pushed signature");
            if chunk.is_empty() {
                return Err(Error::Protocol(
                    "one signature exceeds negotiated frame size".into(),
                ));
            }
            session.framed.send(&Envelope {
                request_id,
                job_id,
                message: Message::SignatureChunk(std::mem::take(&mut chunk)),
            })?;
            chunk.push(last);
        } else if chunk.len() >= crate::protocol::MAX_RECORDS_PER_FRAME {
            session.framed.send(&Envelope {
                request_id,
                job_id,
                message: Message::SignatureChunk(std::mem::take(&mut chunk)),
            })?;
        }
    }
    if !chunk.is_empty() {
        session.framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::SignatureChunk(chunk),
        })?;
    }
    Ok(())
}

fn push_instruction_record_controller(
    session: &mut RemoteSession,
    request_id: u64,
    job_id: u64,
    pending: &mut Vec<crate::delta::Instruction>,
    instruction: crate::delta::Instruction,
) -> Result<()> {
    pending.push(instruction);
    let envelope = Envelope {
        request_id,
        job_id,
        message: Message::InstructionChunk(pending.clone()),
    };
    if crate::protocol::encoded_envelope_len(&envelope)? > session.limits.max_frame as usize {
        let last = pending.pop().expect("just pushed instruction");
        if pending.is_empty() {
            return Err(Error::Protocol(
                "one delta instruction exceeds negotiated frame size".into(),
            ));
        }
        session.framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::InstructionChunk(std::mem::take(pending)),
        })?;
        pending.push(last);
    } else if pending
        .iter()
        .any(|instruction| matches!(instruction, crate::delta::Instruction::Literal(_)))
        || pending.len() >= crate::protocol::MAX_RECORDS_PER_FRAME
    {
        session.framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::InstructionChunk(std::mem::take(pending)),
        })?;
    }
    Ok(())
}

fn add_summary(total: &mut JobSummary, job: &JobSummary) {
    total.files += job.files;
    total.logical_bytes += job.logical_bytes;
    total.literal_bytes += job.literal_bytes;
    total.reused_bytes += job.reused_bytes;
    total.warnings += job.warnings;
    total.conflicts += job.conflicts;
    total.errors += job.errors;
}

fn quote_shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn wall_time_ns() -> i64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
}

fn fault_delay(variable: &str) {
    if let Some(milliseconds) = std::env::var(variable)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        std::thread::sleep(std::time::Duration::from_millis(milliseconds.min(10_000)));
    }
}

struct ProgressReporter {
    mode: ProgressMode,
    quiet: bool,
    terminal: bool,
    last_draw: Instant,
    jobs: usize,
    job_started: Instant,
    planned_entries: usize,
    completed_entries: usize,
    entry_started: Instant,
    entry_logical_bytes: u64,
}

impl ProgressReporter {
    fn new(config: &Config) -> Self {
        let now = Instant::now();
        let terminal = std::io::stderr().is_terminal();
        Self {
            mode: config.progress,
            quiet: config.quiet
                || config.progress == ProgressMode::Never
                || (config.progress == ProgressMode::Auto
                    && !terminal
                    && config.verbose == 0
                    && !config.dry_run),
            terminal,
            last_draw: now
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap_or(now),
            jobs: config.jobs.len(),
            job_started: now,
            planned_entries: 0,
            completed_entries: 0,
            entry_started: now,
            entry_logical_bytes: 0,
        }
    }

    fn session_start(&mut self, jobs: usize) {
        if self.quiet {
            return;
        }
        if self.mode == ProgressMode::Json {
            self.json(serde_json::json!({"event": "session_start", "jobs": jobs}));
        } else {
            eprintln!("xsync: starting {jobs} job(s)");
        }
    }

    fn job_start(&mut self, number: usize, job: &JobConfig) {
        self.job_started = Instant::now();
        self.planned_entries = 0;
        self.completed_entries = 0;
        if self.quiet {
            return;
        }
        if self.mode == ProgressMode::Json {
            self.json(serde_json::json!({
                "event": "job_start",
                "job": number,
                "jobs": self.jobs,
                "local": crate::path::display_absolute(&job.local),
                "remote": crate::path::display_absolute(&job.remote),
            }));
        } else {
            eprintln!(
                "xsync: job {number}/{}: {} <-> {}",
                self.jobs,
                crate::path::display_absolute(&job.local),
                crate::path::display_absolute(&job.remote)
            );
        }
    }

    fn plan_ready(&mut self, plan: &crate::planner::Plan) {
        self.planned_entries = plan.operations.len();
    }

    fn phase(&mut self, phase: &str, path: Option<&crate::path::RelativePath>) {
        if self.quiet {
            return;
        }
        if self.mode == ProgressMode::Json {
            let mut value = serde_json::json!({"event": "phase", "phase": phase});
            if let Some(path) = path {
                add_json_path(&mut value, path);
            }
            self.json(value);
        } else if !self.terminal || self.mode == ProgressMode::Always {
            eprintln!("xsync: phase: {phase}");
        }
    }

    fn conflict(&mut self, path: &crate::path::RelativePath) {
        self.path_event("conflict", path, None);
    }

    fn warning(&mut self, path: &crate::path::RelativePath, message: &str) {
        self.path_event("warning", path, Some(message));
    }

    fn entry_start(&mut self, operation: &Operation) {
        self.entry_started = Instant::now();
        self.entry_logical_bytes = 0;
        if self.quiet {
            return;
        }
        let direction = operation_direction(operation);
        if self.mode == ProgressMode::Json {
            let mut value = serde_json::json!({
                "event": "entry_start",
                "direction": direction,
                "kind": operation_kind(operation),
            });
            add_json_path(&mut value, operation.path());
            self.json(value);
        } else if !self.terminal
            || self.last_draw.elapsed() >= std::time::Duration::from_millis(100)
        {
            eprintln!("xsync: {direction} {}", operation.path());
            self.last_draw = Instant::now();
        }
    }

    fn planned_operation(&mut self, operation: &Operation) {
        if self.quiet {
            return;
        }
        let direction = operation_direction(operation);
        if self.mode == ProgressMode::Json {
            let mut value = serde_json::json!({
                "event": "planned_operation",
                "direction": direction,
                "kind": operation_kind(operation),
            });
            add_json_path(&mut value, operation.path());
            self.json(value);
        } else {
            eprintln!(
                "xsync: would {direction} {} {}",
                operation_description(operation),
                operation.path()
            );
        }
    }

    fn entry_progress(
        &mut self,
        path: &crate::path::RelativePath,
        direction: &str,
        logical_bytes: u64,
        total_bytes: u64,
        literal_bytes: u64,
    ) {
        if self.quiet {
            return;
        }
        let now = Instant::now();
        if logical_bytes < total_bytes
            && now.duration_since(self.last_draw) < std::time::Duration::from_millis(100)
        {
            return;
        }
        self.last_draw = now;
        self.entry_logical_bytes = logical_bytes;
        let elapsed = self.entry_started.elapsed().as_secs_f64().max(0.001);
        let rate = logical_bytes as f64 / elapsed;
        let eta = (rate > 0.0).then(|| total_bytes.saturating_sub(logical_bytes) as f64 / rate);
        if self.mode == ProgressMode::Json {
            let mut event = serde_json::json!({
                "event": "entry_progress",
                "direction": direction,
                "logical_bytes": logical_bytes,
                "total_bytes": total_bytes,
                "literal_bytes": literal_bytes,
                "reused_bytes": logical_bytes.saturating_sub(literal_bytes),
                "rate_bytes_per_second": rate,
                "eta_seconds": eta,
            });
            add_json_path(&mut event, path);
            self.json(event);
        } else if self.terminal {
            eprint!(
                "\r\x1b[2Kxsync: {direction} {path} {logical_bytes}/{total_bytes} bytes, {:.0} B/s{}",
                rate,
                eta.map_or_else(String::new, |seconds| format!(", ETA {seconds:.1}s"))
            );
            let _ = std::io::stderr().flush();
        } else {
            eprintln!(
                "xsync: {direction} {path} {logical_bytes}/{total_bytes} bytes, {:.0} B/s",
                rate
            );
        }
    }

    fn entry_done(&mut self, operation: &Operation, summary: &JobSummary) {
        self.completed_entries = self.completed_entries.saturating_add(1);
        if self.quiet {
            return;
        }
        let elapsed = self.entry_started.elapsed().as_secs_f64().max(0.001);
        let rate = self.entry_logical_bytes as f64 / elapsed;
        let eta = None::<f64>;
        if self.mode == ProgressMode::Json {
            let mut value = serde_json::json!({
                "event": "entry_summary",
                "direction": operation_direction(operation),
                "entries_completed": self.completed_entries,
                "entries_total": self.planned_entries,
                "logical_bytes": summary.logical_bytes,
                "literal_bytes": summary.literal_bytes,
                "reused_bytes": summary.reused_bytes,
                "rate_bytes_per_second": rate,
                "eta_seconds": eta,
            });
            add_json_path(&mut value, operation.path());
            self.json(value);
            let mut done = serde_json::json!({
                "event": "entry_done",
                "direction": operation_direction(operation),
            });
            add_json_path(&mut done, operation.path());
            self.json(done);
        } else if self.terminal {
            eprintln!(
                "xsync: {}/{} entries, {} logical bytes, {:.0} B/s{}",
                self.completed_entries,
                self.planned_entries,
                summary.logical_bytes,
                rate,
                eta.map_or_else(String::new, |seconds| format!(", ETA {seconds:.1}s"))
            );
        }
    }

    fn entry_error(&mut self, operation: &Operation, message: &str) {
        self.completed_entries = self.completed_entries.saturating_add(1);
        self.path_event("entry_error", operation.path(), Some(message));
    }

    fn job_done(&mut self, job: &JobConfig, summary: &JobSummary, operations: usize) {
        if self.quiet {
            return;
        }
        if self.mode == ProgressMode::Json {
            self.json(serde_json::json!({
                "event": "job_done",
                "local": crate::path::display_absolute(&job.local),
                "remote": crate::path::display_absolute(&job.remote),
                "operations": operations,
                "files": summary.files,
                "logical_bytes": summary.logical_bytes,
                "literal_bytes": summary.literal_bytes,
                "reused_bytes": summary.reused_bytes,
                "warnings": summary.warnings,
                "conflicts": summary.conflicts,
                "errors": summary.errors,
            }));
        } else {
            eprintln!(
                "xsync: done: {operations} operations, {} files, {} logical bytes, {} reused, {} conflicts, {} warnings, {} errors",
                summary.files,
                summary.logical_bytes,
                summary.reused_bytes,
                summary.conflicts,
                summary.warnings,
                summary.errors
            );
        }
    }

    fn job_error(&mut self, job: &JobConfig, message: &str) {
        if self.quiet {
            return;
        }
        if self.mode == ProgressMode::Json {
            self.json(serde_json::json!({
                "event": "job_error",
                "local": crate::path::display_absolute(&job.local),
                "remote": crate::path::display_absolute(&job.remote),
                "message": message,
            }));
        } else {
            eprintln!("xsync: job failed: {message}");
        }
    }

    fn session_done(&mut self, summary: &JobSummary) {
        if self.quiet {
            return;
        }
        if self.mode == ProgressMode::Json {
            self.json(serde_json::json!({
                "event": "session_done",
                "files": summary.files,
                "logical_bytes": summary.logical_bytes,
                "literal_bytes": summary.literal_bytes,
                "reused_bytes": summary.reused_bytes,
                "warnings": summary.warnings,
                "conflicts": summary.conflicts,
                "errors": summary.errors,
            }));
        } else {
            eprintln!(
                "xsync: session complete: {} files, {} bytes, {:.1}% reused",
                summary.files,
                summary.logical_bytes,
                if summary.logical_bytes == 0 {
                    0.0
                } else {
                    summary.reused_bytes as f64 * 100.0 / summary.logical_bytes as f64
                }
            );
        }
    }

    fn path_event(&mut self, event: &str, path: &crate::path::RelativePath, message: Option<&str>) {
        if self.quiet {
            return;
        }
        if self.mode == ProgressMode::Json {
            let mut value = serde_json::json!({"event": event});
            add_json_path(&mut value, path);
            if let Some(message) = message {
                value["message"] = serde_json::Value::String(message.to_owned());
            }
            self.json(value);
        } else if let Some(message) = message {
            eprintln!("xsync: {event}: {path}: {message}");
        } else {
            eprintln!("xsync: {event}: {path}");
        }
    }

    fn json(&self, mut value: serde_json::Value) {
        value["version"] = serde_json::Value::from(1);
        eprintln!("{value}");
    }
}

fn add_json_path(value: &mut serde_json::Value, path: &crate::path::RelativePath) {
    value["path"] = serde_json::Value::String(path.display_lossy());
    value["path_base64"] = serde_json::Value::String(path.base64());
}

fn operation_direction(operation: &Operation) -> &'static str {
    match operation {
        Operation::CreateDirectory {
            target: Side::Local,
            ..
        }
        | Operation::FinalizeDirectory {
            target: Side::Local,
            ..
        }
        | Operation::TransferFile {
            source: Side::Remote,
            ..
        }
        | Operation::WriteSymlink {
            source: Side::Remote,
            ..
        } => "remote-to-local",
        Operation::CreateDirectory {
            target: Side::Remote,
            ..
        }
        | Operation::FinalizeDirectory {
            target: Side::Remote,
            ..
        }
        | Operation::TransferFile {
            source: Side::Local,
            ..
        }
        | Operation::WriteSymlink {
            source: Side::Local,
            ..
        } => "local-to-remote",
    }
}

fn operation_kind(operation: &Operation) -> &'static str {
    match operation {
        Operation::CreateDirectory { .. } => "create_directory",
        Operation::TransferFile { .. } => "file",
        Operation::WriteSymlink { .. } => "symlink",
        Operation::FinalizeDirectory { .. } => "finalize_directory",
    }
}

fn operation_description(operation: &Operation) -> &'static str {
    match operation {
        Operation::CreateDirectory { .. } => "create directory",
        Operation::TransferFile { .. } => "transfer file",
        Operation::WriteSymlink { .. } => "write symlink",
        Operation::FinalizeDirectory { .. } => "finalize directory metadata",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_handles_spaces_and_quotes() {
        assert_eq!(
            quote_shell_word("/opt/my tools/x'sync"),
            "'/opt/my tools/x'\\''sync'"
        );
    }

    #[test]
    fn job_memory_budget_is_aggregate_across_retained_phases() {
        let mut budget = JobMemoryBudget { used: 0 };
        budget
            .charge(MAX_JOB_MEMORY - 100, "two manifests")
            .unwrap();
        budget.charge(50, "checksum maps").unwrap();
        assert!(budget.charge(51, "plan").is_err());
    }

    #[test]
    fn basis_retry_is_exactly_once_and_never_retries_digest_mismatch() {
        let mut calls = Vec::new();
        let (value, retried) = retry_basis_once(|literal| {
            calls.push(literal);
            if literal {
                Ok(7)
            } else {
                Err(Error::entry("basis-changed", None, "race"))
            }
        })
        .unwrap();
        assert_eq!((value, retried, calls), (7, true, vec![false, true]));

        let mut calls = 0;
        let error = retry_basis_once::<()>(|_| {
            calls += 1;
            Err(Error::entry("basis-changed", None, "persistent race"))
        })
        .unwrap_err();
        assert!(matches!(error, Error::Entry { .. }));
        assert_eq!(calls, 2);

        let mut calls = 0;
        let error = retry_basis_once::<()>(|_| {
            calls += 1;
            Err(Error::entry("digest-mismatch", None, "corrupt"))
        })
        .unwrap_err();
        assert!(matches!(error, Error::Entry { class, .. } if class == "digest-mismatch"));
        assert_eq!(calls, 1);
    }
}
