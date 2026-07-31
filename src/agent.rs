use std::{
    ffi::OsString,
    io::{Read, Write},
    os::unix::ffi::OsStringExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    Error, Result,
    delta::{self},
    exclude::Excludes,
    filesystem::{OwnershipPolicy, RootDir},
    manifest::Manifest,
    protocol::{
        DigestRecord, EntryResult, Envelope, Framed, JobSummary, Limits, Message, PROTOCOL_MAJOR,
        PROTOCOL_MINOR, WireError,
    },
};

struct JobContext {
    id: u64,
    root: Option<RootDir>,
    manifest: Option<Manifest>,
    excludes: Excludes,
    dry_run: bool,
    direction: crate::cli::Direction,
    preserve_owner: bool,
    preserve_group: bool,
    numeric_ids: bool,
    summary: JobSummary,
    state: JobState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobState {
    Accepted,
    Inventoried,
    Syncing,
    Finalizing,
}

pub fn run() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match run_io(stdin.lock(), stdout.lock()) {
        Err(Error::Transport(message))
            if message.contains("protocol stream ended")
                || message.contains("truncated protocol frame")
                || message.contains("Broken pipe") =>
        {
            // Controller cancellation is communicated by closing the pipes.
            // Receiver guards have already unwound at this point.
            Ok(())
        }
        result => result,
    }
}

pub fn run_io<R: Read, W: Write>(reader: R, writer: W) -> Result<()> {
    let mut framed = Framed::new(reader, writer);
    framed.read_magic()?;
    framed.write_magic()?;
    let hello = framed.receive()?;
    let (nonce, stamp, offered_features, limits) = match hello.message {
        Message::Hello {
            major,
            min_minor,
            max_minor,
            features,
            nonce,
            monotonic_stamp,
            limits,
            ..
        } if major == PROTOCOL_MAJOR && (min_minor..=max_minor).contains(&PROTOCOL_MINOR) => {
            (nonce, monotonic_stamp, features, limits)
        }
        Message::Hello { .. } => {
            framed.send(&Envelope {
                request_id: hello.request_id,
                job_id: 0,
                message: Message::Incompatible {
                    major: PROTOCOL_MAJOR,
                    min_minor: PROTOCOL_MINOR,
                    max_minor: PROTOCOL_MINOR,
                    reason: "no compatible protocol version".into(),
                },
            })?;
            return Ok(());
        }
        _ => return Err(Error::Protocol("first frame is not Hello".into())),
    };
    if std::env::var_os("XSYNC_TEST_AGENT_INCOMPATIBLE").is_some() {
        framed.send(&Envelope {
            request_id: hello.request_id,
            job_id: 0,
            message: Message::Incompatible {
                major: PROTOCOL_MAJOR + 1,
                min_minor: 0,
                max_minor: 0,
                reason: "injected incompatible endpoint".into(),
            },
        })?;
        return Ok(());
    }
    limits.validate()?;
    let features = offered_features & crate::protocol::SUPPORTED_FEATURES;
    let mut limits = limits.intersect(Limits::default());
    if let Some(max_frame) = std::env::var("XSYNC_TEST_AGENT_MAX_FRAME")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    {
        limits.max_frame = limits.max_frame.min(max_frame);
        limits = limits.fit_frame();
    }
    limits.validate()?;
    framed.send(&Envelope {
        request_id: hello.request_id,
        job_id: 0,
        message: Message::HelloAck {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
            features,
            nonce,
            wall_time_ns: wall_time_ns(),
            monotonic_stamp: stamp,
            limits,
        },
    })?;
    framed.set_max_frame(limits.max_frame as usize);

    let mut last_request = hello.request_id;
    let mut job: Option<JobContext> = None;
    loop {
        let envelope = match framed.receive() {
            Ok(envelope) => envelope,
            Err(Error::Transport(_)) if job.is_some() => return Ok(()),
            Err(error) => return Err(error),
        };
        if envelope.request_id <= last_request {
            return Err(Error::Protocol(
                "request IDs must increase monotonically".into(),
            ));
        }
        last_request = envelope.request_id;
        let request_id = envelope.request_id;
        let job_id = envelope.job_id;
        let may_start = matches!(&envelope.message, Message::BeginJob { .. }) && job.is_none();
        let may_end = matches!(&envelope.message, Message::EndSession) && job.is_none();
        if !may_start && !may_end && job.as_ref().map(|context| context.id) != Some(job_id) {
            send_error(
                &mut framed,
                request_id,
                job_id,
                "wrong-state",
                None,
                "message does not match the active job state",
                true,
            )?;
            return Err(Error::Protocol("agent state violation".into()));
        }
        if let Err(reason) = validate_agent_request(job.as_ref(), &envelope.message, features) {
            send_error(
                &mut framed,
                request_id,
                job_id,
                "wrong-state",
                None,
                &reason,
                true,
            )?;
            return Err(Error::Protocol(reason));
        }
        match envelope.message {
            Message::BeginJob {
                root,
                direction,
                excludes,
                dry_run,
                preserve_owner,
                preserve_group,
                numeric_ids,
            } if job.is_none() => {
                let root_path = PathBuf::from(OsString::from_vec(root));
                if !root_path.is_absolute() {
                    send_error(
                        &mut framed,
                        request_id,
                        job_id,
                        "invalid-root",
                        None,
                        "remote root must be absolute",
                        true,
                    )?;
                    continue;
                }
                let excludes = match Excludes::compile(&excludes) {
                    Ok(excludes) => excludes,
                    Err(error) => {
                        send_error(
                            &mut framed,
                            request_id,
                            job_id,
                            "invalid-exclude",
                            None,
                            &error.to_string(),
                            false,
                        )?;
                        continue;
                    }
                };
                let prepared: Result<(Option<RootDir>, Option<Manifest>)> =
                    (|| match std::fs::symlink_metadata(&root_path) {
                        Ok(metadata) if metadata.is_dir() => {
                            let root = RootDir::open(&root_path)?;
                            Ok((Some(root), None))
                        }
                        Ok(_) => Err(Error::Io {
                            path: Some(root_path.clone()),
                            source: std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "remote root is not a directory",
                            ),
                        }),
                        Err(error)
                            if error.kind() == std::io::ErrorKind::NotFound
                                && direction.permits_local_to_remote() =>
                        {
                            if dry_run {
                                Ok((None, Some(Manifest::default())))
                            } else {
                                Ok((
                                    Some(RootDir::create_and_open(&root_path)?),
                                    Some(Manifest::default()),
                                ))
                            }
                        }
                        Err(error) => Err(Error::io(Some(root_path.clone()), error)),
                    })();
                let (root, manifest) = match prepared {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let class = match &error {
                            Error::Entry { class, .. } => class.as_str(),
                            _ => "root-open",
                        };
                        send_error(
                            &mut framed,
                            request_id,
                            job_id,
                            class,
                            None,
                            &error.to_string(),
                            false,
                        )?;
                        continue;
                    }
                };
                if manifest.as_ref().is_some_and(|manifest| {
                    manifest.entries.len() > limits.max_entries as usize
                        || manifest.entries.keys().any(|path| {
                            path.as_bytes().len() > limits.max_path as usize
                                || path.depth() > limits.max_depth as usize
                        })
                }) {
                    send_error(
                        &mut framed,
                        request_id,
                        job_id,
                        "manifest-limit",
                        None,
                        "remote manifest exceeds negotiated limits",
                        false,
                    )?;
                    continue;
                }
                job = Some(JobContext {
                    id: job_id,
                    root,
                    manifest,
                    excludes,
                    dry_run,
                    direction,
                    preserve_owner,
                    preserve_group,
                    numeric_ids,
                    summary: JobSummary::default(),
                    state: JobState::Accepted,
                });
                framed.send(&Envelope {
                    request_id,
                    job_id,
                    message: Message::JobAccepted,
                })?;
            }
            Message::ManifestRequest => {
                let context = active_job(&mut job, job_id)?;
                if context.manifest.is_none() {
                    match require_root(context)?.scan(&context.excludes, limits) {
                        Ok(manifest) => context.manifest = Some(manifest),
                        Err(error) => {
                            framed.send(&Envelope {
                                request_id,
                                job_id,
                                message: Message::StreamStart {
                                    records: Some(0),
                                    bytes: Some(0),
                                },
                            })?;
                            framed.send(&Envelope {
                                request_id,
                                job_id,
                                message: Message::StreamEnd {
                                    records: 0,
                                    bytes: 0,
                                    status: crate::protocol::StreamStatus::Failed(
                                        error.to_string(),
                                    ),
                                },
                            })?;
                            continue;
                        }
                    }
                }
                let manifest = require_manifest(context)?;
                let record_count = manifest.entries.len() as u64;
                let byte_count = manifest
                    .entries
                    .values()
                    .map(|entry| entry.estimated_wire_bytes() as u64)
                    .sum();
                framed.send(&Envelope {
                    request_id,
                    job_id,
                    message: Message::StreamStart {
                        records: Some(record_count),
                        bytes: Some(byte_count),
                    },
                })?;
                send_manifest_chunks(
                    &mut framed,
                    request_id,
                    job_id,
                    manifest,
                    limits.max_frame as usize,
                )?;
                framed.send(&Envelope {
                    request_id,
                    job_id,
                    message: Message::StreamEnd {
                        records: record_count,
                        bytes: byte_count,
                        status: crate::protocol::StreamStatus::Ok,
                    },
                })?;
                context.state = JobState::Inventoried;
            }
            Message::DigestRequest(paths) => {
                let context = active_job(&mut job, job_id)?;
                let manifest = require_manifest(context)?;
                let mut records = Vec::new();
                for path in paths {
                    let result = manifest
                        .get(&path)
                        .ok_or_else(|| Error::Protocol("digest path not in manifest".into()))
                        .and_then(|entry| require_root(context)?.digest_source(entry));
                    let record = match result {
                        Ok(digest) => DigestRecord {
                            path,
                            digest: Some(digest),
                            error: None,
                        },
                        Err(error) => DigestRecord {
                            path,
                            digest: None,
                            error: Some(error.to_string()),
                        },
                    };
                    push_digest_record(
                        &mut framed,
                        request_id,
                        job_id,
                        &mut records,
                        record,
                        limits.max_frame as usize,
                    )?;
                }
                if !records.is_empty() {
                    framed.send(&Envelope {
                        request_id,
                        job_id,
                        message: Message::DigestResponse(records),
                    })?;
                }
            }
            Message::SignatureRequest {
                path,
                expected,
                force_literal,
            } => {
                let context = active_job(&mut job, job_id)?;
                context.state = JobState::Syncing;
                if !context.direction.permits_local_to_remote() {
                    return Err(Error::Protocol(
                        "signature request violates job direction".into(),
                    ));
                }
                let signature_result: Result<(usize, Vec<crate::delta::Signature>, bool)> =
                    (|| {
                        let (block_size, signatures, fallback) = if force_literal {
                            if let Some(expected) = expected {
                                require_root(context)?.validate_expected_path(&path, expected)?;
                            }
                            (4096, Vec::new(), true)
                        } else {
                            let (mut basis, basis_length) =
                                require_root(context)?.basis_reader(&path, expected)?;
                            let mut block_size = delta::choose_block_size(
                                basis_length,
                                delta::WIRE_SIGNATURE_BUDGET,
                            );
                            let result = match delta::signatures_from_reader(
                                &mut basis,
                                block_size,
                                delta::WIRE_SIGNATURE_BUDGET,
                            ) {
                                Ok(signatures) => (signatures, false),
                                Err(Error::Protocol(_)) => {
                                    block_size = 4096;
                                    (Vec::new(), true)
                                }
                                Err(error) => return Err(error),
                            };
                            require_root(context)?.validate_basis(&path, expected, &basis)?;
                            (block_size, result.0, result.1)
                        };
                        Ok((block_size, signatures, fallback))
                    })();
                let (block_size, signatures, fallback) = match signature_result {
                    Ok(response) => response,
                    Err(error) => {
                        send_error(
                            &mut framed,
                            request_id,
                            job_id,
                            "basis-changed",
                            Some(path),
                            &error.to_string(),
                            false,
                        )?;
                        continue;
                    }
                };
                framed.send(&Envelope {
                    request_id,
                    job_id,
                    message: Message::SignatureStreamStart {
                        block_size: u32::try_from(block_size)
                            .map_err(|_| Error::Protocol("block size overflow".into()))?,
                        signatures: signatures.len() as u64,
                        fallback,
                    },
                })?;
                send_signature_chunks(
                    &mut framed,
                    request_id,
                    job_id,
                    &signatures,
                    limits.max_frame as usize,
                )?;
                framed.send(&Envelope {
                    request_id,
                    job_id,
                    message: Message::StreamEnd {
                        records: signatures.len() as u64,
                        bytes: signatures.len().saturating_mul(40) as u64,
                        status: crate::protocol::StreamStatus::Ok,
                    },
                })?;
            }
            Message::ApplyStart {
                entry,
                expected_destination,
                block_size,
                literal_only,
            } => {
                let context = active_job(&mut job, job_id)?;
                context.state = JobState::Syncing;
                if !context.direction.permits_local_to_remote() {
                    framed.send(&Envelope {
                        request_id,
                        job_id,
                        message: Message::ApplyResult(EntryResult::error(
                            "apply request violates job direction",
                        )),
                    })?;
                    continue;
                }
                let result = receive_apply(
                    &mut framed,
                    request_id,
                    job_id,
                    context,
                    entry,
                    expected_destination,
                    block_size,
                    literal_only,
                    limits.max_literal,
                );
                let message = match result {
                    Ok(warning) => Message::ApplyResult(EntryResult {
                        ok: true,
                        warning,
                        error_class: None,
                        error: None,
                        fingerprint: None,
                    }),
                    Err(Error::Protocol(error)) => {
                        send_error(
                            &mut framed,
                            request_id,
                            job_id,
                            "invalid-apply-stream",
                            None,
                            &error,
                            true,
                        )?;
                        return Err(Error::Protocol(error));
                    }
                    Err(Error::Transport(error)) => return Err(Error::Transport(error)),
                    Err(error) => Message::ApplyResult(EntryResult::from_error(&error)),
                };
                framed.send(&Envelope {
                    request_id,
                    job_id,
                    message,
                })?;
            }
            Message::DeltaRequestStart {
                path,
                expected_source,
                block_size,
                signatures,
            } => {
                let received = receive_signature_chunks(
                    &mut framed,
                    request_id,
                    job_id,
                    signatures,
                    block_size,
                )?;
                let context = active_job(&mut job, job_id)?;
                context.state = JobState::Syncing;
                send_delta_stream(
                    &mut framed,
                    request_id,
                    job_id,
                    context,
                    path,
                    expected_source,
                    block_size,
                    received,
                    limits,
                )?;
            }
            Message::SymlinkSourceRequest {
                path,
                expected_source,
            } => {
                let context = active_job(&mut job, job_id)?;
                context.state = JobState::Syncing;
                if !context.direction.permits_remote_to_local() {
                    return Err(Error::Protocol(
                        "symlink source request violates job direction".into(),
                    ));
                }
                let result = require_manifest(context)?
                    .get(&path)
                    .ok_or_else(|| Error::Protocol("symlink source is not in manifest".into()))
                    .and_then(|entry| {
                        if entry.fingerprint != expected_source {
                            return Err(Error::Io {
                                path: None,
                                source: std::io::Error::other("symlink source changed"),
                            });
                        }
                        require_root(context)?.validate_symlink_source(entry)
                    });
                match result {
                    Ok(target) => framed.send(&Envelope {
                        request_id,
                        job_id,
                        message: Message::SymlinkSourceResponse { target },
                    })?,
                    Err(error) => send_error(
                        &mut framed,
                        request_id,
                        job_id,
                        "source-changed",
                        Some(path),
                        &error.to_string(),
                        false,
                    )?,
                }
            }
            Message::ApplyDirectory {
                entry,
                expected_destination,
            } => {
                let context = active_job(&mut job, job_id)?;
                context.state = JobState::Syncing;
                if !context.direction.permits_local_to_remote() {
                    return Err(Error::Protocol(
                        "directory apply violates job direction".into(),
                    ));
                }
                let result: Result<Option<crate::manifest::Fingerprint>> = if context.dry_run {
                    Ok(None)
                } else {
                    require_root(context)?
                        .create_directory(&entry, expected_destination)
                        .map(Some)
                };
                let message = match result {
                    Ok(fingerprint) => Message::ApplyResult(EntryResult {
                        ok: true,
                        warning: None,
                        error_class: None,
                        error: None,
                        fingerprint,
                    }),
                    Err(error) => Message::ApplyResult(EntryResult::from_error(&error)),
                };
                framed.send(&Envelope {
                    request_id,
                    job_id,
                    message,
                })?;
            }
            Message::ApplySymlink {
                entry,
                expected_destination,
            } => {
                let context = active_job(&mut job, job_id)?;
                context.state = JobState::Syncing;
                if !context.direction.permits_local_to_remote() {
                    return Err(Error::Protocol(
                        "symlink apply violates job direction".into(),
                    ));
                }
                let ownership = ownership_policy(context);
                let result = if context.dry_run {
                    Ok(None)
                } else {
                    require_root(context)?.write_symlink_atomic_with_policy(
                        &entry,
                        expected_destination,
                        ownership,
                    )
                };
                framed.send(&Envelope {
                    request_id,
                    job_id,
                    message: Message::ApplyResult(to_entry_result(result)),
                })?;
            }
            Message::FinalizeDirectory {
                entry,
                expected_destination,
            } => {
                let context = active_job(&mut job, job_id)?;
                context.state = JobState::Finalizing;
                if !context.direction.permits_local_to_remote() {
                    return Err(Error::Protocol(
                        "directory finalization violates job direction".into(),
                    ));
                }
                let ownership = ownership_policy(context);
                let result = if context.dry_run {
                    Ok(None)
                } else {
                    require_root(context)?.finalize_directory(
                        &entry,
                        expected_destination,
                        ownership,
                    )
                };
                framed.send(&Envelope {
                    request_id,
                    job_id,
                    message: Message::ApplyResult(to_entry_result(result)),
                })?;
            }
            Message::FinishJob => {
                let context = active_job(&mut job, job_id)?;
                let summary = context.summary.clone();
                framed.send(&Envelope {
                    request_id,
                    job_id,
                    message: Message::JobResult(summary),
                })?;
                job = None;
            }
            Message::AbortJob { .. }
                if job.as_ref().is_some_and(|context| context.id == job_id) =>
            {
                job = None;
                framed.send(&Envelope {
                    request_id,
                    job_id,
                    message: Message::JobAborted,
                })?;
            }
            Message::EndSession if job.is_none() => {
                framed.send(&Envelope {
                    request_id,
                    job_id: 0,
                    message: Message::Goodbye(JobSummary::default()),
                })?;
                return Ok(());
            }
            _ => {
                send_error(
                    &mut framed,
                    request_id,
                    job_id,
                    "wrong-state",
                    None,
                    "message is invalid in current agent state",
                    true,
                )?;
                return Err(Error::Protocol("agent state violation".into()));
            }
        }
    }
}

fn validate_agent_request(
    job: Option<&JobContext>,
    message: &Message,
    features: u64,
) -> std::result::Result<(), String> {
    use crate::protocol::{FEATURE_CHECKSUM, FEATURE_DELTA, FEATURE_OWNERSHIP};

    let state = job.map(|context| context.state);
    match message {
        Message::BeginJob {
            preserve_owner,
            preserve_group,
            ..
        } => {
            if job.is_some() {
                return Err("cannot begin a job while another job is active".into());
            }
            if (*preserve_owner || *preserve_group) && features & FEATURE_OWNERSHIP == 0 {
                return Err("job requests unnegotiated ownership support".into());
            }
        }
        Message::EndSession if job.is_none() => {}
        Message::ManifestRequest if state == Some(JobState::Accepted) => {}
        Message::DigestRequest(_) if state == Some(JobState::Inventoried) => {
            if features & FEATURE_CHECKSUM == 0 {
                return Err("digest request uses an unnegotiated feature".into());
            }
        }
        Message::SignatureRequest { .. }
        | Message::ApplyStart { .. }
        | Message::DeltaRequestStart { .. }
            if matches!(state, Some(JobState::Inventoried | JobState::Syncing)) =>
        {
            if features & FEATURE_DELTA == 0 {
                return Err("file transfer uses an unnegotiated delta feature".into());
            }
        }
        Message::SymlinkSourceRequest { .. }
        | Message::ApplyDirectory { .. }
        | Message::ApplySymlink { .. }
            if matches!(state, Some(JobState::Inventoried | JobState::Syncing)) => {}
        Message::FinalizeDirectory { .. }
            if matches!(
                state,
                Some(JobState::Inventoried | JobState::Syncing | JobState::Finalizing)
            ) => {}
        Message::FinishJob
            if matches!(
                state,
                Some(JobState::Inventoried | JobState::Syncing | JobState::Finalizing)
            ) => {}
        Message::AbortJob { .. } if job.is_some() => {}
        _ => return Err(format!("message is invalid in agent state {state:?}")),
    }
    Ok(())
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

fn fits_frame(envelope: &Envelope, max_frame: usize) -> Result<bool> {
    Ok(crate::protocol::encoded_envelope_len(envelope)? <= max_frame)
}

fn send_manifest_chunks<R: Read, W: Write>(
    framed: &mut Framed<R, W>,
    request_id: u64,
    job_id: u64,
    manifest: &Manifest,
    max_frame: usize,
) -> Result<()> {
    let mut chunk = Vec::new();
    for entry in manifest.entries.values() {
        chunk.push(entry.clone());
        let envelope = Envelope {
            request_id,
            job_id,
            message: Message::ManifestChunk(chunk.clone()),
        };
        if !fits_frame(&envelope, max_frame)? {
            let last = chunk.pop().expect("just pushed manifest entry");
            if chunk.is_empty() {
                return Err(Error::Protocol(
                    "one manifest entry exceeds negotiated frame size".into(),
                ));
            }
            framed.send(&Envelope {
                request_id,
                job_id,
                message: Message::ManifestChunk(std::mem::take(&mut chunk)),
            })?;
            chunk.push(last);
        } else if chunk.len() >= crate::protocol::MAX_RECORDS_PER_FRAME {
            framed.send(&Envelope {
                request_id,
                job_id,
                message: Message::ManifestChunk(std::mem::take(&mut chunk)),
            })?;
        }
    }
    if !chunk.is_empty() {
        framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::ManifestChunk(chunk),
        })?;
    }
    Ok(())
}

fn push_digest_record<R: Read, W: Write>(
    framed: &mut Framed<R, W>,
    request_id: u64,
    job_id: u64,
    records: &mut Vec<DigestRecord>,
    record: DigestRecord,
    max_frame: usize,
) -> Result<()> {
    records.push(record);
    let envelope = Envelope {
        request_id,
        job_id,
        message: Message::DigestResponse(records.clone()),
    };
    if !fits_frame(&envelope, max_frame)? {
        let last = records.pop().expect("just pushed digest record");
        if records.is_empty() {
            return Err(Error::Protocol(
                "one digest record exceeds negotiated frame size".into(),
            ));
        }
        framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::DigestResponse(std::mem::take(records)),
        })?;
        records.push(last);
    } else if records.len() >= crate::protocol::MAX_RECORDS_PER_FRAME {
        framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::DigestResponse(std::mem::take(records)),
        })?;
    }
    Ok(())
}

fn send_signature_chunks<R: Read, W: Write>(
    framed: &mut Framed<R, W>,
    request_id: u64,
    job_id: u64,
    signatures: &[crate::delta::Signature],
    max_frame: usize,
) -> Result<()> {
    let mut chunk = Vec::new();
    for signature in signatures {
        chunk.push(signature.clone());
        let envelope = Envelope {
            request_id,
            job_id,
            message: Message::SignatureChunk(chunk.clone()),
        };
        if !fits_frame(&envelope, max_frame)? {
            let last = chunk.pop().expect("just pushed signature");
            if chunk.is_empty() {
                return Err(Error::Protocol(
                    "one signature exceeds negotiated frame size".into(),
                ));
            }
            framed.send(&Envelope {
                request_id,
                job_id,
                message: Message::SignatureChunk(std::mem::take(&mut chunk)),
            })?;
            chunk.push(last);
        } else if chunk.len() >= crate::protocol::MAX_RECORDS_PER_FRAME {
            framed.send(&Envelope {
                request_id,
                job_id,
                message: Message::SignatureChunk(std::mem::take(&mut chunk)),
            })?;
        }
    }
    if !chunk.is_empty() {
        framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::SignatureChunk(chunk),
        })?;
    }
    Ok(())
}

fn receive_signature_chunks<R: Read, W: Write>(
    framed: &mut Framed<R, W>,
    request_id: u64,
    job_id: u64,
    declared: u64,
    block_size: u32,
) -> Result<Vec<crate::delta::Signature>> {
    if declared.saturating_mul(40) > delta::WIRE_SIGNATURE_BUDGET as u64 {
        return Err(Error::Protocol(
            "basis signature stream exceeds budget".into(),
        ));
    }
    let mut signatures = Vec::with_capacity(usize::try_from(declared).unwrap_or(0));
    loop {
        let envelope = framed.receive()?;
        if envelope.request_id != request_id || envelope.job_id != job_id {
            return Err(Error::Protocol("interleaved signature stream".into()));
        }
        match envelope.message {
            Message::SignatureChunk(chunk) => {
                if signatures.len().saturating_add(chunk.len()) > declared as usize
                    || chunk
                        .iter()
                        .any(|signature| signature.length == 0 || signature.length > block_size)
                {
                    return Err(Error::Protocol("invalid signature stream chunk".into()));
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
                        "signature request stream counts do not match".into(),
                    ));
                }
                return Ok(signatures);
            }
            _ => return Err(Error::Protocol("invalid signature stream record".into())),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send_delta_stream<R: Read, W: Write>(
    framed: &mut Framed<R, W>,
    request_id: u64,
    job_id: u64,
    context: &mut JobContext,
    path: crate::path::RelativePath,
    expected_source: crate::manifest::Fingerprint,
    block_size: u32,
    signatures: Vec<crate::delta::Signature>,
    limits: Limits,
) -> Result<()> {
    if !context.direction.permits_remote_to_local() {
        return Err(Error::Protocol(
            "delta request violates job direction".into(),
        ));
    }
    let entry = require_manifest(context)?
        .get(&path)
        .ok_or_else(|| Error::Protocol("delta source not in manifest".into()))?
        .clone();
    if entry.fingerprint != expected_source {
        send_error(
            framed,
            request_id,
            job_id,
            "source-changed",
            Some(path),
            "source fingerprint changed",
            false,
        )?;
        return Ok(());
    }
    if signatures.len().saturating_mul(40) > delta::WIRE_SIGNATURE_BUDGET {
        send_error(
            framed,
            request_id,
            job_id,
            "signature-limit",
            Some(path),
            "basis signature budget exceeded",
            false,
        )?;
        return Ok(());
    }
    let mut source = match require_root(context)?.source_file(&entry) {
        Ok(source) => source,
        Err(error) => {
            send_error(
                framed,
                request_id,
                job_id,
                "source-changed",
                Some(path),
                &error.to_string(),
                false,
            )?;
            return Ok(());
        }
    };
    framed.send(&Envelope {
        request_id,
        job_id,
        message: Message::DeltaStart,
    })?;
    let proceed = framed.receive()?;
    if proceed.request_id != request_id || proceed.job_id != job_id {
        return Err(Error::Protocol("interleaved delta control".into()));
    }
    match proceed.message {
        Message::DeltaProceed(true) => {}
        Message::DeltaProceed(false) => {
            framed.send(&Envelope {
                request_id,
                job_id,
                message: Message::DeltaCancelled,
            })?;
            return Ok(());
        }
        _ => return Err(Error::Protocol("invalid delta control message".into())),
    }
    let mut pending = Vec::new();
    let literal_limit =
        (limits.max_literal as usize).min((limits.max_frame as usize).saturating_sub(256).max(1));
    let generated = delta::generate_stream(
        &mut source,
        &signatures,
        block_size as usize,
        |instruction| {
            for instruction in split_literal_instruction(instruction, literal_limit) {
                push_instruction_record(
                    framed,
                    request_id,
                    job_id,
                    &mut pending,
                    instruction,
                    limits.max_frame as usize,
                )?;
            }
            Ok(())
        },
    );
    let trailer = match generated {
        Ok(trailer) => trailer,
        Err(error) => {
            framed.send(&Envelope {
                request_id,
                job_id,
                message: Message::StreamEnd {
                    records: 0,
                    bytes: 0,
                    status: crate::protocol::StreamStatus::Failed(error.to_string()),
                },
            })?;
            return Ok(());
        }
    };
    if !pending.is_empty() {
        framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::InstructionChunk(pending),
        })?;
    }
    if let Err(error) = require_root(context)?.validate_source(&entry, &source) {
        framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::StreamEnd {
                records: 0,
                bytes: 0,
                status: crate::protocol::StreamStatus::Failed(error.to_string()),
            },
        })?;
        return Ok(());
    }
    framed.send(&Envelope {
        request_id,
        job_id,
        message: Message::DeltaEnd(trailer),
    })?;
    Ok(())
}

fn push_instruction_record<R: Read, W: Write>(
    framed: &mut Framed<R, W>,
    request_id: u64,
    job_id: u64,
    pending: &mut Vec<crate::delta::Instruction>,
    instruction: crate::delta::Instruction,
    max_frame: usize,
) -> Result<()> {
    pending.push(instruction);
    let envelope = Envelope {
        request_id,
        job_id,
        message: Message::InstructionChunk(pending.clone()),
    };
    if !fits_frame(&envelope, max_frame)? {
        let last = pending.pop().expect("just pushed instruction");
        if pending.is_empty() {
            return Err(Error::Protocol(
                "one delta instruction exceeds negotiated frame size".into(),
            ));
        }
        framed.send(&Envelope {
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
        framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::InstructionChunk(std::mem::take(pending)),
        })?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn receive_apply<R: Read, W: Write>(
    framed: &mut Framed<R, W>,
    request_id: u64,
    job_id: u64,
    context: &mut JobContext,
    entry: crate::manifest::ManifestEntry,
    expected: Option<crate::manifest::Fingerprint>,
    block_size: u32,
    literal_only: bool,
    max_literal: u32,
) -> Result<Option<String>> {
    let (mut basis, basis_length) = if literal_only {
        (crate::filesystem::BasisReader::empty(), 0)
    } else {
        match require_root(context).and_then(|root| root.basis_reader(&entry.path, expected)) {
            Ok(basis) => basis,
            Err(error) => {
                return Err(error);
            }
        }
    };
    let root = require_root(context)?;
    let ownership = ownership_policy(context);
    let ((stats, trailer), warning) = root.write_file_atomic_with(
        &entry,
        expected,
        ownership,
        |output| {
        let mut reconstructor = delta::Reconstructor::new(
            &mut basis,
            basis_length,
            block_size as usize,
            output,
            entry.size,
        )?;
        framed.send(&Envelope {
            request_id,
            job_id,
            message: Message::ApplyReady,
        })?;
        fault_delay("XSYNC_TEST_AGENT_APPLY_DELAY_MS");
        let mut deferred_error = None;
        let mut delayed_after_data = false;
        let trailer = loop {
            let envelope = framed.receive()?;
            if envelope.request_id != request_id || envelope.job_id != job_id {
                return Err(Error::Protocol("interleaved apply stream".into()));
            }
            match envelope.message {
                Message::InstructionChunk(chunk) => {
                    if deferred_error.is_none() {
                        for instruction in &chunk {
                            if matches!(instruction, crate::delta::Instruction::Literal(bytes) if bytes.len() > max_literal as usize)
                            {
                                deferred_error = Some(Error::Protocol(
                                    "literal exceeds negotiated limit".into(),
                                ));
                                break;
                            }
                            if let Err(error) = reconstructor.apply(instruction) {
                                deferred_error = Some(error);
                                break;
                            }
                        }
                        if !delayed_after_data && reconstructor.bytes_written() != 0 {
                            delayed_after_data = true;
                            fault_delay("XSYNC_TEST_AGENT_AFTER_DATA_DELAY_MS");
                        }
                    }
                }
                Message::ApplyEnd(trailer) => break trailer,
                _ => {
                    deferred_error = Some(Error::Protocol("invalid apply stream record".into()));
                }
            }
        };
        if let Some(error) = deferred_error {
            return Err(error);
        }
        let stats = reconstructor.finish(trailer)?;
        if literal_only {
            if let Some(expected) = expected {
                root.validate_expected_path(&entry.path, expected)?;
            }
        } else {
            root.validate_basis(&entry.path, expected, &basis)?;
        }
        Ok((stats, trailer))
        },
    )?;
    context.summary.files += 1;
    context.summary.logical_bytes = context.summary.logical_bytes.saturating_add(trailer.length);
    context.summary.literal_bytes = context
        .summary
        .literal_bytes
        .saturating_add(stats.literal_bytes);
    context.summary.reused_bytes = context
        .summary
        .reused_bytes
        .saturating_add(trailer.length.saturating_sub(stats.literal_bytes));
    Ok(warning)
}

fn active_job(job: &mut Option<JobContext>, job_id: u64) -> Result<&mut JobContext> {
    job.as_mut()
        .filter(|context| context.id == job_id)
        .ok_or_else(|| Error::Protocol("message does not match active job".into()))
}

fn require_root(context: &JobContext) -> Result<&RootDir> {
    context
        .root
        .as_ref()
        .ok_or_else(|| Error::Protocol("dry-run virtual root cannot perform I/O".into()))
}

fn require_manifest(context: &JobContext) -> Result<&Manifest> {
    context
        .manifest
        .as_ref()
        .ok_or_else(|| Error::Protocol("remote inventory has not completed".into()))
}

const fn ownership_policy(context: &JobContext) -> OwnershipPolicy {
    OwnershipPolicy {
        owner: context.preserve_owner,
        group: context.preserve_group,
        numeric_ids: context.numeric_ids,
    }
}

fn to_entry_result(result: Result<Option<String>>) -> EntryResult {
    match result {
        Ok(warning) => EntryResult {
            ok: true,
            warning,
            error_class: None,
            error: None,
            fingerprint: None,
        },
        Err(error) => EntryResult::from_error(&error),
    }
}

fn send_error<R: Read, W: Write>(
    framed: &mut Framed<R, W>,
    request_id: u64,
    job_id: u64,
    class: &str,
    path: Option<crate::path::RelativePath>,
    message: &str,
    fatal: bool,
) -> Result<()> {
    let mut budget = message.len().min(framed.max_frame());
    loop {
        let diagnostic = crate::protocol::truncate_diagnostic(message, budget);
        let envelope = Envelope {
            request_id,
            job_id,
            message: Message::Error(WireError {
                class: class.into(),
                path: path.clone(),
                message: diagnostic,
                fatal,
            }),
        };
        let encoded = crate::protocol::encoded_envelope_len(&envelope)?;
        if encoded <= framed.max_frame() {
            return framed.send(&envelope);
        }
        if budget == 0 {
            return Err(Error::Protocol(
                "negotiated frame cannot encode an empty error diagnostic".into(),
            ));
        }
        budget = budget.saturating_sub((encoded - framed.max_frame()).max(1));
    }
}

fn wall_time_ns() -> i64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let now = i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX);
    // Deterministic fault injection for the fake-SSH acceptance suite. This
    // changes only the advertised handshake clock and grants no authority.
    let offset = std::env::var("XSYNC_TEST_AGENT_CLOCK_OFFSET_NS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    now.saturating_add(offset)
}

fn fault_delay(variable: &str) {
    if let Some(milliseconds) = std::env::var(variable)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        std::thread::sleep(std::time::Duration::from_millis(milliseconds.min(10_000)));
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::protocol::{MAGIC, SUPPORTED_FEATURES};

    fn encoded_client(messages: Vec<Envelope>) -> Vec<u8> {
        let mut framed = Framed::new(Cursor::new(Vec::<u8>::new()), Vec::new());
        framed.write_magic().unwrap();
        for message in messages {
            framed.send(&message).unwrap();
        }
        framed.into_inner().1
    }

    fn context(state: JobState) -> JobContext {
        JobContext {
            id: 1,
            root: None,
            manifest: Some(Manifest::default()),
            excludes: Excludes::default(),
            dry_run: true,
            direction: crate::cli::Direction::InOut,
            preserve_owner: false,
            preserve_group: false,
            numeric_ids: false,
            summary: JobSummary::default(),
            state,
        }
    }

    #[test]
    fn incompatible_major_returns_a_structured_response() {
        let hello = Envelope {
            request_id: 1,
            job_id: 0,
            message: Message::Hello {
                major: PROTOCOL_MAJOR + 1,
                min_minor: 0,
                max_minor: 0,
                implementation: "test".into(),
                features: SUPPORTED_FEATURES,
                nonce: [7; 16],
                wall_time_ns: 0,
                monotonic_stamp: 1,
                limits: Limits::default(),
            },
        };
        let input = encoded_client(vec![hello]);
        let mut output = Vec::new();
        run_io(Cursor::new(input), &mut output).unwrap();
        assert_eq!(&output[..MAGIC.len()], MAGIC);
        let mut framed = Framed::new(Cursor::new(&output[MAGIC.len()..]), Vec::new());
        assert!(matches!(
            framed.receive().unwrap().message,
            Message::Incompatible { .. }
        ));
    }

    #[test]
    fn wrong_state_after_handshake_is_fatal_and_structured() {
        let hello = Envelope {
            request_id: 1,
            job_id: 0,
            message: Message::Hello {
                major: PROTOCOL_MAJOR,
                min_minor: PROTOCOL_MINOR,
                max_minor: PROTOCOL_MINOR,
                implementation: "test".into(),
                features: SUPPORTED_FEATURES,
                nonce: [3; 16],
                wall_time_ns: 0,
                monotonic_stamp: 1,
                limits: Limits::default(),
            },
        };
        let invalid = Envelope {
            request_id: 2,
            job_id: 99,
            message: Message::JobAccepted,
        };
        let input = encoded_client(vec![hello, invalid]);
        let mut output = Vec::new();
        assert!(run_io(Cursor::new(input), &mut output).is_err());
        let mut framed = Framed::new(Cursor::new(&output[MAGIC.len()..]), Vec::new());
        assert!(matches!(
            framed.receive().unwrap().message,
            Message::HelloAck { .. }
        ));
        assert!(matches!(
            framed.receive().unwrap().message,
            Message::Error(WireError { fatal: true, .. })
        ));
    }

    #[test]
    fn explicit_job_state_and_feature_matrix_is_enforced() {
        let accepted = context(JobState::Accepted);
        assert!(
            validate_agent_request(
                Some(&accepted),
                &Message::ManifestRequest,
                SUPPORTED_FEATURES
            )
            .is_ok()
        );
        assert!(
            validate_agent_request(Some(&accepted), &Message::FinishJob, SUPPORTED_FEATURES)
                .is_err()
        );
        let inventoried = context(JobState::Inventoried);
        assert!(
            validate_agent_request(
                Some(&inventoried),
                &Message::ManifestRequest,
                SUPPORTED_FEATURES
            )
            .is_err()
        );
        assert!(
            validate_agent_request(Some(&inventoried), &Message::DigestRequest(Vec::new()), 0)
                .is_err()
        );
        assert!(
            validate_agent_request(
                Some(&inventoried),
                &Message::DigestRequest(Vec::new()),
                crate::protocol::FEATURE_CHECKSUM
            )
            .is_ok()
        );
        let finalizing = context(JobState::Finalizing);
        assert!(
            validate_agent_request(
                Some(&finalizing),
                &Message::SignatureRequest {
                    path: crate::path::RelativePath::root(),
                    expected: None,
                    force_literal: true,
                },
                SUPPORTED_FEATURES,
            )
            .is_err()
        );
    }
}
