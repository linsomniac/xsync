use std::io::{Read, Write};

use ciborium::value::Value;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    cli::Direction,
    delta::{Instruction, Signature, Trailer},
    manifest::{Fingerprint, ManifestEntry},
    path::RelativePath,
};

pub const MAGIC: &[u8; 8] = b"XSYNC\0\r\n";
pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_RECORDS_PER_FRAME: usize = 256;
pub const MAX_TRANSFER_MEMORY: u64 = 512 * 1024 * 1024;
pub const FEATURE_DELTA: u64 = 1 << 0;
pub const FEATURE_CHECKSUM: u64 = 1 << 1;
pub const FEATURE_OWNERSHIP: u64 = 1 << 2;
pub const SUPPORTED_FEATURES: u64 = FEATURE_DELTA | FEATURE_CHECKSUM | FEATURE_OWNERSHIP;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    pub max_frame: u32,
    pub max_literal: u32,
    pub max_entries: u64,
    pub max_path: u32,
    pub max_depth: u16,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame: MAX_FRAME_SIZE as u32,
            max_literal: 1024 * 1024,
            max_entries: 1_000_000,
            max_path: 8 * 1024,
            max_depth: 256,
        }
    }
}

impl Limits {
    pub fn validate(self) -> Result<()> {
        if self.max_frame < 2048
            || self.max_frame as usize > MAX_FRAME_SIZE
            || self.max_literal == 0
            || self.max_literal > self.max_frame.saturating_sub(256).max(1)
            || self.max_entries == 0
            || self.max_path == 0
            || self.max_path as usize > crate::path::MAX_RELATIVE_PATH_BYTES
            || self.max_path > (self.max_frame.saturating_sub(1024) / 4).max(1)
            || self.max_depth == 0
            || self.max_depth as usize > crate::path::MAX_DEPTH
        {
            return Err(Error::Protocol("invalid negotiated resource limits".into()));
        }
        Ok(())
    }

    #[must_use]
    pub fn intersect(self, other: Self) -> Self {
        Self {
            max_frame: self.max_frame.min(other.max_frame),
            max_literal: self.max_literal.min(other.max_literal),
            max_entries: self.max_entries.min(other.max_entries),
            max_path: self.max_path.min(other.max_path),
            max_depth: self.max_depth.min(other.max_depth),
        }
        .fit_frame()
    }

    #[must_use]
    pub fn fit_frame(mut self) -> Self {
        self.max_literal = self
            .max_literal
            .min(self.max_frame.saturating_sub(256).max(1));
        // A manifest/apply record also carries two optional ownership names,
        // metadata, fingerprints, and envelope overhead. Reserving three
        // quarters of a small frame keeps every legal path encodable.
        self.max_path = self
            .max_path
            .min((self.max_frame.saturating_sub(1024) / 4).max(1));
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub request_id: u64,
    pub job_id: u64,
    pub message: Message,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Message {
    Hello {
        major: u16,
        min_minor: u16,
        max_minor: u16,
        implementation: String,
        features: u64,
        nonce: [u8; 16],
        wall_time_ns: i64,
        monotonic_stamp: u64,
        limits: Limits,
    },
    HelloAck {
        major: u16,
        minor: u16,
        features: u64,
        nonce: [u8; 16],
        wall_time_ns: i64,
        monotonic_stamp: u64,
        limits: Limits,
    },
    Incompatible {
        major: u16,
        min_minor: u16,
        max_minor: u16,
        reason: String,
    },
    BeginJob {
        #[serde(with = "serde_bytes")]
        root: Vec<u8>,
        direction: Direction,
        excludes: Vec<String>,
        dry_run: bool,
        preserve_owner: bool,
        preserve_group: bool,
        numeric_ids: bool,
    },
    JobAccepted,
    ManifestRequest,
    ManifestChunk(Vec<ManifestEntry>),
    DigestRequest(Vec<RelativePath>),
    DigestResponse(Vec<DigestRecord>),
    SignatureRequest {
        path: RelativePath,
        expected: Option<Fingerprint>,
        force_literal: bool,
    },
    SignatureStreamStart {
        block_size: u32,
        signatures: u64,
        fallback: bool,
    },
    SignatureChunk(Vec<Signature>),
    ApplyStart {
        entry: ManifestEntry,
        expected_destination: Option<Fingerprint>,
        block_size: u32,
        literal_only: bool,
    },
    InstructionChunk(Vec<Instruction>),
    ApplyEnd(Trailer),
    ApplyResult(EntryResult),
    ApplyReady,
    DeltaRequestStart {
        path: RelativePath,
        expected_source: Fingerprint,
        block_size: u32,
        signatures: u64,
    },
    DeltaStart,
    DeltaEnd(Trailer),
    DeltaProceed(bool),
    DeltaCancelled,
    SymlinkSourceRequest {
        path: RelativePath,
        expected_source: Fingerprint,
    },
    SymlinkSourceResponse {
        #[serde(with = "serde_bytes")]
        target: Vec<u8>,
    },
    ApplyDirectory {
        entry: ManifestEntry,
        expected_destination: Option<Fingerprint>,
    },
    ApplySymlink {
        entry: ManifestEntry,
        expected_destination: Option<Fingerprint>,
    },
    FinalizeDirectory {
        entry: ManifestEntry,
        expected_destination: Fingerprint,
    },
    FinishJob,
    JobResult(JobSummary),
    AbortJob {
        reason: String,
    },
    JobAborted,
    EndSession,
    Goodbye(JobSummary),
    StreamStart {
        records: Option<u64>,
        bytes: Option<u64>,
    },
    StreamEnd {
        records: u64,
        bytes: u64,
        status: StreamStatus,
    },
    Error(WireError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DigestRecord {
    pub path: RelativePath,
    pub digest: Option<[u8; 32]>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobSummary {
    pub files: u64,
    pub logical_bytes: u64,
    pub literal_bytes: u64,
    pub reused_bytes: u64,
    pub warnings: u64,
    pub conflicts: u64,
    pub errors: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntryResult {
    pub ok: bool,
    pub warning: Option<String>,
    pub error_class: Option<String>,
    pub error: Option<String>,
    pub fingerprint: Option<Fingerprint>,
}

impl EntryResult {
    #[must_use]
    pub const fn ok() -> Self {
        Self {
            ok: true,
            warning: None,
            error_class: None,
            error: None,
            fingerprint: None,
        }
    }

    #[must_use]
    pub fn error(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            warning: None,
            error_class: Some("entry-failed".into()),
            error: Some(error.into()),
            fingerprint: None,
        }
    }

    #[must_use]
    pub fn from_error(error: &Error) -> Self {
        let class = match error {
            Error::Entry { class, .. } => class.clone(),
            Error::Io { .. } => "io".into(),
            Error::Protocol(_) => "protocol".into(),
            Error::Transport(_) => "transport".into(),
            Error::Usage(_) => "usage".into(),
            Error::Partial => "partial".into(),
            Error::Interrupted => "interrupted".into(),
        };
        Self {
            ok: false,
            warning: None,
            error_class: Some(class),
            error: Some(error.to_string()),
            fingerprint: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WireError {
    pub class: String,
    pub path: Option<RelativePath>,
    pub message: String,
    pub fatal: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StreamStatus {
    Ok,
    Failed(String),
}

pub struct Framed<R, W> {
    reader: R,
    writer: W,
    max_frame: usize,
}

impl<R: Read, W: Write> Framed<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            max_frame: MAX_FRAME_SIZE,
        }
    }

    pub fn with_max_frame(reader: R, writer: W, max_frame: usize) -> Self {
        Self {
            reader,
            writer,
            max_frame: max_frame.min(MAX_FRAME_SIZE),
        }
    }

    pub fn set_max_frame(&mut self, max_frame: usize) {
        self.max_frame = max_frame.min(MAX_FRAME_SIZE);
    }

    #[must_use]
    pub const fn max_frame(&self) -> usize {
        self.max_frame
    }

    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    pub fn write_magic(&mut self) -> Result<()> {
        self.writer
            .write_all(MAGIC)
            .map_err(|e| Error::Transport(format!("could not write protocol magic: {e}")))?;
        self.writer
            .flush()
            .map_err(|e| Error::Transport(format!("could not flush protocol magic: {e}")))?;
        Ok(())
    }

    pub fn read_magic(&mut self) -> Result<()> {
        let mut actual = [0u8; 8];
        self.reader
            .read_exact(&mut actual)
            .map_err(|e| Error::Transport(format!("could not read protocol magic: {e}")))?;
        if &actual != MAGIC {
            return Err(Error::Protocol(format!(
                "remote shell wrote to protocol stdout (leading bytes {})",
                escaped_preview(&actual)
            )));
        }
        Ok(())
    }

    pub fn send(&mut self, envelope: &Envelope) -> Result<()> {
        let mut payload = Vec::new();
        ciborium::into_writer(&encode_envelope(envelope)?, &mut payload)
            .map_err(|e| Error::Protocol(format!("could not encode protocol frame: {e}")))?;
        if payload.len() > self.max_frame {
            return Err(Error::Protocol(format!(
                "outgoing frame exceeds {} bytes",
                self.max_frame
            )));
        }
        let length = u32::try_from(payload.len())
            .map_err(|_| Error::Protocol("frame length overflow".into()))?;
        self.writer
            .write_all(&length.to_be_bytes())
            .map_err(|e| Error::Transport(format!("could not write protocol frame: {e}")))?;
        self.writer
            .write_all(&payload)
            .map_err(|e| Error::Transport(format!("could not write protocol frame: {e}")))?;
        self.writer
            .flush()
            .map_err(|e| Error::Transport(format!("could not flush protocol frame: {e}")))?;
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Envelope> {
        let mut length = [0u8; 4];
        self.reader
            .read_exact(&mut length)
            .map_err(|e| Error::Transport(format!("protocol stream ended: {e}")))?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > self.max_frame {
            return Err(Error::Protocol(format!("invalid frame length {length}")));
        }
        let mut payload = vec![0u8; length];
        self.reader
            .read_exact(&mut payload)
            .map_err(|e| Error::Transport(format!("truncated protocol frame: {e}")))?;
        let value: Value = ciborium::from_reader(payload.as_slice())
            .map_err(|e| Error::Protocol(format!("could not decode protocol frame: {e}")))?;
        decode_envelope(value)
    }

    pub fn into_inner(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

fn encode_envelope(envelope: &Envelope) -> Result<Value> {
    let (kind, payload) = encode_message(&envelope.message)?;
    Ok(integer_map([
        (0, Value::from(kind)),
        (1, Value::from(envelope.request_id)),
        (2, Value::from(envelope.job_id)),
        (3, payload),
    ]))
}

fn decode_envelope(value: Value) -> Result<Envelope> {
    let mut fields = Fields::new(value, "envelope")?;
    let kind = fields.take(0)?;
    let request_id = fields.take(1)?;
    let job_id = fields.take(2)?;
    let payload = fields.take_value(3)?;
    fields.finish("envelope")?;
    Ok(Envelope {
        request_id,
        job_id,
        message: decode_message(kind, payload)?,
    })
}

#[allow(clippy::too_many_lines)]
fn encode_message(message: &Message) -> Result<(u16, Value)> {
    let empty = || integer_map([]);
    Ok(match message {
        Message::Hello {
            major,
            min_minor,
            max_minor,
            implementation,
            features,
            nonce,
            wall_time_ns,
            monotonic_stamp,
            limits,
        } => (
            1,
            integer_map([
                (0, serialized(major)?),
                (1, serialized(min_minor)?),
                (2, serialized(max_minor)?),
                (3, serialized(implementation)?),
                (4, serialized(features)?),
                (5, Value::Bytes(nonce.to_vec())),
                (6, serialized(wall_time_ns)?),
                (7, serialized(monotonic_stamp)?),
                (8, serialized(limits)?),
            ]),
        ),
        Message::HelloAck {
            major,
            minor,
            features,
            nonce,
            wall_time_ns,
            monotonic_stamp,
            limits,
        } => (
            2,
            integer_map([
                (0, serialized(major)?),
                (1, serialized(minor)?),
                (2, serialized(features)?),
                (3, Value::Bytes(nonce.to_vec())),
                (4, serialized(wall_time_ns)?),
                (5, serialized(monotonic_stamp)?),
                (6, serialized(limits)?),
            ]),
        ),
        Message::Incompatible {
            major,
            min_minor,
            max_minor,
            reason,
        } => (
            3,
            integer_map([
                (0, serialized(major)?),
                (1, serialized(min_minor)?),
                (2, serialized(max_minor)?),
                (3, serialized(reason)?),
            ]),
        ),
        Message::BeginJob {
            root,
            direction,
            excludes,
            dry_run,
            preserve_owner,
            preserve_group,
            numeric_ids,
        } => (
            10,
            integer_map([
                (0, Value::Bytes(root.clone())),
                (1, Value::from(direction_code(*direction))),
                (2, serialized(excludes)?),
                (3, serialized(dry_run)?),
                (4, serialized(preserve_owner)?),
                (5, serialized(preserve_group)?),
                (6, serialized(numeric_ids)?),
            ]),
        ),
        Message::JobAccepted => (11, empty()),
        Message::ManifestRequest => (20, empty()),
        Message::ManifestChunk(entries) => (21, integer_map([(0, serialized(entries)?)])),
        Message::DigestRequest(paths) => (22, integer_map([(0, serialized(paths)?)])),
        Message::DigestResponse(records) => (23, integer_map([(0, serialized(records)?)])),
        Message::SignatureRequest {
            path,
            expected,
            force_literal,
        } => (
            30,
            integer_map([
                (0, serialized(path)?),
                (1, serialized(expected)?),
                (2, serialized(force_literal)?),
            ]),
        ),
        Message::SignatureStreamStart {
            block_size,
            signatures,
            fallback,
        } => (
            24,
            integer_map([
                (0, serialized(block_size)?),
                (1, serialized(signatures)?),
                (2, serialized(fallback)?),
            ]),
        ),
        Message::SignatureChunk(signatures) => (25, integer_map([(0, serialized(signatures)?)])),
        Message::ApplyStart {
            entry,
            expected_destination,
            block_size,
            literal_only,
        } => (
            32,
            integer_map([
                (0, serialized(entry)?),
                (1, serialized(expected_destination)?),
                (2, serialized(block_size)?),
                (3, serialized(literal_only)?),
            ]),
        ),
        Message::InstructionChunk(instructions) => {
            (33, integer_map([(0, serialized(instructions)?)]))
        }
        Message::ApplyEnd(trailer) => (34, integer_map([(0, serialized(trailer)?)])),
        Message::ApplyResult(result) => (35, integer_map([(0, serialized(result)?)])),
        Message::ApplyReady => (45, empty()),
        Message::DeltaRequestStart {
            path,
            expected_source,
            block_size,
            signatures,
        } => (
            26,
            integer_map([
                (0, serialized(path)?),
                (1, serialized(expected_source)?),
                (2, serialized(block_size)?),
                (3, serialized(signatures)?),
            ]),
        ),
        Message::DeltaStart => (37, empty()),
        Message::DeltaEnd(trailer) => (38, integer_map([(0, serialized(trailer)?)])),
        Message::DeltaProceed(proceed) => (46, integer_map([(0, serialized(proceed)?)])),
        Message::DeltaCancelled => (47, empty()),
        Message::SymlinkSourceRequest {
            path,
            expected_source,
        } => (
            39,
            integer_map([(0, serialized(path)?), (1, serialized(expected_source)?)]),
        ),
        Message::SymlinkSourceResponse { target } => {
            (43, integer_map([(0, Value::Bytes(target.clone()))]))
        }
        Message::ApplyDirectory {
            entry,
            expected_destination,
        } => (
            40,
            integer_map([
                (0, serialized(entry)?),
                (1, serialized(expected_destination)?),
            ]),
        ),
        Message::ApplySymlink {
            entry,
            expected_destination,
        } => (
            41,
            integer_map([
                (0, serialized(entry)?),
                (1, serialized(expected_destination)?),
            ]),
        ),
        Message::FinalizeDirectory {
            entry,
            expected_destination,
        } => (
            42,
            integer_map([
                (0, serialized(entry)?),
                (1, serialized(expected_destination)?),
            ]),
        ),
        Message::FinishJob => (50, empty()),
        Message::JobResult(summary) => (51, integer_map([(0, serialized(summary)?)])),
        Message::AbortJob { reason } => (52, integer_map([(0, serialized(reason)?)])),
        Message::JobAborted => (53, empty()),
        Message::EndSession => (60, empty()),
        Message::Goodbye(summary) => (61, integer_map([(0, serialized(summary)?)])),
        Message::StreamStart { records, bytes } => (
            69,
            integer_map([(0, serialized(records)?), (1, serialized(bytes)?)]),
        ),
        Message::StreamEnd {
            records,
            bytes,
            status,
        } => (
            70,
            integer_map([
                (0, serialized(records)?),
                (1, serialized(bytes)?),
                (2, serialized(status)?),
            ]),
        ),
        Message::Error(error) => (255, integer_map([(0, serialized(error)?)])),
    })
}

#[allow(clippy::too_many_lines)]
fn decode_message(kind: u16, payload: Value) -> Result<Message> {
    let mut fields = Fields::new(payload, "message payload")?;
    let message = match kind {
        1 => Message::Hello {
            major: fields.take(0)?,
            min_minor: fields.take(1)?,
            max_minor: fields.take(2)?,
            implementation: fields.take(3)?,
            features: fields.take(4)?,
            nonce: take_fixed_bytes(&mut fields, 5)?,
            wall_time_ns: fields.take(6)?,
            monotonic_stamp: fields.take(7)?,
            limits: fields.take(8)?,
        },
        2 => Message::HelloAck {
            major: fields.take(0)?,
            minor: fields.take(1)?,
            features: fields.take(2)?,
            nonce: take_fixed_bytes(&mut fields, 3)?,
            wall_time_ns: fields.take(4)?,
            monotonic_stamp: fields.take(5)?,
            limits: fields.take(6)?,
        },
        3 => Message::Incompatible {
            major: fields.take(0)?,
            min_minor: fields.take(1)?,
            max_minor: fields.take(2)?,
            reason: fields.take(3)?,
        },
        10 => Message::BeginJob {
            root: take_bytes(&mut fields, 0)?,
            direction: decode_direction(fields.take(1)?)?,
            excludes: fields.take(2)?,
            dry_run: fields.take(3)?,
            preserve_owner: fields.take(4)?,
            preserve_group: fields.take(5)?,
            numeric_ids: fields.take(6)?,
        },
        11 => Message::JobAccepted,
        20 => Message::ManifestRequest,
        21 => Message::ManifestChunk(fields.take(0)?),
        22 => Message::DigestRequest(fields.take(0)?),
        23 => Message::DigestResponse(fields.take(0)?),
        30 => Message::SignatureRequest {
            path: fields.take(0)?,
            expected: fields.take(1)?,
            force_literal: fields.take(2)?,
        },
        24 => Message::SignatureStreamStart {
            block_size: fields.take(0)?,
            signatures: fields.take(1)?,
            fallback: fields.take(2)?,
        },
        25 => Message::SignatureChunk(fields.take(0)?),
        32 => Message::ApplyStart {
            entry: fields.take(0)?,
            expected_destination: fields.take(1)?,
            block_size: fields.take(2)?,
            literal_only: fields.take(3)?,
        },
        33 => Message::InstructionChunk(fields.take(0)?),
        34 => Message::ApplyEnd(fields.take(0)?),
        35 => Message::ApplyResult(fields.take(0)?),
        45 => Message::ApplyReady,
        26 => Message::DeltaRequestStart {
            path: fields.take(0)?,
            expected_source: fields.take(1)?,
            block_size: fields.take(2)?,
            signatures: fields.take(3)?,
        },
        37 => Message::DeltaStart,
        38 => Message::DeltaEnd(fields.take(0)?),
        46 => Message::DeltaProceed(fields.take(0)?),
        47 => Message::DeltaCancelled,
        39 => Message::SymlinkSourceRequest {
            path: fields.take(0)?,
            expected_source: fields.take(1)?,
        },
        40 => Message::ApplyDirectory {
            entry: fields.take(0)?,
            expected_destination: fields.take(1)?,
        },
        41 => Message::ApplySymlink {
            entry: fields.take(0)?,
            expected_destination: fields.take(1)?,
        },
        42 => Message::FinalizeDirectory {
            entry: fields.take(0)?,
            expected_destination: fields.take(1)?,
        },
        43 => Message::SymlinkSourceResponse {
            target: take_bytes(&mut fields, 0)?,
        },
        50 => Message::FinishJob,
        51 => Message::JobResult(fields.take(0)?),
        52 => Message::AbortJob {
            reason: fields.take(0)?,
        },
        53 => Message::JobAborted,
        60 => Message::EndSession,
        61 => Message::Goodbye(fields.take(0)?),
        69 => Message::StreamStart {
            records: fields.take(0)?,
            bytes: fields.take(1)?,
        },
        70 => Message::StreamEnd {
            records: fields.take(0)?,
            bytes: fields.take(1)?,
            status: fields.take(2)?,
        },
        255 => Message::Error(fields.take(0)?),
        _ => return Err(Error::Protocol(format!("unknown message kind {kind}"))),
    };
    fields.finish("message payload")?;
    validate_message(&message)?;
    Ok(message)
}

fn validate_message(message: &Message) -> Result<()> {
    let validate_entry = |entry: &ManifestEntry, kind: crate::manifest::EntryKind| {
        entry.validate()?;
        if entry.kind != kind {
            return Err(Error::Protocol(format!(
                "message entry {} has the wrong kind",
                entry.path
            )));
        }
        Ok(())
    };
    match message {
        Message::ManifestChunk(entries) => {
            if entries.len() > MAX_RECORDS_PER_FRAME {
                return Err(Error::Protocol(
                    "manifest chunk record limit exceeded".into(),
                ));
            }
            for entry in entries {
                entry.validate()?;
            }
        }
        Message::DigestRequest(paths) => {
            if paths.len() > MAX_RECORDS_PER_FRAME {
                return Err(Error::Protocol(
                    "digest request record limit exceeded".into(),
                ));
            }
        }
        Message::DigestResponse(records) => {
            if records.len() > MAX_RECORDS_PER_FRAME {
                return Err(Error::Protocol(
                    "digest response record limit exceeded".into(),
                ));
            }
        }
        Message::ApplyStart {
            entry,
            expected_destination,
            block_size,
            ..
        } => {
            validate_entry(entry, crate::manifest::EntryKind::File)?;
            validate_optional_fingerprint(expected_destination, crate::manifest::EntryKind::File)?;
            if *block_size == 0 || *block_size as usize > crate::delta::MAX_BLOCK_SIZE {
                return Err(Error::Protocol("invalid apply block size".into()));
            }
        }
        Message::SignatureStreamStart {
            block_size,
            signatures,
            ..
        } => {
            if *block_size == 0
                || *block_size as usize > crate::delta::MAX_BLOCK_SIZE
                || signatures.saturating_mul(40) > crate::delta::WIRE_SIGNATURE_BUDGET as u64
            {
                return Err(Error::Protocol("invalid signature stream fields".into()));
            }
        }
        Message::SignatureChunk(signatures) => {
            if signatures.len() > MAX_RECORDS_PER_FRAME
                || signatures.len().saturating_mul(40) > crate::delta::WIRE_SIGNATURE_BUDGET
                || signatures.iter().any(|signature| signature.length == 0)
            {
                return Err(Error::Protocol("invalid signature chunk".into()));
            }
        }
        Message::InstructionChunk(instructions) => {
            if instructions.len() > MAX_RECORDS_PER_FRAME {
                return Err(Error::Protocol(
                    "instruction chunk record limit exceeded".into(),
                ));
            }
        }
        Message::ApplyDirectory {
            entry,
            expected_destination,
        } => {
            validate_entry(entry, crate::manifest::EntryKind::Directory)?;
            validate_optional_fingerprint(
                expected_destination,
                crate::manifest::EntryKind::Directory,
            )?;
        }
        Message::FinalizeDirectory {
            entry,
            expected_destination,
        } => {
            validate_entry(entry, crate::manifest::EntryKind::Directory)?;
            validate_fingerprint(expected_destination, crate::manifest::EntryKind::Directory)?;
        }
        Message::ApplySymlink {
            entry,
            expected_destination,
        } => {
            validate_entry(entry, crate::manifest::EntryKind::Symlink)?;
            validate_optional_fingerprint(
                expected_destination,
                crate::manifest::EntryKind::Symlink,
            )?;
        }
        Message::SignatureRequest {
            expected: Some(fingerprint),
            ..
        } => {
            fingerprint.mtime.validate()?;
            if fingerprint.kind != crate::manifest::EntryKind::File {
                return Err(Error::Protocol("signature basis is not a file".into()));
            }
        }
        Message::SymlinkSourceRequest {
            expected_source, ..
        } => {
            expected_source.mtime.validate()?;
            if expected_source.kind != crate::manifest::EntryKind::Symlink {
                return Err(Error::Protocol("symlink source has the wrong kind".into()));
            }
        }
        Message::DeltaRequestStart {
            expected_source,
            block_size,
            signatures,
            ..
        } => {
            validate_fingerprint(expected_source, crate::manifest::EntryKind::File)?;
            if *block_size == 0
                || *block_size as usize > crate::delta::MAX_BLOCK_SIZE
                || signatures.saturating_mul(40) > crate::delta::WIRE_SIGNATURE_BUDGET as u64
            {
                return Err(Error::Protocol(
                    "invalid delta request stream fields".into(),
                ));
            }
        }
        Message::ApplyEnd(Trailer { length, .. }) | Message::DeltaEnd(Trailer { length, .. })
            if *length > i64::MAX as u64 =>
        {
            return Err(Error::Protocol("transfer length is out of range".into()));
        }
        _ => {}
    }
    Ok(())
}

fn validate_optional_fingerprint(
    fingerprint: &Option<Fingerprint>,
    kind: crate::manifest::EntryKind,
) -> Result<()> {
    if let Some(fingerprint) = fingerprint {
        validate_fingerprint(fingerprint, kind)?;
    }
    Ok(())
}

fn validate_fingerprint(fingerprint: &Fingerprint, kind: crate::manifest::EntryKind) -> Result<()> {
    fingerprint.mtime.validate()?;
    if fingerprint.kind != kind {
        return Err(Error::Protocol(
            "fingerprint has the wrong entry kind".into(),
        ));
    }
    Ok(())
}

fn integer_map<const N: usize>(fields: [(u16, Value); N]) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

fn serialized<T: ?Sized + Serialize>(value: &T) -> Result<Value> {
    Value::serialized(value)
        .map_err(|error| Error::Protocol(format!("could not encode message field: {error}")))
}

pub fn encoded_envelope_len(envelope: &Envelope) -> Result<usize> {
    let value = encode_envelope(envelope)?;
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded)
        .map_err(|error| Error::Protocol(format!("could not encode frame: {error}")))?;
    Ok(encoded.len())
}

/// Bounds an operator-facing diagnostic without splitting a UTF-8 code point.
///
/// Callers that put the result on the wire must still check the encoded
/// envelope size because CBOR and the envelope's other fields add overhead.
#[must_use]
pub fn truncate_diagnostic(value: &str, max_bytes: usize) -> String {
    const MARKER: &str = "...[truncated]";
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    if max_bytes <= MARKER.len() {
        let mut end = max_bytes;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        return value[..end].to_owned();
    }
    let mut end = max_bytes - MARKER.len();
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &value[..end], MARKER)
}

struct Fields(std::collections::BTreeMap<u16, Value>);

impl Fields {
    fn new(value: Value, description: &str) -> Result<Self> {
        let Value::Map(entries) = value else {
            return Err(Error::Protocol(format!("{description} is not a CBOR map")));
        };
        let mut fields = std::collections::BTreeMap::new();
        for (key, value) in entries {
            let Value::Integer(key) = key else {
                return Err(Error::Protocol(format!(
                    "{description} has a non-integer field key"
                )));
            };
            let key = u16::try_from(key)
                .map_err(|_| Error::Protocol(format!("{description} field key is out of range")))?;
            if fields.insert(key, value).is_some() {
                return Err(Error::Protocol(format!(
                    "{description} has duplicate field {key}"
                )));
            }
        }
        Ok(Self(fields))
    }

    fn take<T: DeserializeOwned>(&mut self, key: u16) -> Result<T> {
        self.take_value(key)?
            .deserialized()
            .map_err(|error| Error::Protocol(format!("invalid message field {key}: {error}")))
    }

    fn take_value(&mut self, key: u16) -> Result<Value> {
        self.0
            .remove(&key)
            .ok_or_else(|| Error::Protocol(format!("required message field {key} is missing")))
    }

    fn finish(&self, description: &str) -> Result<()> {
        if let Some(key) = self.0.keys().next() {
            return Err(Error::Protocol(format!(
                "{description} has unsupported field {key}"
            )));
        }
        Ok(())
    }
}

fn take_fixed_bytes<const N: usize>(fields: &mut Fields, key: u16) -> Result<[u8; N]> {
    let bytes = take_bytes(fields, key)?;
    bytes
        .try_into()
        .map_err(|_| Error::Protocol(format!("message field {key} has the wrong byte length")))
}

fn take_bytes(fields: &mut Fields, key: u16) -> Result<Vec<u8>> {
    match fields.take_value(key)? {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(Error::Protocol(format!(
            "message field {key} is not a byte string"
        ))),
    }
}

const fn direction_code(direction: Direction) -> u8 {
    match direction {
        Direction::InOut => 0,
        Direction::In => 1,
        Direction::Out => 2,
    }
}

fn decode_direction(code: u8) -> Result<Direction> {
    match code {
        0 => Ok(Direction::InOut),
        1 => Ok(Direction::In),
        2 => Ok(Direction::Out),
        _ => Err(Error::Protocol("invalid direction code".into())),
    }
}

fn escaped_preview(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\x{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::manifest::{EntryKind, Timestamp};

    use super::*;

    fn sample_entry(kind: EntryKind) -> ManifestEntry {
        let path = RelativePath::new(b"entry".to_vec()).unwrap();
        let mtime = Timestamp {
            seconds: 1,
            nanos: 2,
        };
        let target = if kind == EntryKind::Symlink {
            b"target".to_vec()
        } else {
            Vec::new()
        };
        let size = target.len() as u64;
        ManifestEntry {
            path,
            kind,
            mtime,
            mode: 0o644,
            uid: 1,
            gid: 2,
            owner_name: None,
            group_name: None,
            size,
            symlink_target: target,
            scan_error: None,
            fingerprint: Fingerprint {
                device: 3,
                inode: 4,
                kind,
                size,
                mtime,
            },
        }
    }

    #[test]
    fn golden_end_session_frame_round_trips() {
        let hello = Envelope {
            request_id: 1,
            job_id: 0,
            message: Message::EndSession,
        };
        let mut framed = Framed::new(Cursor::new(Vec::new()), Vec::new());
        framed.send(&hello).unwrap();
        let (_, encoded) = framed.into_inner();
        assert_eq!(
            encoded,
            [
                0, 0, 0, 10, 0xa4, 0x00, 0x18, 0x3c, 0x01, 0x01, 0x02, 0x00, 0x03, 0xa0
            ]
        );
        let encoded = encoded.to_vec();
        let mut framed = Framed::new(Cursor::new(encoded), Vec::new());
        assert_eq!(framed.receive().unwrap(), hello);
    }

    #[test]
    fn rejects_oversized_and_corrupt_magic() {
        let mut bytes = Vec::from((1024u32).to_be_bytes());
        bytes.resize(1028, 0);
        let mut framed = Framed::with_max_frame(Cursor::new(bytes), Vec::new(), 32);
        assert!(framed.receive().is_err());
        let mut framed = Framed::new(Cursor::new(*b"welcome!"), Vec::new());
        assert!(
            framed
                .read_magic()
                .unwrap_err()
                .to_string()
                .contains("remote shell")
        );
    }

    #[test]
    fn protocol_version_constants_are_stable() {
        assert_eq!((PROTOCOL_MAJOR, PROTOCOL_MINOR), (1, 0));
        assert_eq!(MAGIC, b"XSYNC\0\r\n");
    }

    #[test]
    fn intersected_field_limits_fit_small_frames() {
        let constrained = Limits::default().intersect(Limits {
            max_frame: 2048,
            ..Limits::default()
        });
        constrained.validate().unwrap();
        assert_eq!(constrained.max_frame, 2048);
        assert!(constrained.max_literal <= 1792);
        assert!(constrained.max_path <= 256);
    }

    #[test]
    fn decoded_record_arrays_enforce_the_per_frame_count_cap() {
        let file = sample_entry(EntryKind::File);
        let digest = DigestRecord {
            path: file.path.clone(),
            digest: Some([0; 32]),
            error: None,
        };
        let signature = Signature {
            block_index: 0,
            length: 1,
            weak: 0,
            strong: [0; 16],
        };
        let over = MAX_RECORDS_PER_FRAME + 1;
        for message in [
            Message::ManifestChunk(vec![file.clone(); over]),
            Message::DigestRequest(vec![file.path.clone(); over]),
            Message::DigestResponse(vec![digest; over]),
            Message::SignatureChunk(vec![signature; over]),
            Message::InstructionChunk(vec![
                Instruction::Copy {
                    first_block: 0,
                    block_count: 1,
                };
                over
            ]),
        ] {
            assert!(validate_message(&message).is_err());
        }
    }

    #[test]
    fn unknown_kinds_and_duplicate_integer_fields_are_rejected() {
        let unknown = integer_map([
            (0, Value::from(999u16)),
            (1, Value::from(1u64)),
            (2, Value::from(0u64)),
            (3, integer_map([])),
        ]);
        assert!(decode_envelope(unknown).is_err());

        let duplicate = Value::Map(vec![
            (Value::from(0u16), Value::from(60u16)),
            (Value::from(0u16), Value::from(60u16)),
            (Value::from(1u16), Value::from(1u64)),
            (Value::from(2u16), Value::from(0u64)),
            (Value::from(3u16), integer_map([])),
        ]);
        assert!(decode_envelope(duplicate).is_err());
    }

    #[test]
    fn every_message_kind_has_a_unique_round_trip_encoding() {
        let file = sample_entry(EntryKind::File);
        let directory = sample_entry(EntryKind::Directory);
        let symlink = sample_entry(EntryKind::Symlink);
        let signature = Signature {
            block_index: 0,
            length: 1,
            weak: 2,
            strong: [3; 16],
        };
        let trailer = Trailer {
            length: 0,
            digest: *blake3::hash(&[]).as_bytes(),
        };
        let messages = vec![
            Message::Hello {
                major: 1,
                min_minor: 0,
                max_minor: 0,
                implementation: "test".into(),
                features: SUPPORTED_FEATURES,
                nonce: [1; 16],
                wall_time_ns: 1,
                monotonic_stamp: 2,
                limits: Limits::default(),
            },
            Message::HelloAck {
                major: 1,
                minor: 0,
                features: SUPPORTED_FEATURES,
                nonce: [1; 16],
                wall_time_ns: 1,
                monotonic_stamp: 2,
                limits: Limits::default(),
            },
            Message::Incompatible {
                major: 2,
                min_minor: 0,
                max_minor: 1,
                reason: "version".into(),
            },
            Message::BeginJob {
                root: b"root".to_vec(),
                direction: Direction::InOut,
                excludes: vec!["*.tmp".into()],
                dry_run: false,
                preserve_owner: false,
                preserve_group: false,
                numeric_ids: false,
            },
            Message::JobAccepted,
            Message::ManifestRequest,
            Message::ManifestChunk(vec![file.clone()]),
            Message::DigestRequest(vec![file.path.clone()]),
            Message::DigestResponse(vec![DigestRecord {
                path: file.path.clone(),
                digest: Some([4; 32]),
                error: None,
            }]),
            Message::SignatureRequest {
                path: file.path.clone(),
                expected: Some(file.fingerprint),
                force_literal: false,
            },
            Message::SignatureStreamStart {
                block_size: 4096,
                signatures: 1,
                fallback: false,
            },
            Message::SignatureChunk(vec![signature.clone()]),
            Message::ApplyStart {
                entry: file.clone(),
                expected_destination: Some(file.fingerprint),
                block_size: 4096,
                literal_only: false,
            },
            Message::InstructionChunk(vec![Instruction::Literal(vec![1])]),
            Message::ApplyEnd(trailer),
            Message::ApplyResult(EntryResult::ok()),
            Message::ApplyReady,
            Message::DeltaRequestStart {
                path: file.path.clone(),
                expected_source: file.fingerprint,
                block_size: 4096,
                signatures: 0,
            },
            Message::DeltaStart,
            Message::DeltaEnd(trailer),
            Message::DeltaProceed(true),
            Message::DeltaCancelled,
            Message::SymlinkSourceRequest {
                path: symlink.path.clone(),
                expected_source: symlink.fingerprint,
            },
            Message::SymlinkSourceResponse {
                target: b"target".to_vec(),
            },
            Message::ApplyDirectory {
                entry: directory.clone(),
                expected_destination: Some(directory.fingerprint),
            },
            Message::ApplySymlink {
                entry: symlink,
                expected_destination: None,
            },
            Message::FinalizeDirectory {
                entry: directory.clone(),
                expected_destination: directory.fingerprint,
            },
            Message::FinishJob,
            Message::JobResult(JobSummary::default()),
            Message::AbortJob {
                reason: "test".into(),
            },
            Message::JobAborted,
            Message::EndSession,
            Message::Goodbye(JobSummary::default()),
            Message::StreamStart {
                records: Some(1),
                bytes: Some(2),
            },
            Message::StreamEnd {
                records: 1,
                bytes: 2,
                status: StreamStatus::Ok,
            },
            Message::Error(WireError {
                class: "test".into(),
                path: None,
                message: "message".into(),
                fatal: false,
            }),
        ];
        let mut kinds = std::collections::BTreeSet::new();
        for (request_id, message) in messages.into_iter().enumerate() {
            let envelope = Envelope {
                request_id: request_id as u64 + 1,
                job_id: 1,
                message,
            };
            let encoded = encode_envelope(&envelope).unwrap();
            let Value::Map(fields) = &encoded else {
                panic!("envelope was not a map");
            };
            let kind = fields
                .iter()
                .find(|(key, _)| key == &Value::from(0u16))
                .map(|(_, value)| value.clone())
                .unwrap();
            assert!(kinds.insert(format!("{kind:?}")), "duplicate message kind");
            assert_eq!(decode_envelope(encoded).unwrap(), envelope);
        }
    }

    #[test]
    fn diagnostic_truncation_is_utf8_safe_and_bounded() {
        assert_eq!(truncate_diagnostic("short", 10), "short");
        let truncated = truncate_diagnostic("abécd".repeat(20).as_str(), 25);
        assert!(truncated.len() <= 25);
        assert!(truncated.ends_with("...[truncated]"));
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());

        let tiny = truncate_diagnostic("ééé", 3);
        assert!(tiny.len() <= 3);
        assert!(std::str::from_utf8(tiny.as_bytes()).is_ok());
    }
}
