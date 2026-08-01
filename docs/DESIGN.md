# xsync design specification

Status: implemented release candidate for protocol 1.0

## 1. Purpose and scope

`xsync` synchronizes one or more directory trees between the machine on which it
is invoked and a machine reached through SSH. A single SSH connection is reused
for all directory jobs. In the default bidirectional mode, the copy with the
newer modification time wins. Unlike mirroring tools, xsync never infers a
deletion from absence: an entry present on only one side is copied to the other
side.

The first release targets Unix hosts and regular files, directories, and
symbolic links. It preserves file modes and mtimes. Ownership preservation is
opt-in because accounts frequently have different IDs on different hosts. Device
nodes, sockets, and FIFOs are reported and skipped. Hard-link relationships,
ACLs, extended attributes, sparse-file layout, and cross-session deletion
tracking are explicitly out of scope for version 1.

Version 1 is stateless: it cannot distinguish a deletion from a file newly
created on the other side, nor can it detect two independent edits when their
mtimes provide an ordering. It is rsync-style at the block-transfer layer, not
wire-compatible with rsync. Whole-job rollback, backups of overwritten files,
parallel/resumable transfers, and automatic conflict merging are also out of
scope.

The program is not a continuous watcher. Each invocation takes snapshots,
plans work, performs it, and exits.

## 2. Command line

```text
xsync SERVER [GLOBAL_OPTIONS] DIR [DIRECTORY_OPTIONS] [DIR [DIRECTORY_OPTIONS] ...]
xsync --agent
```

`--agent` is an internal, protocol-only mode launched on the remote host. Its
standard input and output carry framed protocol data; diagnostics go to standard
error. Users do not invoke it directly.

Global options must precede the first directory:

- `--in-out` selects bidirectional synchronization and is the default.
- `--in` permits only remote-to-local transfers.
- `--out` permits only local-to-remote transfers.
- `--ssh COMMAND` replaces the SSH command, defaulting to `ssh`. `COMMAND` is
  split with shell-word syntax and executed directly, never through a shell.
- `--remote-program PATH` selects the remote executable, default `xsync`.
- `--progress=MODE` selects `auto`, `always`, `never`, or `json`; bare
  `--progress` means `always` and never consumes the following token. `auto`
  renders only when stderr is a terminal.
- `-n` / `--dry-run` performs handshake, scans, and planning but no mutation. It emits
  each planned operation even when automatic progress would normally be silent;
  `--quiet` or `--progress=never` explicitly suppresses this display.
- `--checksum` hashes same-size/same-mtime regular files to detect ambiguous
  divergence. Without it, equality of type, size, and mtime is considered equal.
- `--modify-window SECONDS` treats mtimes within the window as equal. The
  default is 0 so every representable newer mtime wins. Coarse filesystems such
  as FAT may require an explicit 1 or 2 seconds;
  version 1 does not attempt a mutating filesystem-resolution probe.
- `--max-clock-skew SECONDS` refuses to synchronize when the handshake's
  round-trip-adjusted wall-clock skew estimate exceeds the value (default 60).
  Skew above 2 seconds is always warned about. `--ignore-clock-skew` overrides
  refusal but not the warning.
- `--owner` and `--group` preserve the corresponding owner by name when
  possible. `--numeric-ids` makes those options use numeric IDs directly.
- `--verbose` may be repeated; `--quiet` suppresses non-error summaries.

Direction may also occur in a directory option group and overrides the global
direction for that job. Directory options apply to the immediately preceding
`DIR` until the next positional directory:

- `--dest PATH` sets that directory's remote root. Its default is exactly the
  local path spelling after local lexical normalization.
- `--exclude PATTERN` may be repeated. Patterns use gitignore-like syntax and
  `/` separators, are rooted at the job root when beginning with `/`, and apply
  identically on both peers. Version 1 supports `*`, `?`, character classes,
  `**`, a leading `/`, and a trailing `/` for directory-only matching. It does
  not read ignore files or support `!` negation. Excluding a directory excludes
  its subtree.
- `--in`, `--out`, and `--in-out` override the global direction.

`--` ends option interpretation and every following token is a directory path;
no directory options can follow it. `--dir PATH` is the repeatable explicit form
for a path beginning with `-` and starts a normal directory option group.
Unknown options, a directory option before any
directory, incompatible directions, an empty SSH command, or duplicate `--dest`
are usage errors. Local and destination job roots must be absolute after
normalization and must not overlap another root on their respective side. A
relative local path is made absolute using the controller's current directory
without resolving symlinks; that absolute spelling is also the default remote
destination. Relative `--dest` is rejected. `--help` and `--version` exit 0; a
server without a directory exits 2. The custom grouping parser is covered by
table-driven tests.

Examples:

```text
xsync host.example /home/me/src --exclude target --exclude .git
xsync backup --out /srv/photos --dest /data/photos /etc --dest /archive/etc
xsync laptop --progress=json /home/me/notes --in-out
```

## 3. Terminology and architecture

- **controller**: the user-facing local process.
- **agent**: the remote `xsync --agent` child reached through the transport.
- **job**: one local root, remote root, direction, and exclude set.
- **source/receiver**: roles for one planned entry; they can reverse between
  entries in a bidirectional job.

The controller owns all policy and planning. The agent validates requests,
scans its requested root, computes signatures/deltas when asked, applies
receiver operations atomically, and remains alive for subsequent jobs.

```text
controller                       agent
    |---- Hello ------------------->|
    |<--- HelloAck -----------------|
    |---- BeginJob ---------------->|
    |<--- JobAccepted --------------|
    |---- ManifestRequest --------->|
    |<--- Manifest chunks ----------|
    |  scan local; build plan         |
    |<=== entry operations =========>|
    |---- FinishJob ---------------->|
    |<--- JobResult -----------------|
    |       repeat BeginJob ...       |
    |---- EndSession -------------->|
    |<--- Goodbye -------------------|
```

Only the controller launches SSH. This controller corresponds to the original
goal's local "server," while the agent corresponds to its SSH-side "client."
The command is assembled as SSH command tokens, `--`, `SERVER`, and one remote
command string. SSH does not preserve remote argument boundaries: the login
shell interprets that string. Xsync therefore POSIX-single-quotes the remote
program (including embedded quote escaping) and appends the fixed ` --agent`.
Server values beginning with `-` are rejected as defense in depth. Tests use the
same agent over piped child-process stdio without SSH.

The controller starts a dedicated reader for the transport child's stderr before
the handshake and keeps it running through child teardown. It prefixes forwarded
lines with `remote:`, uses a bounded queue, and reports the number of dropped
diagnostic lines instead of allowing a full stderr pipe to deadlock the agent.
The local and remote scans begin concurrently.

## 4. Protocol

### 4.1 Framing and encoding

The byte stream begins with eight ASCII magic bytes (`XSYNC\0\r\n`). Every
subsequent frame is:

```text
u32 big-endian payload length | CBOR-encoded Message payload
```

Frames are negotiated between 2 KiB and 16 MiB, and bulk literals are chunked
to at most 1 MiB.
Lists and instruction streams use explicit begin/chunk/end messages so memory is
bounded and progress can be reported. Unknown message kinds are protocol errors.
All integer sizes, mtimes, IDs, modes, and ownership fields have explicit widths.
Path components are transported as Unix byte strings, not assumed UTF-8.
If the first eight received bytes are not the magic, the controller reports that
the remote shell wrote to protocol stdout, includes a bounded escaped preview,
and exits 3. This gives login banners and shell startup noise a direct diagnosis.

Each request has a monotonically increasing `request_id`; its response repeats
that ID. Messages are strictly request/response in version 1, except for chunks
belonging to the active request. Unexpected IDs, illegal state transitions,
oversized frames, and premature EOF fail the session.

Streams have message-specific boundaries. Manifests use `StreamStart`, chunks,
and `StreamEnd`; signatures use a typed start, chunks, and `StreamEnd`; file
apply streams use `ApplyReady`, instruction chunks, `ApplyEnd`, and
`ApplyResult`; remote-source streams use `DeltaStart`, `DeltaProceed`,
instruction chunks, and `DeltaEnd`. A receiver that acknowledged a stream
drains its bounded records through the corresponding trailer before returning a
recoverable failure. A receiver that cannot initialize replies before the
sender begins, using `ApplyResult` or `DeltaProceed(false)`/`DeltaCancelled`.
No abort frame is injected into an active stream.

### 4.2 Handshake and compatibility

`Hello` contains:

- implementation semantic version (diagnostic only),
- protocol major and supported inclusive minor range,
- feature bit set,
- random session nonce used for diagnostic correlation,
- wall-clock Unix time and monotonic send timestamp for round-trip-adjusted skew
  estimation.

`HelloAck` selects a minor version and the intersection of features. A major
mismatch or no common minor produces `Incompatible` and exits before a job is
started. Minor versions are backwards compatible: the chosen minor defines
allowed message fields and behavior. Required job features must be in the
negotiated set. It also echoes the controller's monotonic stamp and supplies the
agent wall-clock time when `Hello` was processed. With measured round-trip time,
the controller estimates `remote_wall - (local_wall_at_send + RTT/2)`; exceeding
the configured maximum is a transport refusal (exit 3). The initial major/minor
is `1.0`.

### 4.3 State machine

The agent accepts only:

```text
AwaitHello -> Idle -> Accepted -> Inventoried -> Syncing
           -> Finalizing -> Idle -> ... -> Closed
```

`BeginJob` is valid only in `Idle`; it carries a job ID, the remote root, excludes,
direction (for validation/diagnostics), dry-run flag, and negotiated limits.
One job is active at a time. `BeginJob` opens or creates the root and enters
`Accepted`; `ManifestRequest` inventories it and enters `Inventoried`; the first
entry operation enters `Syncing`. `Syncing` is skipped for an empty plan.
`FinishJob` enters
`Finalizing` and `JobResult` returns to `Idle`. The controller may send
`AbortJob` only between streams. On cancellation during a response stream, the
controller drains that response first; while the agent receives a request
stream, the agent drains it before an abort can be sent. The agent then replies
`JobAborted`. Recoverable job errors take the same finalizing/cleanup
edge. Framing, handshake, and state-machine errors are session-fatal.
`EndSession` is valid only in `Idle`.

If a requested root is missing and direction permits writes to that peer, xsync
creates the root (but not missing ancestors) with temporary mode `0700` and
later finalizes it from the source root metadata. The root's creation metadata is
provisional and the empty-path manifest entry participates in the same final
deepest-first directory pass. It reports `RootParentMissing` when
the parent is absent. A missing root on a read-only side fails the job. Dry-run
reports but does not perform root creation.

### 4.4 Normative message catalog

Every frame is an envelope containing `kind: u16`, `request_id: u64`,
`job_id: u64` (zero for session messages), and a kind-specific CBOR map with
integer field keys. Additive fields use new keys and are ignored only when the
negotiated minor permits them. The one `request_id` identifies the operation and
all of its stream frames; there is no separate operation-ID namespace. A request
stream always ends before its response stream begins.

| Group | Message and direction | Valid state and payload |
|---|---|---|
| Session | `Hello` C→A | `AwaitHello`; protocol/implementation versions, features, limits, nonce `[u8;16]`, local wall nanoseconds `i64`, monotonic stamp `u64` |
| Session | `HelloAck` A→C / `Incompatible` A→C | handshake response; selected version/features/limits or supported range/reason, echoed stamp and agent wall nanoseconds |
| Session | `EndSession` C→A / `Goodbye` A→C | `Idle`; empty request and summary response |
| Job | `BeginJob` C→A / `JobAccepted` A→C | `Idle`→`Accepted`; absolute remote-root bytes, direction, excludes, dry-run and preservation flags |
| Job | `FinishJob` C→A / `JobResult` A→C | `Inventoried` or `Syncing`→`Finalizing`→`Idle`; transfer/warning/error counters |
| Job | `AbortJob` C→A / `JobAborted` A→C | between streams in an active job; reason and cleanup result |
| Inventory | `ManifestRequest` C→A | `Accepted`; A→C `StreamStart`, bounded `ManifestChunk` frames, then `StreamEnd`; success enters `Inventoried` |
| Inventory | `DigestRequest` C→A / `DigestResponse` A→C | `Inventoried`; one bounded path vector per request and one or more bounded response vectors with a digest or per-path error |
| Remote receiver basis | `SignatureRequest` C→A | `Inventoried`/`Syncing`; path, planned fingerprint and literal-fallback flag; A→C `SignatureStreamStart`, `SignatureChunk` frames, `StreamEnd` |
| Remote receiver apply | `ApplyStart` C→A | file entry, planned destination, block size and literal-only flag; A→C `ApplyReady` (or early `ApplyResult`), then C→A `InstructionChunk` frames and `ApplyEnd {length,digest}`, then A→C `ApplyResult` |
| Remote source | `DeltaRequestStart` C→A | path, planned source, block size and signature count; C→A `SignatureChunk` frames and `StreamEnd`; A→C `DeltaStart`; C→A `DeltaProceed(true)` followed by A→C `InstructionChunk` frames and `DeltaEnd`, or `DeltaProceed(false)` followed by `DeltaCancelled` |
| Symlink source | `SymlinkSourceRequest` C→A / `SymlinkSourceResponse` A→C | planned source identity and target bytes |
| Non-file receiver | `ApplyDirectory`, `ApplySymlink`, `FinalizeDirectory` C→A | validated entry metadata and planned destination identity; `ApplyResult` A→C |
| Control | `Error` A→C | bounded structured class/path/message; fatal flag controls session teardown |

Chunk arrays contain at most 256 records and must also fit the negotiated frame.
Literal instructions are at most 1 MiB and are flushed promptly instead of being
aggregated into a multi-megabyte frame. `StreamEnd` carries record/byte counts and
`Ok` or `Failed(message)` where that stream shape uses it. Warnings are returned
inside normal results, never as unsolicited protocol frames. Protocol 1.0 has no
legacy whole-vector signature/delta messages and no `SetMetadata` message.

## 5. Filesystem model and manifests

Every manifest entry contains a root-relative byte path and:

- kind: regular file, directory, symlink, or unsupported;
- mtime as signed seconds plus nanoseconds;
- Unix mode, numeric uid/gid, and optional owner/group names;
- regular-file length;
- symlink target bytes;

The root itself is represented by the empty relative path. Entries are emitted
in bytewise path order for deterministic plans and tests. Scanning uses
`symlink_metadata`; symlinks are recorded and never traversed. A relative entry
must be normalized, contain no empty, `.` or `..` component, contain no NUL, and
must not be absolute. Both peers independently apply the same excludes.
Manifest entries do not carry content digests. With `--checksum`, after
comparing manifests the controller uses bounded, chunked
`DigestRequest`/`DigestResponse` exchanges only for ambiguous paths.

The absolute job-root spelling may contain symlinks above its final component.
The root is resolved and opened once, its identity is recorded, and subsequent
work is relative to that directory capability. The final root component must be
a directory. Receiver mutations are confined beneath it. Operations reject an
ancestor below the opened root that is a symlink. Temporary names are created in the destination
entry's parent with exclusive creation. This prevents protocol paths and a
concurrent symlink swap from redirecting writes outside the root. Version 1 is
designed for non-hostile trees but still performs these containment checks at
each mutation boundary.

The `.xsync.tmp.` filename prefix is reserved in every synchronized directory.
Scans unconditionally omit entries with that prefix before user excludes are
evaluated. Receiver files use `.xsync.tmp.<pid>.<random>` with exclusive mode
`0600`; they receive final metadata only during commit. A clean failure or EOF
removes known temporaries, while stale crash debris remains ignored. Before an
existing destination is atomically exchanged, the prepared payload is renamed
to a visible `.xsync.recovery.` name. Consequently, an abrupt process death can
leave an obvious recovery file but cannot hide independently written data under
the scanner-pruned temp prefix.

A source file is fingerprinted with device, inode, kind, size, and mtime and is
restatted before and after reading. The destination is likewise fingerprinted at
planning and revalidated immediately before commit. Any change causes
`SourceChanged` or `DestinationChanged`; an inconsistent source is never
committed and an independently changed destination is never overwritten.

Both peers acquire non-blocking advisory locks on their opened root directories
before inventory and hold them through finalization. A busy root fails clearly;
there is no distributed wait and therefore no lock-order deadlock.

## 6. Planning and conflict policy

Planning is deterministic over the union of relative paths.

When an entry exists on only one side:

- `in-out`: copy it to the missing side;
- `out`: copy local-only entries outward; leave remote-only entries untouched;
- `in`: copy remote-only entries inward; leave local-only entries untouched.

No mode deletes an entry merely because it is absent on the other side.

Mtime comparisons use the requested modify window. When both sides contain the
same kind:

- regular files with equal size and equal mtime are content-equal unless
  `--checksum` finds differing digests. Equal-time permission differences and
  ownership differences selected by `--owner`/`--group` are warned about and
  left unchanged because neither side is newer. Warnings name every differing
  field and show its local and remote values;
- otherwise the side with the newer mtime is the candidate source;
- direction permits or suppresses that candidate transfer;
- directories are merged recursively. Their selected mode/ownership/mtime
  metadata is captured from the permitted newer side before mutations and is
  finalized after children, deepest first. All touched directories are finalized
  even after recoverable child failures, so child creation does not cause mtime
  oscillation. Equal-time selected metadata differences produce a warning,
  leave both metadata copies unchanged, and never block children;
- symlinks compare target bytes, then use mtime/direction as above. Equal-time,
  equal-target symlinks compare selected ownership but not mode bits.

Equal mtimes with differing content/size/target are conflicts. Different entry
kinds are structural conflicts regardless of mtime. Special permission bits are
ignored when comparing metadata because version 1 never applies them. A conflict is reported, neither side
is changed, other independent entries continue, and the process exits with a
partial-failure status. This avoids silent data loss where mtime supplies no
ordering. A future explicit conflict policy can add alternatives without
changing version 1's safe default.

The complete plan is stable-sorted: create required directories shallowest
first, transfer/symlink entries bytewise by path, and finalize directory
metadata deepest first. If a parent path has a structural conflict, descendants
beneath it are blocked and reported once. Metadata-only divergence never blocks
descendants.

## 7. Delta transfer

A missing receiver file uses a literal-only transfer. For any existing regular
receiver file, xsync can use an rsync-style single-round delta:

1. The receiver selects a block size approximately `sqrt(file_size)`, at least
   4 KiB, and large enough that all signatures fit the negotiated signature
   budget. It sends for each block its index, length, rsync rolling
   checksum, and 128 bits of BLAKE3.
2. The source indexes blocks by weak checksum, scans its file with a rolling
   window, and confirms candidates with the strong digest and exact block
   length.
3. It streams `Copy { first_block, block_count }` and bounded
   `Literal { bytes }` instructions. Adjacent copies
   and literals are coalesced up to negotiated bounds.
4. The receiver reconstructs into an exclusively created mode-`0600` sibling temporary
   file by copying old blocks or literals while calculating the full BLAKE3
   digest and byte count.
5. The source sends its full digest and length as the instruction stream's
   `DeltaTrailer`. In both directions it computes the trailer during the same
   single read that generates instructions. The receiver commits only if its
   running digest and length both match.

A missing-basis whole-file transfer is represented as a literal-only stream and
uses the same final length/digest verification.

For a remote source, the controller sends local signatures and requests a delta
from the agent. For a local source, it requests remote signatures and sends the
locally generated delta. This is the same algorithm in both directions.

The receiver's basis file is opened before signature generation and its
identity/size/mtime are revalidated before reconstruction. A changed basis
causes a retry as a whole-file transfer at most once. Invalid copy indices,
lengths, or output sizes abort the temporary file.

A final digest mismatch removes the temporary and fails the entry with
`DigestMismatch`; it is not retried because it indicates corruption or an
implementation fault rather than the explicitly detected basis race.

If even the budget-derived block policy cannot represent the basis within the
signature bound, xsync warns and degrades that entry to whole-file transfer
instead of failing it.

Commit order is: flush data, `sync_data` the temporary file, set ownership and
mode, set mtime, stage it under a recovery-visible name, then atomically rename
or exchange it with the destination. Successful replacement removes the old
planned inode; a race is rolled back when safe or retained under the recovery
name. Temporary cleanup compares stable device/inode/kind identity so partial
writes and mtime changes cannot defeat cleanup.

## 8. Metadata

New directories are created with a restrictive temporary mode and finalized
after children. Regular files, directories, and symlinks preserve mtime where
the platform supports it. File and directory permission bits are applied with
an explicit `mode & 0o0777`; setuid, setgid, and sticky bits are cleared for
both files and directories and produce a structured warning. A future opt-in
mode may preserve them after a separate privilege review. Ownership is unchanged unless
`--owner` or `--group` is selected. By default names are resolved on the
receiver, with numeric ID fallback plus a warning; `--numeric-ids` opts directly
into numeric mapping. Equal-time comparisons likewise use names when both are
available and otherwise fall back to numeric IDs. Ownership is applied before
final mode because `chown` may clear special bits. Permission failure produces
a structured warning and does not invalidate correct file content. Symlink
ownership/mtime operations use no-follow APIs.

## 9. Progress, diagnostics, and exit status

Protocol bytes always use stdout in agent mode. Controller human output and all
agent diagnostics use stderr.

Human progress uses a throttled single-line terminal redraw for active entries,
plus job counters and stable summaries. It reports logical, literal/reused
bytes, per-entry rate in binary units (`KiB/s`, `MiB/s`, and so on), and ETA
where meaningful, redraws no more than 10 times per second, and degrades to
newline events on non-interactive stderr. `auto` is
silent on non-TTY stderr unless `--verbose` is selected; `--quiet` wins over all
progress modes. `json` emits versioned JSON Lines with `session_start`,
`job_start`, `phase`, `entry_start`, `entry_progress`, `entry_summary`,
`entry_done`, `planned_operation`, `warning`, `conflict`, `job_error`, `job_done`,
`clock_skew_warning`, `remote_diagnostic`, terminal `error`, and
`session_done`. Transfer directions are consistently `local-to-remote` or
`remote-to-local`. Paths
include a display string and a lossless base64 form when needed. Secrets and the
full SSH command environment are never printed.
JSON progress is also written to stderr.

Exit statuses:

- `0`: all requested jobs completed without conflict or error (warnings alone
  do not change the status);
- `1`: at least one entry/job failed or conflicted after a valid session;
- `2`: command-line usage error;
- `3`: transport, handshake, or protocol failure.
- `130`: controller interrupted by SIGINT.

The SIGINT handler only sets an atomic cancellation flag. At a stream boundary,
the controller sends `AbortJob`. During an in-flight blocking stream, a watchdog
terminates the transport child, which unblocks pending I/O and makes the session
end rather than merely aborting the job. The controller removes its own known
temporaries and exits 130; stdin EOF makes the agent remove its own. End-to-end
tests require no known temporary on either peer after the child has exited.

## 10. Errors and resource limits

Errors are structured by class and include job and escaped path context. A
single entry I/O error is normally recoverable and allows independent work to
continue. Root access failures, containment violations, inconsistent manifests,
and protocol errors abort the job or session as appropriate.

Negotiated defaults include 16 MiB maximum frame size, 1 MiB literal chunks,
one million entries per job, 8 KiB path length, maximum relative directory depth
256, 512 MiB total manifest/plan memory, and 4 MiB signature memory. Intersected
literal, path, symlink-target, and inventory-diagnostic limits are reduced when
necessary to fit the selected frame; oversized values therefore fail as
structured job limits rather than fatal frame errors. Record arrays are capped
at 256 on both encode and decode as well as by encoded size. Abort reasons and
agent error diagnostics are UTF-8-safely truncated against their actual encoded
envelopes, so a long filesystem path cannot turn a recoverable job error into an
oversized-frame session failure. The byte ceilings are binding; entry counts and
depth are secondary guards. Both peers report an over-depth offending path as a
structured limit error before exhausting stack or file descriptors.
Manifest and delta streams are bounded. Plans may initially reside in memory;
exceeding a limit fails clearly instead of exhausting the host.

## 11. Security model

SSH provides peer authentication, confidentiality, and transport integrity.
The xsync protocol has no independent authentication. The agent trusts the SSH
account to request paths that account can access, but never trusts transported
relative paths. It validates lengths, state, paths, copy indices, and decoded
values. Filesystem/protocol operations do not invoke a shell, follow manifest symlinks, accept absolute
relative entries, or deserialize into unbounded containers.

Stock SSH servers run the remote command through the account's login shell, so
SSH offers no remote argv preservation. The controller treats the remote command
as a shell fragment solely for this transport boundary and POSIX-quotes the
user-supplied executable as one word before appending the fixed agent flag. This
is a correctness boundary rather than an additional privilege boundary: the SSH
account already has shell access. No directory, exclude, or protocol data is put
in that command; it travels only after the binary handshake.

## 12. Test strategy and acceptance criteria

Unit tests cover CLI grouping, exclusion semantics, path validation, manifest
ordering, planning matrices, frame bounds, handshake negotiation, state
transitions, rolling checksums, signature matching, delta reconstruction,
atomic/crash races, aggregate resource accounting, and progress schema fields.

Property tests generate old/new byte strings and assert that applying a delta
always yields the new bytes and digest, including repeated blocks and boundary
sizes. Malformed-frame and malformed-delta tests assert bounded clean failures.

Filesystem integration tests use temporary roots to cover bidirectional newer
wins, all one-sided cases, direction filtering, no deletion, conflicts, nested
directories, excludes, permissions, mtimes, symlinks, non-UTF-8 paths, atomic
replacement, interrupted transfers, and source/basis races where injectable
hooks permit deterministic simulation.

End-to-end tests spawn the built `xsync --agent` through piped stdio using a
fake SSH executable that joins the remote command arguments and executes them
through `sh -c`, matching OpenSSH semantics. They cover shell paths containing
spaces/quotes, a simulated login banner corrupting stdout, version incompatibility, multi-job
connection reuse, both transfer directions, delta reuse, progress modes,
remote errors, reduced negotiated frames, warnings/exit statuses, partial-data
interruption cleanup, and premature transport death without requiring SSH
credentials.

Release acceptance requires `cargo fmt --check`, strict `cargo clippy`, all unit
and integration tests, and successful debug and release builds.
