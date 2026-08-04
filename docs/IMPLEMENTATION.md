# xsync implementation guide and checklist

This guide turns [DESIGN.md](DESIGN.md) into independently reviewable vertical
slices. Every checked item has focused coverage and leaves the complete test
suite green. Claude Code reached consensus on the specification and guide, but
its implementation-stage reviews became unavailable at the account usage limit;
the final retry failed with API `ENOTIMP`. Three requested Ultra reviewers were
used for the implementation/final passes, and their actionable findings were
fixed and re-reviewed. This is the sole review-process exception recorded for
the release candidate.

## Engineering conventions

- One Rust workspace and one `xsync` binary; library modules hold testable logic.
- Stable Rust, Unix-first, and `#![forbid(unsafe_code)]` unless a narrowly
  reviewed no-follow filesystem primitive later proves impossible without it.
- Errors use typed library enums and contextual application reports; expected
  failures never panic.
- Protocol types are separate from filesystem types. All wire conversions are
  checked.
- Blocking filesystem and child-process I/O is acceptable in version 1. Jobs
  execute serially, while the two peer scans within one job overlap. The
  protocol remains streaming and memory-bounded.
- Dependencies should be few, maintained, and pinned through `Cargo.lock`.
- Filesystem authority uses safe `cap-std`/`cap-fs-ext` directory capabilities;
  `rustix` supplies safe per-component `O_NOFOLLOW|O_DIRECTORY` traversal,
  advisory locking, atomic rename/exchange, and no-follow ownership operations, and
  `signal-hook` supplies flag-only signal handling. Full-path resolve-then-mutate fallbacks are
  forbidden because they reintroduce symlink races.
- Tests use temporary directories and a fake transport; they never require a
  network or SSH credentials.

## Implemented module map

```text
src/
  main.rs          CLI entry and exit mapping
  lib.rs
  cli.rs           grouped argument parser and validated configuration
  error.rs         structured error taxonomy
  path.rs          Unix byte paths, validation, display escaping
  exclude.rs       compiled, symmetric exclusion rules
  manifest.rs      no-follow tree scan and metadata model
  planner.rs       deterministic reconciliation plan
  delta.rs         checksums, signatures, encoder, validation/application
  protocol.rs      wire messages, framing, negotiation, state validation
  filesystem.rs    contained receiver operations and metadata
  agent.rs         remote request loop
  controller.rs    transport, progress, jobs, and bidirectional orchestration
tests/
  cli_smoke.rs
  e2e.rs
  support/fake_ssh.*
```

## Checklist

### A. Project foundation

- [x] Create the Cargo package, library/binary structure, dependency policy,
      formatting/lint configuration, typed top-level errors, and smoke test.
- [x] Add CI-equivalent local commands and a short README with safety semantics
      and development instructions.

### B. CLI and paths

- [x] Implement the grouped CLI grammar, direction inheritance, SSH shell-word
      splitting, attached progress modes, modify-window/clock policy, ownership
      and `-a`/`--archive` shorthand, one-way per-path `--delete`
      flags, and every option in DESIGN section 2 including internal `--agent`;
      cover `--dest` default/relative/duplicate behavior, `--exclude`, `--dir`,
      `--`, leading-dash server rejection, overlap validation, help/version and
      their exit statuses, and every invalid grouping including no directory.
- [x] Implement lossless Unix relative-path representation, wire conversion,
      the 8 KiB limit, containment validation, display escaping, and hostile-path
      tests.
- [x] Implement symmetric exclusion matcher semantics for rooted `/`, trailing
      `/`, `*`, `?`, classes, and `**`, with no negation/ignore files.

### C. Manifest and planning

- [x] Implement deterministic no-follow manifest scanning for directories,
      regular files, symlinks, metadata, non-UTF-8 names, unsupported kinds, and
      exclusion pruning; enforce the entry-count and binding manifest-memory caps
      with structured limit errors. The reserved `.xsync.tmp.` prefix is always
      pruned, including stale debris, before user exclusions; visible
      `.xsync.recovery.*` artifacts become protected inventory barriers. Walk iteratively
      and enforce the depth cap so deep trees return a structured path error
      instead of stack overflow or file-descriptor exhaustion.
- [x] Implement job-root resolution/opening as an explicit directory-root or
      selected-entry capability. Directory roots reject symlinks below them;
      entry roots open the parent capability, retain the exact basename, target
      only logical `.`, and never expose siblings. Directory roots acquire a
      nonblocking exclusive advisory lock; entry roots acquire a shared parent
      lock so unrelated entry jobs coexist but a directory-root job on that
      parent is excluded. Per-target fingerprint and atomic-commit checks arbitrate
      same-entry writers. Cover busy, concurrent-target, and escaped-root cases.
- [x] Implement content digesting over a byte source plus source/destination
      fingerprint capture and revalidation (device, inode, kind, size, mtime).
- [x] Implement the full deterministic planning matrix, conflict/blocking rules,
      direction filters, metadata-only warnings, metadata finalization, and
      exhaustive unit tests; enforce the binding plan-memory ceiling. Planning is
      two-phase under `--checksum`: pass 1 returns an ordered ambiguous-path set,
      and digest resolution produces the final plan. Test equal/different digests
      and the checksum-off single-pass path, modify-window boundaries, and
      explicit unsupported-kind skip/report behavior.
- [x] Implement one-way receiver-only deletion planning, deepest-first delete
      order after transfers, job-root protection, subtree barrier protection,
      runtime suppression after earlier errors, and conditional metadata
      finalization for directories that survive failed deletion.

### D. Delta engine

- [x] Implement and test the rolling checksum, block-size policy, signatures,
      collision-safe strong verification, and signature-memory budget.
- [x] Implement streaming delta generation with bounded literal chunks, computing
      the final `DeltaTrailer` length/digest during the same source-file pass.
- [x] Implement validated reconstruction into a generic `Write` sink, rejecting
      invalid indices/lengths/output size while computing digest and byte count.
- [x] Implement and test fallback policy: a basis race retries whole-file once,
      signature-budget exhaustion warns and uses whole-file, and digest mismatch
      removes the temporary and fails without retry.
- [x] Add property and corruption tests, including repeated data, empty files,
      tails, shifted content, invalid copy indices, and output limits.

### E. Protocol and agent

- [x] Define the magic prologue and session nonce, versioned CBOR messages,
      bounded framing, request IDs, feature
      negotiation, clock-skew data, stream boundaries/drain behavior, and
      golden/negative codec tests. Implement every message and fixed-width field
      in DESIGN section 4.4, with a stable golden session-control frame, unique
      round-trip coverage for every message kind, and a single request-ID
      namespace across request/response streams.
- [x] Implement the agent state machine, handshake, multi-job lifecycle, clean
      EOF/error handling, `AbortJob`/`JobAborted` including drain-then-abort,
      and focused state/feature-matrix protocol tests.
- [x] Implement chunked manifest and delta/signature exchanges with negotiated
      resource limits, plus bounded chunked `DigestRequest`/`DigestResponse` for
      checksum ambiguity, with state-machine tests.
- [x] Negotiate `FEATURE_FILE_ROOT` and the path-root intent/actual-kind job
      messages without changing legacy directory message encodings. Validate
      directory and selected-entry manifest shapes independently, fail file jobs
      against older agents before beginning work, and turn existing root-kind
      mismatches into structural conflicts.
- [x] Negotiate `FEATURE_DELETE`, omit false delete fields for old path-root
      endpoints, bind delete authorization to the active job, validate exact
      receiver-manifest membership, and revalidate sender absence with the
      bounded `ValidateAbsent` request.

### F. Safe receiver filesystem operations

- [x] Implement root-confined, no-follow directory/symlink/file operations,
      exclusive sibling temporaries, cleanup guards, planned-destination
      revalidation, and atomic rename on the root capability from section C;
      drive generic reconstruction into the temporary and commit in the design's
      flush/sync-data/ownership/mode/mtime/recovery-stage/rename order. Provide test-only
      race hooks for source, destination, and basis mutation points. Exercise the
      capability's relative open/create/rename/symlink/remove/time APIs and prove
      an ancestor swapped to a symlink between plan and commit cannot redirect a
      write; assert in-progress temporary files are exclusively mode `0600`.
      Compare the reconstruction's running length/digest to the trailer before
      any commit.
- [x] Implement missing job-root policy: create only a directory root at
      provisional `0700` when direction permits, report `RootParentMissing`, and
      fail a missing read-only-side root. A selected-entry receiver opens and
      shared-locks its existing parent capability but does not create or `mkdir`
      the target until atomic commit, including dry-run. `Auto` adopts an existing remote type and
      retains legacy directory behavior when both sides are absent. Finalize
      empty-path directory roots with explicit tests.
- [x] Implement file/directory modes, mtimes, best-effort numeric ownership,
      special-bit masking, opt-in name/numeric ownership, reverse-depth
      directory/root finalization, and warning reporting.
- [x] Implement fingerprint-checked deletion by same-parent recovery rename,
      post-rename identity verification, non-recursive file/symlink unlink or
      directory emptiness preflight/`rmdir`, and `NOREPLACE` rollback. Protect
      recovery artifacts, excluded descendants, concurrent replacements, and all job roots.
- [x] Test symlink ancestors, replacement failures, interruption cleanup,
      metadata, and basis/source-change detection.

### G. Synchronization orchestration

- [x] Implement the transport-independent progress event model and stable
      summary so all orchestration work emits structured events from the start.
- [x] Implement local subprocess transport and configurable SSH transport with
      safe local tokenization and POSIX remote quoting, continuously drained
      stderr (`remote:` prefix, bounded queue, dropped-line count), corrupt-banner
      diagnosis, exit/error mapping, and shutdown behavior. Build the fake SSH
      executable here; it joins the remote command and uses `sh -c`, and proves
      quoting for program paths containing spaces and single quotes.
- [x] Implement controller session establishment: magic exchange and corrupt
      stdout diagnosis, `Hello`/`HelloAck` version/feature negotiation and
      required-feature checks, RTT-adjusted skew warning/refusal/override, and
      exit-3 mapping, tested with the in-memory duplex.
- [x] Implement controller job execution for local-to-remote whole/delta files,
      symlinks, directories, and metadata; issue the remote manifest request
      before local scanning so the agent inventories concurrently; drain the
      outstanding response if local inventory fails.
- [x] Between manifest comparison and final planning under `--checksum`, compute
      local digests and request bounded remote digests for exactly the pass-1
      ambiguous set; prove no digest request is sent when checksum mode is off.
- [x] Implement remote-to-local whole/delta files and the same receiver safety.
- [x] Wire bidirectional plans, conflicts, recoverable entry failures, dry-run,
      sequential multi-path reuse, and final exit status.
- [x] Implement SIGINT/EOF cancellation: drain or abort between streams,
      use a flag-only handler and watchdog to terminate an in-flight blocked
      transport, remove controller temporaries, rely on agent stdin EOF for its
      own cleanup, and map controller interruption to exit 130. Test that neither
      peer retains a known temporary after child exit.

### H. Progress and user experience

- [x] Implement throttled terminal rendering, non-TTY fallback, and versioned
      JSON Lines output with end-to-end schema/key/direction assertions.
- [x] Ensure agent stdout is protocol-only and diagnostics/progress never corrupt
      framing; test quiet/verbose behavior, corrupt stdout, EOF, and transport
      death.

### I. End-to-end hardening

- [x] Prove through the fake SSH harness that one agent session handles multiple
      path jobs without reconnecting.
- [x] Add end-to-end tests for all modes, newer-wins, one-sided copy/no deletion,
      conflict safety, excludes, metadata, symlinks, delta reuse, non-UTF-8 paths,
      missing-root creation/read-only/parent errors, clock-skew refusal/override,
      incompatible versions, corrupt banners, transport death, interruption
      (exit 130 and no temporary files), dry-run, and `--checksum` both detecting
      same-size/same-mtime divergence and confirming identical content as no-op.
- [x] Add one-way delete end-to-end coverage for inbound/outbound reconciliation,
      dry-run, excludes, nonempty-directory retention, recovery barriers, and
      required-feature refusal before mutation. Inject a sender appearance
      after inventory to prove absence revalidation and later-delete suppression.
- [x] Add selected-file root end-to-end coverage for exact-path creation,
      `--dest` rename semantics, inbound creation, newer-wins updates, dry-run,
      and file/directory root conflicts without mutation.
- [x] Assert the full exit matrix end to end: 0 including warnings-only, 1 for
      conflict/recoverable entry failure, 2 for usage, and 3 for handshake,
      corrupt-banner, and transport failures.
- [x] Add malformed/negative protocol tests and property/corruption delta tests; verify all
      negotiated bounds, including maximum directory depth, fail closed without
      panics or file-descriptor exhaustion.
- [x] Run formatting, strict clippy, the full test suite, and debug/release builds;
      reconcile README/help/spec behavior with the executable.

## Review loop and recorded exception

1. Implement the smallest coherent unchecked slice and its tests.
2. Run focused tests, then formatting and the complete suite.
3. Ask Claude Code to inspect the goal, design, checklist item, diff, and test
   evidence. Request only actionable correctness, safety, interoperability, or
   missing-test findings, classified by severity.
4. Fix valid findings and ask Claude to re-review. Stop when it explicitly says
   consensus/no critical or major findings, or after five rounds; after five
   rounds document any unresolved disagreement before proceeding.
5. Check the item and record any intentional design adjustment in the relevant
   document.

The specification/guide loop completed with Claude consensus. During the code
slices, Claude began returning its account usage-limit error, and the final
repository-wide retry could not connect to its API (`ENOTIMP`). Rather than
claiming reviews that did not occur, the implementation used the requested Ultra
reviewers iteratively; their final blockers drove the crash-recovery, bounded
framing, cancellation, mtime, progress, and documentation changes.

## Final verification

After all items are checked, compare the original prompt, design, guide,
executable help, tests, and behavior in one final review. This checklist is fully
checked, the Claude availability exception is documented above, and the version
1 release candidate requires the implementation tests plus final Ultra reviews
to have no unresolved critical or major finding.
