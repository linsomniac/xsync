# xsync

`xsync` is a Unix-first, stateless bidirectional directory synchronizer. It
reuses one SSH connection for multiple directory jobs and transfers changed file
regions with an rsync-style rolling-checksum algorithm.

```text
xsync SERVER [GLOBAL_OPTIONS] DIR [DIRECTORY_OPTIONS]...
```

The default direction is `in-out`; `--in` and `--out` restrict which side may be
a source. The newer mtime wins. A path found on only one side is copied when its
direction is permitted—it is never interpreted as a deletion. Equal-time
divergent files and entry-kind collisions are reported as conflicts without
overwriting either side. Symlinks are copied as symlinks and never traversed.

This first release is intentionally stateless and non-deleting. It is not rsync
wire-compatible and does not preserve hard-link topology, ACLs, xattrs, sparse
layout, or special files. Modes and mtimes are preserved; owner/group
preservation is opt-in because IDs and account names often differ between hosts.
See [the design specification](docs/DESIGN.md) for the complete safety and
conflict model.

Examples:

```sh
xsync host.example /home/me/src --exclude target --exclude .git
xsync backup --out /srv/photos --dest /data/photos /etc --dest /archive/etc
xsync laptop --progress=json /home/me/notes
xsync laptop --dry-run /home/me/notes
```

Use `--dry-run` to print each operation xsync would perform without modifying
either side. Combine it with `--progress=json` for machine-readable planned
operation events.

The remote host must have `xsync` installed. Use `--ssh 'ssh -p 2222'` to
customize transport or `--remote-program /path/to/xsync` to select its binary.

## Development

The CI-equivalent local checks are:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build
cargo build --release
```

Tests use a fake SSH transport and never need an SSH account or network access.
The implementation checklist is tracked in [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md).

## Releases

CI checks formatting, Clippy, tests, release builds, and the Rust 1.85 minimum
supported version. A tag matching the package version, such as `v0.1.0`, starts
the release workflow. It publishes Linux amd64/arm64 binary archives and Debian
packages, macOS Intel/Apple-Silicon binary archives, and a `SHA256SUMS` file to
the corresponding GitHub Release. The workflow can also be rerun manually for
an existing tag.
