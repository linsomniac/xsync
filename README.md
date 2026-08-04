# xsync

`xsync` is a stateless bidirectional file and directory synchronizer.
Note: Because it is stateless, it cannot bi-directionally sync delete
operations.  Effectively, it is "flood fill".  In the "--in" and "--out"
modes, it can be directed to delete files.

It reuses one SSH connection for multiple path jobs and transfers changed
file regions with an rsync-style rolling-checksum algorithm.

```text
xsync SERVER [GLOBAL_OPTIONS] PATH [PATH_OPTIONS]...
```

The default direction is `in-out`; `--in` and `--out` restrict which side may be
a source. The newer mtime wins. A path found on only one side is copied when its
direction is permitted. Add the per-path `--delete` option to a one-way
`--in` or `--out` directory job to delete receiver-only entries. Equal-time
divergent files and entry-kind collisions are reported as conflicts without
overwriting either side. Symlinks are copied as symlinks and never traversed.

It is not rsync wire-compatible and does not preserve hard-link topology,
ACLs, xattrs, sparse layout, or special files. Modes and mtimes are
preserved; owner/group preservation is opt-in because IDs and account names
often differ between hosts. `-a` / `--archive` is shorthand for this program's
`--owner --group`; it does not add ACL, xattr, hard-link, device, or other rsync
archive features. See [the design specification](docs/DESIGN.md)
for the complete safety and conflict model.

Examples:

```sh
xsync host.example /home/me/src --exclude target --exclude .git
xsync backup --out /srv/photos --dest /data/photos /etc --dest /archive/etc
xsync laptop --progress=json /home/me/notes
xsync laptop -n /home/me/notes
xsync backup --out /tmp/package.deb --dest /srv/incoming/package.deb
xsync backup --out /srv/published --dest /srv/mirror --delete
xsync backup -a --out /srv/photos --dest /data/photos
```

A regular file or symlink operand is synchronized as that one exact path; xsync
does not scan its siblings. For a file job, `--dest` names the exact remote file
rather than a containing directory, so it can also rename the file. An existing
file-versus-directory mismatch is a conflict and neither side is overwritten.
Because excludes apply below directory roots, they do not filter an explicitly
selected file or symlink root.

`--delete` is valid only after a path whose effective direction is exactly
`--in` or `--out`. It never deletes the job root itself, so it has no additional
effect on a direct file or symlink job and a missing sending root remains an
error; xsync warns that the flag has no additional effect. Excluded entries are
not deleted. If an excluded descendant keeps a receiver-only directory
nonempty, xsync retains that directory with a warning before moving it. A child
created in the later race window makes xsync restore the directory and report a
recoverable failure instead of removing it recursively.
Deletion is fingerprint-checked, runs only after non-delete work, and is
suppressed after an earlier operation fails. `.xsync.recovery.*` artifacts are
protected and require manual inspection.

Use `-n` or `--dry-run` to print each operation xsync would perform without
modifying either side. Combine it with `--progress=json` for machine-readable
planned operation events. Human progress displays transfer rates with binary
units such as `KiB/s` and `MiB/s`; JSON retains numeric bytes per second.

The remote host must have `xsync` installed. Use `--ssh 'ssh -p 2222'` to
customize transport or `--remote-program /path/to/xsync` to select its binary.

## Nix and NixOS

The repository is a flake with packages for x86_64 and ARM64 Linux and macOS.
Run xsync without installing it, or install it into your user profile:

```sh
nix run github:linsomniac/xsync -- --help
nix profile install github:linsomniac/xsync
```

For a flake-based NixOS configuration, add xsync as an input:

```nix
{
  inputs.xsync.url = "github:linsomniac/xsync";

  outputs = { nixpkgs, xsync, ... }: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ({ pkgs, ... }: {
          environment.systemPackages = [
            xsync.packages.${pkgs.stdenv.hostPlatform.system}.default
          ];
        })
      ];
    };
  };
}
```

An overlay is also available as `xsync.overlays.default`, exposing the package
as `pkgs.xsync`. Install xsync on both the initiating and SSH endpoint machines;
their protocol versions must be compatible.

For development, `nix develop` provides Rust, Cargo, rustfmt, Clippy, and
rust-analyzer. `nix flake check` builds the package and runs its test suite;
use the Cargo commands below for formatting and Clippy checks.

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

## License

This project is dedicated to the public domain under the
[CC0 1.0 Universal](LICENSE) public domain dedication.

## Releases

CI checks formatting, Clippy, tests, release builds, and the Rust 1.88 minimum
supported version. A tag matching the package version, such as `v0.1.0`, starts
the release workflow. It publishes Linux amd64/arm64 binary archives and Debian
packages, macOS Intel/Apple-Silicon binary archives, and a `SHA256SUMS` file to
the corresponding GitHub Release. The workflow can also be rerun manually for
an existing tag.
