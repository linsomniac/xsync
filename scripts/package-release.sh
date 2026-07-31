#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 TARGET [DEBIAN_ARCH]" >&2
    exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage

target=$1
debian_arch=${2:-}
repo_root=$(git rev-parse --show-toplevel)
target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}
if [[ $target_dir != /* ]]; then
    target_dir="$repo_root/$target_dir"
fi

manifest_version=$(awk '
    /^\[package\]$/ { in_package = 1; next }
    /^\[/ && in_package { exit }
    in_package && $1 == "version" {
        gsub(/"/, "", $3)
        print $3
        exit
    }
' "$repo_root/Cargo.toml")

[[ -n $manifest_version ]] || {
    echo "could not read package version from Cargo.toml" >&2
    exit 1
}
if [[ -n ${VERSION:-} && $VERSION != "$manifest_version" ]]; then
    echo "VERSION $VERSION does not match Cargo.toml version $manifest_version" >&2
    exit 1
fi
version=$manifest_version
binary="$target_dir/$target/release/xsync"
[[ -x $binary ]] || {
    echo "release binary not found: $binary" >&2
    exit 1
}

dist="$repo_root/dist"
mkdir -p "$dist"
stage=$(mktemp -d "${TMPDIR:-/tmp}/xsync-package.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT

archive_name="xsync-${version}-${target}"
archive_root="$stage/$archive_name"
mkdir -p "$archive_root"
cp "$binary" "$archive_root/xsync"
chmod 0755 "$archive_root/xsync"
cp "$repo_root/README.md" "$repo_root/LICENSE" "$archive_root/"
if command -v strip >/dev/null 2>&1; then
    strip "$archive_root/xsync" 2>/dev/null || true
fi

archive="$dist/$archive_name.tar.gz"
rm -f -- "$archive"
tar -C "$stage" -czf "$archive" "$archive_name"

if [[ -n $debian_arch ]]; then
    command -v dpkg-deb >/dev/null 2>&1 || {
        echo "dpkg-deb is required to build a Debian package" >&2
        exit 1
    }
    case $debian_arch in
        amd64 | arm64) ;;
        *)
            echo "unsupported Debian architecture: $debian_arch" >&2
            exit 2
            ;;
    esac

    deb_root="$stage/deb"
    mkdir -p \
        "$deb_root/DEBIAN" \
        "$deb_root/usr/bin" \
        "$deb_root/usr/share/doc/xsync"
    cp "$archive_root/xsync" "$deb_root/usr/bin/xsync"
    chmod 0755 "$deb_root/usr/bin/xsync"
    cp "$repo_root/README.md" "$deb_root/usr/share/doc/xsync/README.md"
    cp "$repo_root/LICENSE" "$deb_root/usr/share/doc/xsync/copyright"
    chmod 0644 "$deb_root/usr/share/doc/xsync/README.md" \
        "$deb_root/usr/share/doc/xsync/copyright"
    installed_size=$(du -sk "$deb_root/usr" | awk '{ print $1 }')

    cat >"$deb_root/DEBIAN/control" <<EOF
Package: xsync
Version: $version
Section: utils
Priority: optional
Architecture: $debian_arch
Maintainer: xsync contributors <linsomniac@users.noreply.github.com>
Installed-Size: $installed_size
Depends: libc6 (>= 2.35), libgcc-s1
Homepage: https://github.com/linsomniac/xsync
Description: stateless bidirectional directory synchronization over SSH
 xsync synchronizes multiple directory trees over one SSH connection and uses
 an rsync-style delta algorithm while preserving conflict safety.
EOF
    chmod 0644 "$deb_root/DEBIAN/control"

    deb="$dist/xsync_${version}_${debian_arch}.deb"
    rm -f -- "$deb"
    dpkg-deb --root-owner-group --build "$deb_root" "$deb"
fi

printf 'created %s\n' "$archive"
if [[ -n $debian_arch ]]; then
    printf 'created %s\n' "$deb"
fi
