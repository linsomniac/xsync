#!/bin/sh
set -eu
if [ "${1-}" = "--" ]; then
    shift
fi
server=${1-}
if [ -z "$server" ]; then
    echo "fake ssh: missing server" >&2
    exit 64
fi
shift
if [ "$#" -ne 1 ]; then
    echo "fake ssh: expected one remote command" >&2
    exit 64
fi
if [ -n "${XSYNC_FAKE_COUNT_FILE-}" ]; then
    printf '1\n' >> "$XSYNC_FAKE_COUNT_FILE"
fi
exec sh -c "$1"
