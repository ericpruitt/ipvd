#!/bin/sh
set -e
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi
trap 'rm -r -f -- "$tempdir"' EXIT
tempdir="$(mktemp -d)"
if ! cp "$PWD/ipvd" "$tempdir"; then
    echo "Has 'make' been executed?" >&2
    exit 1
fi
chmod 500 "$tempdir/ipvd"
if ! chroot "$tempdir" "/ipvd" "$@"; then
    echo "Was ipvd compiled with '-static'?" >&2
    exit 1
fi
