#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
  echo 'Error: no container command supplied' >&2
  exit 64
fi

uid="$(id -u)" || {
  echo 'Error: cannot determine container user' >&2
  exit 70
}
case "$uid" in
  ''|*[!0-9]*)
    echo 'Error: invalid container user ID' >&2
    exit 70
    ;;
esac

# Restrict newly created runtime files; do not chmod existing volumes.
umask 077
DATA_DIR="${DATA_DIR:-/app/data}"
export DATA_DIR
mkdir -p "$DATA_DIR"

if [ "$uid" = 0 ]; then
  chown node:node "$DATA_DIR"
  exec gosu node "$@"
fi

if [ ! -w "$DATA_DIR" ] || [ ! -x "$DATA_DIR" ]; then
  echo 'Error: DATA_DIR must be writable and searchable by the current user' >&2
  exit 73
fi

exec "$@"
