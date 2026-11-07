#!/bin/sh
set -eu
DATA_DIR="${DATA_DIR:-/app/data}"
export DATA_DIR
mkdir -p "$DATA_DIR"
chown node:node "$DATA_DIR"
exec gosu node "$@"
