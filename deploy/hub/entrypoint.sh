#!/bin/sh
set -eu
umask 077
data_dir="${HUB_DATA_DIR:-/data}"
mkdir -p "$data_dir"
# flock releases on exit, including SIGKILL. --no-fork lets Node receive the
# container's signals directly. Keep this entry point when mounting this volume.
exec flock --exclusive --nonblock --no-fork "$data_dir/.hub.lock" \
  node /app/deploy/hub/start.mjs
