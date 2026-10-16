#!/usr/bin/env bash
# Runs the PRF probe for the household devices (RUNBOOK.md). Needs only Docker on the host.
#
#   ./serve.sh start <host-name> [port]   build, then serve https://<host-name>:<port>/ (default 8443)
#   ./serve.sh ca                         print the local CA certificate (PEM) to install on devices
#   ./serve.sh report                     print the per-credential table
#   ./serve.sh stop                       stop the server; the data volume is kept
#
# Certificates, registrations and records live in the Docker volume `vilicus-prf-probe-lan`,
# so a login days after the registration finds its credential. `docker volume rm` it when done.
set -euo pipefail

# rust:1-trixie (Debian 13), the same digest as run.sh and docker/compose.yaml.
RUST_IMAGE="rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a"
TARGET_VOLUME="vilicus-prf-probe-target"
DATA_VOLUME="vilicus-prf-probe-lan"
CONTAINER="vilicus-prf-probe-lan"
BINARY="/target/release/prf-probe"

SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
if HOST_DIR="$(cd "$SPIKE_DIR" && pwd -W 2>/dev/null)"; then
  export MSYS_NO_PATHCONV=1
else
  HOST_DIR="$SPIKE_DIR"
fi

in_data() {
  docker run --rm -v "$DATA_VOLUME:/data" -v "$TARGET_VOLUME:/target:ro" "$RUST_IMAGE" "$@"
}

case "${1:-}" in
  start)
    host="${2:?host name required, for example prf-probe.home.arpa}"
    port="${3:-8443}"
    docker volume create "$TARGET_VOLUME" >/dev/null
    docker run --rm \
      -v "$HOST_DIR:/spike:ro" \
      -v vilicus-spike-cargo-registry:/usr/local/cargo/registry \
      -v "$TARGET_VOLUME:/target" \
      -e CARGO_TARGET_DIR=/target \
      -w /spike \
      "$RUST_IMAGE" cargo build --locked --release --quiet
    docker run --detach --name "$CONTAINER" --restart unless-stopped \
      -p "$port:8443" \
      -v "$DATA_VOLUME:/data" \
      -v "$TARGET_VOLUME:/target:ro" \
      "$RUST_IMAGE" "$BINARY" serve 0.0.0.0:8443 /data "$host" "https://$host:$port" >/dev/null
    # The certificates are generated at first start; wait for the server's first line.
    for _ in $(seq 1 30); do
      if docker logs "$CONTAINER" 2>/dev/null | grep -q '^SERVER '; then
        docker logs "$CONTAINER" 2>/dev/null | grep -m1 '^SERVER '
        exit 0
      fi
      sleep 1
    done
    echo "the server did not start; docker logs $CONTAINER" >&2
    exit 1
    ;;
  ca)
    in_data cat /data/ca.crt
    ;;
  report)
    in_data "$BINARY" report /data
    ;;
  stop)
    docker stop "$CONTAINER" >/dev/null
    docker container rm "$CONTAINER" >/dev/null
    ;;
  *)
    sed -n '2,10p' "$0"
    exit 2
    ;;
esac
