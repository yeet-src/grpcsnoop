#!/usr/bin/env bash
# Spin up the two-container gRPC demo. Builds the image, creates the bridge
# network, and starts the server + looping client.
#
#   bash demo/up.sh          # (auto-uses sudo for docker if needed)
set -euo pipefail
cd "$(dirname "$0")"

# Use sudo for docker only if the daemon isn't reachable as the current user.
DOCKER="docker"
if ! docker info >/dev/null 2>&1; then
  DOCKER="sudo docker"
  echo "[demo] docker needs root on this host — using sudo"
fi

$DOCKER compose up --build -d

echo
echo "[demo] containers:"
$DOCKER compose ps
echo
echo "[demo] server logs:  $DOCKER compose logs -f server"
echo "[demo] client logs:  $DOCKER compose logs -f client"
echo
echo "Inspect the gRPC/protobuf traffic (from the repo root) with:"
echo "    yeet run . --port 50051"
echo
echo "Tear down with:  bash demo/down.sh"
