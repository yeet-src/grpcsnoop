#!/usr/bin/env bash
# Tear down the two-container gRPC demo.
set -euo pipefail
cd "$(dirname "$0")"

DOCKER="docker"
docker info >/dev/null 2>&1 || DOCKER="sudo docker"

$DOCKER compose down
echo "[demo] down"
