#!/usr/bin/env bash
# Start warren-server locally using the Podman machine socket.
# Requires: podman machine start (run once after reboot)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PODMAN_SOCK="${WARREN_PODMAN_SOCKET:-/var/folders/db/bcp1n3fj09ng_c53xtk6pwwc0000gp/T/podman/podman-machine-default-api.sock}"

if [[ ! -S "$PODMAN_SOCK" ]]; then
  echo "Podman socket not found: $PODMAN_SOCK"
  echo "Run: podman machine start"
  exit 1
fi

mkdir -p "$HOME/.warren/server-data"

exec env \
  WARREN_PODMAN_SOCKET="$PODMAN_SOCK" \
  WARREN_DATA_DIR="$HOME/.warren/server-data" \
  WARREN_SECRET_KEY="${WARREN_SECRET_KEY:-local-dev-key-not-for-prod}" \
  WARREN_AUTH_TOKEN="${WARREN_AUTH_TOKEN:-local-dev-token}" \
  uv run --package warren-server --directory "$REPO" -- python -m warren
