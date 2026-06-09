#!/bin/bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
HOST="${1:-127.0.0.1}"
PORT="${2:-9000}"
exec ./build/vcs_client --host "$HOST" --port "$PORT"
