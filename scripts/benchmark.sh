#!/bin/bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOST="${1:-127.0.0.1}"
PORT="${2:-9000}"
SCENARIO="${3:-0}"

if [ ! -f ./build/benchmark_load ]; then
    echo "[!] benchmark_load binary not found. Run scripts/build.sh first."
    exit 1
fi

echo "[*] Starting benchmark against $HOST:$PORT scenario=$SCENARIO"
./build/benchmark_load --host "$HOST" --port "$PORT" --scenario "$SCENARIO" | tee docs/BENCHMARK_RESULTS.md
echo "[*] Results saved to docs/BENCHMARK_RESULTS.md"
