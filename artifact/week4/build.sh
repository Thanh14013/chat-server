#!/bin/bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[*] Installing dependencies..."
sudo apt-get install -y build-essential cmake libssl-dev libsqlite3-dev nlohmann-json3-dev 2>/dev/null

echo "[*] Configuring..."
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release

echo "[*] Building..."
make -j$(nproc)

echo "[OK] Build complete: build/vcs_server  build/vcs_client  build/run_tests_*  build/benchmark"
