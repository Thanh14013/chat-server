#!/bin/bash
cd "$(dirname "$0")/.."
if [ ! -f "build/vcs_server" ]; then
    echo "Server binary not found. Please run scripts/build.sh first."
    exit 1
fi
./build/vcs_server
