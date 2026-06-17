#!/bin/bash
cd "$(dirname "$0")/.."
if [ ! -f "build/vcs_client" ]; then
    echo "Client binary not found. Please run scripts/build.sh first."
    exit 1
fi
./build/vcs_client "$@"
