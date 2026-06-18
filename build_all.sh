#!/bin/bash
set -e

BASE_DIR="$(pwd)"

echo "=== 1. Building Linux Native Version ==="
mkdir -p build/linux
cd build/linux
cmake ../..
make -j$(nproc)
cd ../..

echo "=== 2. Preparing Windows Dependencies ==="
bash scripts/build_windows_deps.sh

echo "=== 3. Building Windows Cross-Compiled Version ==="
rm -rf build/windows
mkdir -p build/windows
cd build/windows
cmake ../.. -DCMAKE_TOOLCHAIN_FILE=../../mingw-toolchain.cmake \
    -DOPENSSL_ROOT_DIR="${BASE_DIR}/windows_deps/openssl" \
    -DOPENSSL_USE_STATIC_LIBS=TRUE \
    -DOPENSSL_INCLUDE_DIR="${BASE_DIR}/windows_deps/openssl/include" \
    -DOPENSSL_CRYPTO_LIBRARY="${BASE_DIR}/windows_deps/openssl/lib64/libcrypto.a" \
    -DOPENSSL_SSL_LIBRARY="${BASE_DIR}/windows_deps/openssl/lib64/libssl.a"
make -j$(nproc) vcs_client
cd ../..

echo "=== 4. Copying Artifacts ==="
cp build/linux/vcs_server build/
cp build/linux/vcs_client build/
cp build/windows/vcs_client.exe build/

echo "Build complete! Check the 'build' directory."
