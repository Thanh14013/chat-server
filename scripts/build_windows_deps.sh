#!/bin/bash
set -e

DEPS_DIR="$(pwd)/windows_deps"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

if [ ! -d "openssl-3.1.4" ]; then
    echo "Downloading OpenSSL 3.1.4..."
    wget -qO- https://github.com/openssl/openssl/releases/download/openssl-3.1.4/openssl-3.1.4.tar.gz | tar xz
fi

cd openssl-3.1.4
if [ ! -f "libssl.a" ]; then
    echo "Configuring OpenSSL for mingw64..."
    ./Configure mingw64 no-shared --cross-compile-prefix=x86_64-w64-mingw32- --prefix="$DEPS_DIR/openssl"
    echo "Building OpenSSL..."
    make -j$(nproc)
    make install_sw
fi
echo "OpenSSL cross-compilation done."
