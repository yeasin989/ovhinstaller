#!/bin/bash
set -e

echo "[*] Installing build dependencies..."
apt update
apt install -y build-essential autoconf automake libtool pkg-config \
    libgnutls28-dev libseccomp-dev libwrap0-dev libpam0g-dev liboath-dev \
    libxml2-dev liblz4-dev libhttp-parser-dev libreadline-dev \
    gperf libnsl-dev libev-dev libpthread-stubs0-dev git

echo "[*] Cloning ocserv source..."
cd /usr/src
rm -rf ocserv
git clone https://gitlab.com/openconnect/ocserv.git
cd ocserv

echo "[*] Building ocserv from source..."
./autogen.sh
./configure --prefix=/usr --enable- socket-activation
make -j$(nproc)
make install

echo "[*] Verifying build..."
ocserv --version | grep socket-control && echo "✅ Socket-control enabled!" || echo "❌ Still missing socket-control."

echo "[*] Done. You can now restart ocserv with a valid config and socket path."
