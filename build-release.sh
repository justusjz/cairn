#!/usr/bin/env bash
#
# build-release.sh — build a static musl binary of Cairn and package it for
# distribution (a .tar.gz plus its .sha256). The release workflow
# (.github/workflows/release.yml) runs this and attaches the result to the
# GitHub release; run it locally to build the same bundle by hand.
#
# It builds for the machine's own architecture (x86_64 or aarch64); the
# workflow runs it once on each. It also leaves the bare binary in
# dist/<arch>/cairn, with Docker's name for the architecture (amd64 or arm64),
# which is where the Dockerfile takes it from.
#
# Usage:  ./build-release.sh
# Output: dist/cairn-v<version>-<arch>-unknown-linux-musl.tar.gz (+ .sha256)
#         dist/<amd64|arm64>/cairn
#
# Requires the musl target, e.g.:  rustup target add x86_64-unknown-linux-musl
# and Node.js 26 or later (with npm), to build the dashboard's UI.

set -euo pipefail

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64) DOCKER_ARCH=amd64 ;;
    aarch64) DOCKER_ARCH=arm64 ;;
    *) echo "ERROR: unsupported architecture $ARCH" >&2; exit 1 ;;
esac
TARGET="${ARCH}-unknown-linux-musl"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Version comes straight from Cargo.toml, so the package name always matches.
VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
PKG="cairn-v${VERSION}-${TARGET}"
BIN="target/${TARGET}/release/cairn"

# The dashboard's UI is embedded in the binary, which doesn't build without it.
# A fresh build, so that the release never ships a stale one.
echo "Building the dashboard UI..."
(cd ui && npm ci && npm run build)

echo "Building cairn v${VERSION} for ${TARGET}..."
cargo build --release --locked --target "$TARGET"

# A musl build links crt-static by default, so the result should have no dynamic
# dependencies. Verify it, since a non-static binary defeats the whole point.
if ! ldd "$BIN" 2>&1 | grep -q "statically linked\|not a dynamic executable"; then
    echo "ERROR: $BIN is not statically linked:" >&2
    ldd "$BIN" >&2 || true
    exit 1
fi

echo "Packaging dist/${PKG}.tar.gz..."
rm -rf "dist/${PKG}" "dist/${PKG}.tar.gz" "dist/${PKG}.tar.gz.sha256"
mkdir -p "dist/${PKG}"
install -m755 "$BIN" "dist/${PKG}/cairn"
strip "dist/${PKG}/cairn"

# Ship the license and notice alongside the binary.
install -m644 LICENSE NOTICE README.md "dist/${PKG}/"

tar -C dist -czf "dist/${PKG}.tar.gz" "$PKG"
(cd dist && sha256sum "${PKG}.tar.gz" > "${PKG}.tar.gz.sha256")
rm -rf "dist/${DOCKER_ARCH}"
mkdir -p "dist/${DOCKER_ARCH}"
mv "dist/${PKG}/cairn" "dist/${DOCKER_ARCH}/cairn"
rm -rf "dist/${PKG}"

echo ""
echo "Done. Release assets:"
echo "  dist/${PKG}.tar.gz"
echo "  dist/${PKG}.tar.gz.sha256"
echo "and the binary for the Docker image: dist/${DOCKER_ARCH}/cairn"
ls -lh "dist/${PKG}.tar.gz" "dist/${PKG}.tar.gz.sha256"
