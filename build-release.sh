#!/usr/bin/env bash
#
# build-release.sh — build a static musl binary of Cairn and package it for
# distribution (a .tar.gz plus its .sha256). The release workflow
# (.github/workflows/release.yml) runs this and attaches the result to the
# GitHub release; run it locally to build the same bundle by hand.
#
# Usage:  ./build-release.sh
# Output: dist/cairn-v<version>-x86_64-unknown-linux-musl.tar.gz (+ .sha256)
#
# Requires the musl target:  rustup target add x86_64-unknown-linux-musl

set -euo pipefail

TARGET="x86_64-unknown-linux-musl"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Version comes straight from Cargo.toml, so the package name always matches.
VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
PKG="cairn-v${VERSION}-${TARGET}"
BIN="target/${TARGET}/release/cairn"

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
rm -rf "dist/${PKG}"

echo ""
echo "Done. Release assets:"
echo "  dist/${PKG}.tar.gz"
echo "  dist/${PKG}.tar.gz.sha256"
ls -lh "dist/${PKG}.tar.gz" "dist/${PKG}.tar.gz.sha256"
