#!/bin/bash
set -e

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE=awg-proxy
DIR=builds
LDFLAGS="-s -w -X main.version=$VERSION"

rm -rf "$DIR"
mkdir -p "$DIR"

echo "=== Version: $VERSION ==="
echo ""

# --- Binaries ---
echo "--- Binaries ---"
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64         go build -trimpath -ldflags="$LDFLAGS" -o "$DIR/$IMAGE-linux-arm64"   . &
CGO_ENABLED=0 GOOS=linux   GOARCH=arm   GOARM=7 go build -trimpath -ldflags="$LDFLAGS" -o "$DIR/$IMAGE-linux-arm"     . &
CGO_ENABLED=0 GOOS=linux   GOARCH=arm   GOARM=5 go build -trimpath -ldflags="$LDFLAGS" -o "$DIR/$IMAGE-linux-armv5"   . &
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64         go build -trimpath -ldflags="$LDFLAGS" -o "$DIR/$IMAGE-linux-amd64"   . &
CGO_ENABLED=0 GOOS=windows GOARCH=amd64         go build -trimpath -ldflags="$LDFLAGS" -o "$DIR/$IMAGE-windows-amd64.exe" . &
wait
echo "Binaries done"
echo ""

# --- OCI images ---
echo "--- OCI images ---"
for spec in "arm64:linux/arm64" "arm:linux/arm/v7" "armv5:linux/arm/v5" "amd64:linux/amd64"; do
  arch="${spec%%:*}"
  platform="${spec#*:}"
  docker buildx build --no-cache --platform "$platform" \
    --build-arg VERSION="$VERSION" \
    --output "type=oci,dest=$DIR/$IMAGE-$arch.tar" \
    -t "$IMAGE:$VERSION-$arch" . && gzip -f "$DIR/$IMAGE-$arch.tar" &
done
wait
echo "OCI images done"
echo ""

# --- Classic Docker (RouterOS 7.20 LT) ---
echo "--- Classic Docker (7.20) ---"
declare -A GOARMS=([arm64]="" [arm]="7" [armv5]="5" [amd64]="")
for arch in arm64 arm armv5 amd64; do
  VERSION=$VERSION scripts/mkdockertar.sh linux "${arch%v5}" "${GOARMS[$arch]}" \
    "$IMAGE:$VERSION-$arch" "$DIR/$IMAGE-$arch-7.20-Docker.tar.gz" &
done
wait
echo "Classic Docker images done"
echo ""

# --- Summary ---
echo "=== All 13 artifacts ==="
ls -lh "$DIR/"
