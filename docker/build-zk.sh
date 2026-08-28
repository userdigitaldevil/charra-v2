#!/usr/bin/env bash
#
# Builds the ZK prover image. Separate from docker/build.sh because it is a
# different image for a different architecture: the charra image is
# linux/amd64, this one is linux/arm64 so that bb can run natively.
#
# Takes about two minutes -- it downloads prebuilt toolchains rather than
# compiling anything. You need it only for TRUST_MODE=zk.
set -euo pipefail

IMAGE="${ZK_IMAGE:-charra-zk:arm64}"
PLATFORM="${ZK_PLATFORM:-linux/arm64}"

cd "$(dirname "$0")/.."
echo "Building $IMAGE for $PLATFORM ..."
docker build --platform "$PLATFORM" -t "$IMAGE" docker/zk

echo
docker run --rm --platform "$PLATFORM" "$IMAGE" bash -lc \
    'echo "  nargo: $(nargo --version | head -1)"; echo "  bb:    $(bb --version)"'
echo
echo "Done. TRUST_MODE=zk ./run_daemon.sh will start this image itself."
