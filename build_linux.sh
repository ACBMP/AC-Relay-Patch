#!/bin/sh

# cross-compile from lin to win (same toolchain as acb2's build_linux.sh)
# compile-check only: clang-cl accepts things real MSVC rejects (e.g. C2712,
# __try next to objects with destructors), and acb2 found the resulting .asi
# doesn't work in-game. Build the real one with build_windows.bat.

set -e

PROJECT_DIR="$(pwd)"

IMAGE="registry.gitlab.com/superewald/llwin:17-debug-wine"
CONFIG="${1:-Release}"

echo "building ac_relay ($CONFIG) in $PROJECT_DIR..."

docker run --rm \
    -v "$PROJECT_DIR:/src" \
    -w /src \
    "$IMAGE" \
    sh -c "
        wmake -B build/$CONFIG -A Win32
        cmake --build build/$CONFIG -j\$(nproc)
    "

echo ""
echo "build complete: build/$CONFIG/bin/ac_relay.asi"
