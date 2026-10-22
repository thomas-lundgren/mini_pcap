#!/usr/bin/env bash
# Builds the benchmark workload tool for the phone (arm64) and the host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NDK="${ANDROID_NDK:-$HOME/Android/Sdk/ndk/27.2.12479018}"
cmake -S "$ROOT/native" -B "$ROOT/native/build-nettool-android" -G Ninja -DMPC_TOOLS_ONLY=ON \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-29 -DCMAKE_BUILD_TYPE=Release >/dev/null
ninja -C "$ROOT/native/build-nettool-android" nettool >/dev/null
cmake -S "$ROOT/native" -B "$ROOT/native/build-nettool-host" -G Ninja -DMPC_TOOLS_ONLY=ON -DCMAKE_BUILD_TYPE=Release >/dev/null
ninja -C "$ROOT/native/build-nettool-host" nettool >/dev/null
adb push "$ROOT/native/build-nettool-android/nettool" /data/local/tmp/nettool >/dev/null && adb shell chmod 755 /data/local/tmp/nettool
echo "host: $ROOT/native/build-nettool-host/nettool   phone: /data/local/tmp/nettool"
