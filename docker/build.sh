#!/usr/bin/env bash

set -euo pipefail

if [[ $# -eq 2 && "${1}" = "linux" ]]; then
    platform="${1}"
    platform_options=()
elif [[ $# -eq 2 && "${1}" == "mingw" ]]; then
    platform="${1}"
    platform_options=(
        -DCMAKE_TOOLCHAIN_FILE=/src/mingw.cmake
    )
else
    echo "Usage: ./build.sh <linux|mingw> <major.minor>" >&2
    exit 1
fi

target_version="${2}" # major.minor, e.g., "4.4"

cd /src/plugin/
rm -rf build
mkdir -p build
cd build
cmake \
    "${platform_options[@]}" \
    -DCMAKE_PREFIX_PATH="/wireshark/${platform}-${target_version}" \
    -DWIRESHARK_CUSTOM_PLUGIN_DIR="/wireshark-plugin" \
    ..
make
make copy_plugin_custom
