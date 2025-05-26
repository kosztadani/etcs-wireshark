#!/usr/bin/env bash

set -euo pipefail

repository="$(readlink -f "$(dirname "${0}")")"
plugin_dir="${repository}/wireshark-config/my-plugins"

cd "${repository}" || {
    echo "Could not enter directory at \"${repository}\""
    exit 1
}

rm -rf build
mkdir -p build
pushd build
cmake .. \
    -DWIRESHARK_CUSTOM_PLUGIN_DIR="${plugin_dir}"
make
make copy_plugin_custom
