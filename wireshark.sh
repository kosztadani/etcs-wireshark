#!/usr/bin/env bash

set -euo pipefail

repository="$(readlink -f "$(dirname "${0}")")"
export WIRESHARK_CONFIG_DIR="${repository}/wireshark-config"
export WIRESHARK_PLUGIN_DIR="${repository}/wireshark-config/my-plugins"

exec wireshark "$@"
