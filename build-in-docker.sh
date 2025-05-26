#!/usr/bin/env bash

set -euo pipefail

repository="$(readlink -f "$(dirname "${0}")")"

tag="etcs-wireshark"

docker build \
    --file docker/Dockerfile \
    --tag "${tag}" \
    "${repository}"

rm -rf "${repository}/wireshark-config/my-plugins"
mkdir -p "${repository}/wireshark-config/my-plugins"

docker run \
    --rm \
    "${tag}" \
    tar -C /wireshark-plugin . -cf - |
    tar -C "${repository}/wireshark-config/my-plugins" -xf -
