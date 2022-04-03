#!/bin/bash

set -e

for f in *; do
    if [ -d "${f}" ]; then
        pushd "${f}"
        ./build.sh
        popd
    fi
fi