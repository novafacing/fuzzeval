#!/bin/bash

set -e

pushd src
for f in *; do
    if [ -d "${f}" ]; then
        pushd "${f}"
        echo "Building $(pwd)"
        ./build.sh
        popd
    fi
done
popd