#!/bin/bash

set -e

pushd src
for f in *; do
    if [ -d "${f}" ]; then
        pushd "${f}"
        echo "Running extra script on $(pwd)"
        ./extra.sh
        popd
    fi
done
popd