#!/bin/bash

set -e

pushd /corpus/src
for f in "cgc"; do #  "cgc"; do
    echo "Building corpus ${f}"
    if [ -d "${f}" ]; then
        pushd "${f}"
        echo "Building $(pwd)"
        ./build.sh
        popd
    fi
done
popd