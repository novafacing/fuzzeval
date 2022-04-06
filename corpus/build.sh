#!/bin/bash

set -e

pushd /corpus/src
for f in "test_fuzzers_work" "cgc"; do
    echo "Building corpus ${f}"
    if [ -d "${f}" ]; then
        pushd "${f}"
        echo "Building $(pwd)"
        ./build.sh
        popd
    fi
done
popd