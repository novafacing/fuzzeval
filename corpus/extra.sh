#!/bin/bash

set -e

pushd /corpus/src
for f in "test_fuzzers_work"; do # "cgc"; do
    if [ -d "${f}" ]; then
        pushd "${f}"
        echo "Running extra script on $(pwd)"
        ./extra.sh
        popd
    fi
done
popd