#!/bin/bash

set -e

pushd /corpus/src
for f in "cgc"; do # "cgc"; do
    if [ -d "${f}" ]; then
        pushd "${f}"
        echo "Running extra script on $(pwd)"
        ./extra.sh
        popd
    fi
done
popd