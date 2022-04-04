#!/bin/bash

set -e

pushd /scripts/cgc-generate-polls/
./generate_all.sh "/corpus/src/cgc/"
popd

for f in *; do
    if [ -d "${f}" ]; then
        pushd "${f}"
        OUTDIR="../../../../build/cgc/${f}"
        echo "Building $(pwd)..."
        if [ -d "build" ]; then
            rm -rf build
        fi
        mkdir -p build
        pushd build
        cmake -DCMAKE_EXE_LINKER_FLAGS='-no-pie -fno-pie' ..
        make
        mkdir -p "${OUTDIR}/seeds/"
        cp "${f}" "${OUTDIR}/${f}"
        find . -type f -name '*.so' -exec cp '{}' "${OUTDIR}/" \;
        cp -a ../seeds/* "${OUTDIR}/seeds/"
        popd
        popd
    fi
done