#!/bin/bash

set -e


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
        mkdir -p "${OUTDIR}/seeds/good"
        mkdir -p "${OUTDIR}/seeds/empty"
        touch "${OUTDIR}/seeds/empty/empty"
        cp "${f}"* "${OUTDIR}/"
        find . -type f -name '*.so' -exec cp '{}' "${OUTDIR}/" \;
        # cp -a ../seeds/* "${OUTDIR}/seeds/"
        popd
        popd
    fi
done