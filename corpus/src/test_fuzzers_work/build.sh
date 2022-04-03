#!/bin/bash

set -e

OUTDIR=../../../../build/test_fuzzers_work/AIS-Lite/

pushd AIS-Lite
if [ -d "build" ]; then
    rm -rf build
fi
mkdir -p build
pushd build
cmake -DCMAKE_EXE_LINKER_FLAGS='-no-pie -fno-pie' ..
make

mkdir -p "${OUTDIR}/seeds/"
cp AIS-Lite "${OUTDIR}/AIS-Lite"
find . -type f -name '*.so' -exec cp '{}' "${OUTDIR}/" \;
cp -a ../seeds/* "${OUTDIR}/seeds/"

popd

popd
