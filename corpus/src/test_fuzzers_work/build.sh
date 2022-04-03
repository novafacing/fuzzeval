#!/bin/bash

set -e

OUTDIR=../../../../build/AIS-Lite/

pushd AIS-Lite
if [ -d "build" ]; then
    rm -rf build
fi
mkdir -p build
pushd build
cmake -DCMAKE_EXE_LINKER_FLAGS='-no-pie -fno-pie -static' -DBUILD_STATIC_LIBS=ON ..
make
mkdir -p "${OUTDIR}"
cp AIS-Lite "${OUTDIR}"
popd

popd
