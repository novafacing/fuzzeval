#!/bin/bash

set -e

OUTDIR=../../../build/

pushd AIS-Lite
cmake -DCMAKE_EXE_LINKER_FLAGS='-no-pie -fno-pie -static' -DBUILD_STATIC_LIBS=ON .
make
mkdir -p "${OUTDIR}"
cp AIS-Lite/AIS-Lite "${OUTDIR}"

popd
