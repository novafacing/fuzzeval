#!/bin/bash

set -e

pushd AIS-Lite
cmake -DCMAKE_EXE_LINKER_FLAGS='-no-pie -fno-pie -static' -DBUILD_STATIC_LIBS=1 .
make
popd
