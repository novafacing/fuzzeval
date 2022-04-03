#!/bin/bash

# Script that copies all the relevant AFL files from /AFLplusplus/ to $1

TARGET=$1

echo "Copying AFL to ${TARGET}..."

if [[ ! -d "${TARGET}" ]]; then
    mkdir -p "${TARGET}"
fi

cp /AFLplusplus/*.so "${TARGET}"
cp /AFLplusplus/afl-* "${TARGET}"