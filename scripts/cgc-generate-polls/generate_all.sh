#!/bin/bash

set -e

CGC_DIR=$1

echo "Generating CGC seeds for CGC_DIR: ${CGC_DIR}"

mkdir -p "${CGC_DIR}/*/seeds/good"
mkdir -p "${CGC_DIR}/*/seeds/empty"
touch "${CGC_DIR}/*/seeds/empty/empty"
find "${CGC_DIR}" -type d -path '*/poller/for-*' -mindepth 3 -maxdepth 3 -exec bash -c \
    'python3 generate-polls --count 20 --duplicate 1 --repeat 1 --store_seed \
    "{}/machine.py" "{}/state-graph.yaml" $(printf "{}" | cut -d"/" -f-5)/seeds/good/' \;
exit 1