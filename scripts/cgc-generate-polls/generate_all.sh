#!/bin/bash

set -e

CGC_DIR=$1

echo "Generating CGC seeds for CGC_DIR: ${CGC_DIR}"

find "${CGC_DIR}" -type d -path '*/poller/for-*' -mindepth 3 -maxdepth 3 -exec bash -c \
    'mkdir -p /corpus/build/$(printf "{}" | cut -d"/" -f4-5)/seeds/good; \
    python2 /scripts/cgc-generate-polls/generate-polls --count 20 --duplicate 1 --repeat 1 --store_seed \
    "{}/machine.py" "{}/state-graph.yaml" /corpus/build/$(printf "{}" | cut -d"/" -f4-5)/seeds/good/; \
    echo built seeds in /corpus/build/$(printf "{}" | cut -d"/" -f4-5)/seeds/good/' \;