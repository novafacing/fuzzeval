#!/bin/bash

set -e

if [ ! -z "${1}" ]; then
    CGC_DIR="${1}"
fi

echo "Generating CGC seeds for CGC_DIR: ${CGC_DIR}"

find "${CGC_DIR}" -type d -path '*/poller/for-*' -mindepth 3 -maxdepth 3 -exec bash -c \
    'export BINNAME="$(printf "{}" | cut -d "/" -f4-5)"; \
    echo "[+] Building seeds for ${BINNAME}"; \
    mkdir -p /corpus/build/${BINNAME}/seeds/good; \
    cd "/corpus/src/${BINNAME}"; \
    export CORPUS_ROOT="/corpus/build/cgc"; \
    if [[ -f "{}/state-graph.yaml" && -f "{}/machine.py" ]]; then \
        OUTPUT=$(python2 /scripts/cgc-generate-polls/generate-polls --count 20 --duplicate 1 --repeat 1 --store_seed \
        "{}/machine.py" "{}/state-graph.yaml" /corpus/build/${BINNAME}/seeds/good/ 2>&1); \
    else \
        OUTPUT=$(python2 /scripts/cgc-generate-polls/parse-polls "{}" "/corpus/build/${BINNAME}/seeds/good/"); \
    fi; \
    export NUMBUILT=$(ls "/corpus/build/${BINNAME}/seeds/good/" | grep -v png | grep -v dot | wc -l); \
    if [[ ${NUMBUILT} != 20 ]]; then \
        export STATCODE="[!]"; \
    else \
        export STATCODE="[+]"; \
    fi; \
    echo "${STATCODE}" Built $(ls "/corpus/build/${BINNAME}/seeds/good/" | grep -v png | grep -v dot | wc -l) seeds in \
    /corpus/build/${BINNAME}/seeds/good/
    if [[ ${NUMBUILT} != 20 ]]; then echo "${OUTPUT}"; fi;' \;