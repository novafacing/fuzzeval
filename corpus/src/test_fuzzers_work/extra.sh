#!/bin/bash

pushd /scripts/cgc-generate-polls
./generate_all.sh "/corpus/src/test_fuzzers_work"
popd