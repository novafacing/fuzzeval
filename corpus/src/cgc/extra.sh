#!/bin/bash

pushd /scripts/cgc-generate-polls/
echo "Generating all for /corpus/src/cgc"
./generate_all.sh "/corpus/src/cgc/"
popd