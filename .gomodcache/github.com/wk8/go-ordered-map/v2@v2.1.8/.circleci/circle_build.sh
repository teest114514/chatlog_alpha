#!/usr/bin/env bash

set -ex

# might as well run a little longer
export FUZZ_TIME=20s

# there are too many golangci plugins that don't work for 1.19 just yet, so just skip linting for it
if [[ "$GO_VER" == 1.18.* ]]; then
  make
else
  make test_with_fuzz
fi
