#!/usr/bin/env bash
# Rebuild every VA figure from the checked-in sources/results, verify the
# export contract, then run the page-neutral placement test.
set -euo pipefail
cd "$(dirname "$0")"
make all
make placement
