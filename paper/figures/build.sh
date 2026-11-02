#!/usr/bin/env bash
# Rebuild every figure from the checked-in result files, then verify the export
# contract and the main-text page budget. Run from any directory.
set -euo pipefail
cd "$(dirname "$0")"
make all
make page-budget
