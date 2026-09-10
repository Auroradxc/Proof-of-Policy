#!/usr/bin/env bash
# Regenerate the verifier-only fixture: a COMPRESSED proof (verifiable by pop-verify
# without any prover) for a tiny policy, copied into circuits/testdata/audit_proof/.
#
# Usage:  SP1_PROVER=cpu bash scripts/make_audit_proof.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

WORK="$(mktemp -d)"
OUT="circuits/testdata/audit_proof"
mkdir -p "$OUT"

echo "building tiny vectors ..."
python3 - "$WORK" <<'EOF'
import json, sys, pathlib
sys.path.insert(0, '.')
from policydsl.compile import compile_policy
from policydsl.model import Policy, Rule
from policydsl.serialize import spec_to_rust_constraints
p = Policy("audit-fixture", "1", rules=[
    Rule("keyword_block", "kb", {"keywords": ["bad"]}),
    Rule("length_bound", "lb", {"min": 1, "max": 100}),
])
spec = compile_policy(p)
pathlib.Path(sys.argv[1], "vectors.json").write_text(json.dumps({"vectors": [{
    "name": "audit-fixture", "response": "hello world",
    "constraints": spec_to_rust_constraints(spec)}]}))
EOF

echo "proving (compressed; this is the slow step) ..."
SP1_PROVER=cpu ./circuits/target/release/pop-script \
  --vectors "$WORK/vectors.json" --out "$WORK/results.json" \
  --proof-out "$WORK/proof.bin" --proof-mode compressed

echo "copying artifacts to $OUT ..."
cp "$WORK/proof.bin" "$OUT/proof.bin"
cp "$WORK/proof.bin.bytes" "$OUT/proof.bytes"
cp "$WORK/proof.bin.pv" "$OUT/proof.pv"
cp "$WORK/proof.bin.vkh" "$OUT/proof.vkh"
cp "$WORK/proof.bin.meta.json" "$OUT/proof.meta.json"

# rewrite the sidecar to point at the copied files (relative names)
python3 - "$WORK/proof.bin.verify.json" "$OUT/proof.verify.json" "$OUT" <<'EOF'
import json, sys, pathlib
src, dst, outdir = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])
meta = json.loads(pathlib.Path(src).read_text())
meta["proof_bytes_file"] = str(outdir / "proof.bytes")
meta["public_values_file"] = str(outdir / "proof.pv")
meta["vkey_hash_file"] = str(outdir / "proof.vkh")
pathlib.Path(dst).write_text(json.dumps(meta, indent=2))
print("wrote", dst)
EOF

echo "done. Fixture in $OUT:"
ls -la "$OUT"
