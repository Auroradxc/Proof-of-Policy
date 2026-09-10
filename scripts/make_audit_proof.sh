#!/usr/bin/env bash
# 重新生成「仅验证器」用的固定装置（fixture）：针对一条极小策略产出一份
# COMPRESSED 证明（可被 pop-verify 在完全没有 prover 的情况下验证），
# 并拷贝到 circuits/testdata/audit_proof/。
#
# 用法：  SP1_PROVER=cpu bash scripts/make_audit_proof.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

WORK="$(mktemp -d)"
OUT="circuits/testdata/audit_proof"
mkdir -p "$OUT"

# 用内联 Python 生成极小输入：2 条规则 + 一句无命中的短响应（保证 passed=true）
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

# --proof-mode compressed：产物小、且验证端不需要 prover（fixture 的关键前提）
echo "proving (compressed; this is the slow step) ..."
SP1_PROVER=cpu ./circuits/target/release/pop-script \
  --vectors "$WORK/vectors.json" --out "$WORK/results.json" \
  --proof-out "$WORK/proof.bin" --proof-mode compressed

# 把出证产生的全部旁路产物一起入库，验证方只靠这些文件即可离线校验
echo "copying artifacts to $OUT ..."
cp "$WORK/proof.bin" "$OUT/proof.bin"
cp "$WORK/proof.bin.bytes" "$OUT/proof.bytes"
cp "$WORK/proof.bin.pv" "$OUT/proof.pv"
cp "$WORK/proof.bin.vkh" "$OUT/proof.vkh"
cp "$WORK/proof.bin.meta.json" "$OUT/proof.meta.json"

# 重写 sidecar 里的路径，指向拷贝后的文件（用相对名，避免带出本机绝对路径）
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
