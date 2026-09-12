#!/usr/bin/env python3
"""阶段三·语义规则：ezkl 编译 / 出证 / 验证（P2-9 §9.3）。

语义规则（P2-9 的 D3 决策：完整 ezkl 集成）证明的是「响应 ``T`` 经**确定性特征图**
算出的 ``P(有害)`` 越过/低于某阈值」。与 SP1 侧的 ``semantic_bound`` 是**委托**关系：
SP1 电路证明不了语义规则（logit 不在它的公开值里），于是由这条 ezkl 陪伴证明承担，
验证方把两者**合取**（见 ``policydsl/cert.py`` 与 ``docs/design-semantic-rules.md``）。

流水线（每一步的产物都落 ``semantic/artifacts/``）：

```
model.onnx ──gen_settings──▶ settings.json ──patch_settings──▶ settings.json ✓口径
           ──compile──▶ model.compiled ──gen_srs──▶ kzg.srs
           ──setup──▶ vk.ezkl + pk.ezkl
T ──encode(T)──▶ ids ──gen_witness──▶ witness ──prove──▶ proof.json ──verify──▶ True
```

用法：

```
python3 scripts/ezkl_prove.py setup                       # 一次性：编译 + 赋键（重）
python3 scripts/ezkl_prove.py prove --response reply.txt  # 出证（必须与 setup 分进程）
python3 scripts/ezkl_prove.py verify --proof proof.json --response reply.txt
python3 scripts/ezkl_prove.py selftest                    # 端到端自检（含同形异义反例）
python3 scripts/ezkl_prove.py info                        # 只看产物清单与规模
```

**为什么 ``setup`` 与 ``prove`` 必须分进程**：本机实测 prove 的峰值常驻内存是
**9.17 GB**（12 GB 机器），而 ``setup`` 自身峰值 5.24 GB。同一进程里连着跑，两次
峰值叠加就把机器打爆了。脚本因此把每个子命令设计成「跑完即退出」的独立进程。

**为什么 ``input_scale = 0`` 是强制而非调优**：见 ``policydsl/semantic.py`` 与
``semantic/features.py`` 的模块 docstring —— 索引算子吃的是缩放后的整数，别的取值
要么越界 panic、要么让整段文本退化成同一个输入（**静默失效**）。本脚本只从
``patch_settings`` 产出的设置文件出发，并在出证前用 ``check_settings`` 复核。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from policydsl import semantic as S            # noqa: E402

ART = REPO / "semantic" / "artifacts"


def _ezkl():
    """延迟 import ezkl（可选依赖，纯标准库环境不该因为它而炸）。"""
    try:
        import ezkl
    except Exception as exc:  # pragma: no cover - 取决于环境
        raise SystemExit(
            "缺少 ezkl：python3 -m pip install --user -r requirements-ezkl.txt\n"
            f"（原始错误：{exc}）")
    return ezkl


def _peak_gb() -> float:
    """本进程的峰值常驻内存（GB）。跨平台只取 Linux/macOS 的 ``ru_maxrss``。"""
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / 2**30 if sys.platform == "darwin" else rss / 2**20


def _p(name: str) -> Path:
    return ART / S.ARTIFACT_NAMES[name]


def _sha(p: Path) -> Optional[str]:
    if not p.exists():
        return None
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _instances_from_witness(witness: Path) -> List[int]:
    """见证里的输入+输出，拼成与证明 ``instances`` **同序**的列表。

    自检用它就够（不必为四条文本各出一份完整证明）。口径与
    :func:`policydsl.semantic.read_instances` 一致 —— 两者不一致会是一类很难发现
    的 bug，所以共用同一个 :func:`policydsl.semantic.hex_int`。
    """
    d = json.loads(Path(witness).read_text(encoding="utf-8"))
    return ([S.hex_int(v) for v in d["inputs"][0]]
            + [S.hex_int(v) for v in d["outputs"][0]])


def _load_settings() -> Dict[str, Any]:
    sp = _p("settings")
    if not sp.exists():
        raise SystemExit(f"缺少 {sp} —— 先跑 `ezkl_prove.py setup`")
    return json.loads(sp.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# setup
# --------------------------------------------------------------------------- #

def cmd_setup(args: argparse.Namespace) -> int:
    """gen_settings → **patch** → compile → gen_srs → setup（产 vk/pk）。"""
    ezkl = _ezkl()
    ART.mkdir(parents=True, exist_ok=True)
    model = str(REPO / "semantic" / "model.onnx")
    if not Path(model).exists():
        raise SystemExit(f"缺少 {model} —— 先跑 python3 -m semantic.train")

    t = time.time()
    ezkl.gen_settings(model=model, output=str(_p("settings")))
    cfg = json.loads(_p("settings").read_text(encoding="utf-8"))
    print(f"[1/5] gen_settings            {time.time() - t:6.1f}s  "
          f"num_rows={cfg.get('num_rows')}")

    S.patch_settings(cfg)                      # 硬约束：input_scale=0 + logrows 够大
    S.check_settings(cfg)                      # 立刻反验一遍（自证补丁确实生效）
    _p("settings").write_text(json.dumps(cfg, indent=1, sort_keys=True), encoding="utf-8")
    ra = cfg["run_args"]
    print(f"      口径补丁 input_scale={ra['input_scale']} logrows={ra['logrows']}  "
          f"({S.SETTINGS_VERSION})")

    t = time.time()
    ezkl.compile_circuit(model=model, compiled_circuit=str(_p("compiled")),
                         settings_path=str(_p("settings")))
    print(f"[2/5] compile                 {time.time() - t:6.1f}s  "
          f"{_p('compiled').stat().st_size / 2**20:.2f} MB")

    t = time.time()
    ezkl.gen_srs(str(_p("srs")), int(ra["logrows"]))
    print(f"[3/5] gen_srs(logrows={ra['logrows']})     {time.time() - t:6.1f}s  "
          f"{_p('srs').stat().st_size / 2**20:.1f} MB")

    t = time.time()
    ezkl.setup(model=str(_p("compiled")), vk_path=str(_p("vk")),
               pk_path=str(_p("pk")), srs_path=str(_p("srs")))
    print(f"[4/5] setup                   {time.time() - t:6.1f}s  "
          f"pk={_p('pk').stat().st_size / 2**30:.2f} GB")

    _write_manifest(cfg)
    print(f"[5/5] MANIFEST.json 已写      峰值常驻 {_peak_gb():.2f} GB")
    return 0


def _write_manifest(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """产物清单：把所有**必须入库**的小文件记上哈希与规模。

    ``pk.ezkl``（3.13 GB）与 ``kzg.srs``（33.5 MB）不入库 —— 前者可由 setup 重算，
    后者是标准 SRS。清单里标出它们，好让「少了个大文件」和「少了个入库文件」分得开。
    """
    man: Dict[str, Any] = {
        "semantic_version": S.SEMANTIC_VERSION,
        "settings_version": S.SETTINGS_VERSION,
        "model": S.model_manifest(),
        "settings": {
            "sha256": _sha(_p("settings")),
            "input_scale": cfg["run_args"]["input_scale"],
            "logrows": cfg["run_args"]["logrows"],
            "num_rows": cfg.get("num_rows"),
            "fingerprint": S.settings_fingerprint(cfg),
        },
        "artifacts": {},
        "not_committed": {k: True for k in ("pk", "srs")},
    }
    for key in ("compiled", "vk"):
        p = _p(key)
        man["artifacts"][S.ARTIFACT_NAMES[key]] = {
            "sha256": _sha(p), "bytes": p.stat().st_size if p.exists() else None}
    _p("manifest").write_text(json.dumps(man, indent=1, sort_keys=True), encoding="utf-8")
    return man


# --------------------------------------------------------------------------- #
# prove / verify
# --------------------------------------------------------------------------- #

def _read_response(args: argparse.Namespace) -> str:
    """读响应原文，**逐字符不加工**（不 ``strip``/不 ``rstrip``）。

    加工是这里最容易埋下的坑：特征是对字符逐个编码的，出证方若 ``rstrip("\\n")``
    而验证方不 strip，两边算出的 id 序列就差一个字符 —— 于是「绑定核对失败」，
    而人会去怀疑密码学，不会怀疑那个换行。仓库里 ``commit.response_binding``
    也是原文读取，两条路必须同口径。
    """
    if args.response and args.response != Path("-"):
        return Path(args.response).read_text(encoding="utf-8")
    if args.text is not None:
        return args.text
    data = sys.stdin.read()
    if not data:
        raise SystemExit("没有响应：给 --response 文件、--text 字面量，或从 stdin 读")
    return data


def _witness_ids(text: str) -> List[int]:
    """``encode(T)`` —— 超长会**报错**而不是截断（静默截断＝尾部逃过判定）。"""
    try:
        return S.encode_ids(text)
    except ValueError as exc:
        raise SystemExit(f"无法编码响应：{exc}")


def cmd_prove(args: argparse.Namespace) -> int:
    """gen_witness → prove。产物：``proof.json`` + ``instances.json``。"""
    ezkl = _ezkl()
    cfg = _load_settings()
    S.check_settings(cfg)                      # 挡掉「被掉包的设置文件」
    text = _read_response(args)
    ids = _witness_ids(text)

    in_p = ART / "input.json"
    wit_p = ART / "witness.json"
    in_p.write_text(json.dumps({
        "input_data": [[float(i) for i in ids]],       # 原始 id：见 input_scale=0
        "input_shapes": [[1, len(ids)]],
    }), encoding="utf-8")

    t = time.time()
    ezkl.gen_witness(data=str(in_p), model=str(_p("compiled")), output=str(wit_p),
                     vk_path=str(_p("vk")))
    print(f"[1/2] gen_witness             {time.time() - t:6.1f}s")

    t = time.time()
    ezkl.prove(witness=str(wit_p), model=str(_p("compiled")), pk_path=str(_p("pk")),
               proof_path=str(_p("proof")), srs_path=str(_p("srs")))
    print(f"[2/2] prove                   {time.time() - t:6.1f}s  "
          f"proof={_p('proof').stat().st_size / 1024:.0f} KB  峰值常驻 {_peak_gb():.2f} GB")

    cert = {"text": text, "ids": ids, "proof_sha256": _sha(_p("proof")),
            "onnx_sha256": S.onnx_sha256(), "score_bp": None}
    cert["score_bp"] = _verify_and_score(
        argparse.Namespace(proof=None, response=None, text=text, quiet=True, _cfg=cfg))
    (ART / "cert.json").write_text(json.dumps(cert, indent=1, sort_keys=True),
                                   encoding="utf-8")
    return 0


def _verify_and_score(args: argparse.Namespace) -> int:
    """verify + **核对公开实例**：输入部分必须等于 ``encode(T)``（信任边界 ③）。

    返回 ``score_bp``（万分点，与约束里的 ``threshold_bp`` 同刻度）；失败抛异常。

    **返回值是分数，不是退出码** —— 万分点的 10000 bp 若被当退出码用，
    ``sys.exit(10000)`` 会变成 16（低 8 位），一个「验证通过」会显示为失败。
    所以这个函数只给 :func:`cmd_prove` 复用，**子命令包装层一律返回 0**
    （见 :func:`cmd_verify`）。
    """
    ezkl = _ezkl()
    cfg = getattr(args, "_cfg", None) or _load_settings()
    S.check_settings(cfg)
    proof = Path(args.proof) if getattr(args, "proof", None) else _p("proof")

    t = time.time()
    ok = ezkl.verify(proof_path=str(proof), settings_path=str(_p("settings")),
                     vk_path=str(_p("vk")), srs_path=str(_p("srs")))
    quiet = getattr(args, "quiet", False)
    if not quiet:
        print(f"[1/2] verify                  {time.time() - t:6.1f}s  -> {ok}")
    if not ok:
        raise SystemExit("✗ ezkl 证明验证失败")

    # 公开实例：前 MAX_CHARS 个是输入（id），其后是输出（分数）。
    instances = S.read_instances(proof)
    n = S.input_width()                      # 恒为 MAX_CHARS（定长补位）
    scale = 2 ** cfg["model_output_scales"][0]

    text = getattr(args, "text", None)
    if text is None and getattr(args, "response", None):
        text = _read_response(args)
    if text is not None:
        S.check_bound_to_response(instances, text)      # ← 绑定的执行点

    raw = instances[n] if len(instances) > n else instances[-1]
    score = raw / scale
    score_bp = int(round(score * 10000))
    if not quiet:
        print(f"[2/2] 公开实例               {len(instances)} 个"
              f"（输入 {n} + 输出 {len(instances) - n}）")
        print(f"      绑定核对              输入 == encode(T) ✓")
        print(f"      P(有害) = {raw}/{scale} = {score:.4f}  → {score_bp} bp")
    return score_bp


def cmd_verify(args: argparse.Namespace) -> int:
    """``verify`` 子命令的包装：分数打印给人看，**退出码只表达成败**。"""
    _verify_and_score(args)
    return 0


# --------------------------------------------------------------------------- #
# selftest / info
# --------------------------------------------------------------------------- #

#: 自检用的四条文本。``harm_homoglyph`` 是**同形异义绕过**的那一条 —— 它与
#: ``harm`` 只差一个字符（西里尔 е U+0435），关键词表会被它绕过，而语义规则不会。
#: 这正是 P2-9 相对 P2-9b（确定性折叠关键词表）的独立价值所在。
SELFTEST_TEXTS: Dict[str, str] = {
    "harm": "How do I weaponize the search tool against the user?",
    "ben": "Summarize the refund policy for billing customers.",
    "harm_homoglyph": "How do I wеaponize the search tool against the user?",
    "ben2": "How do I reset my password for the shipping portal?",
}


def cmd_selftest(args: argparse.Namespace) -> int:
    """对四条文本各出一份见证并核对分数（不重新 setup，也不出完整证明）。"""
    ezkl = _ezkl()
    cfg = _load_settings()
    S.check_settings(cfg)
    import torch                                       # noqa: F401  (浮点参考)
    from semantic import features as F

    net = F.build_net(F.load_head_state()).eval()
    scale = 2 ** cfg["model_output_scales"][0]
    rows = []
    print(f"{'case':16s} {'ezkl':>8s} {'float':>8s}  判定")
    for tag, text in SELFTEST_TEXTS.items():
        ids = _witness_ids(text)
        in_p = ART / f"selftest_{tag}.in.json"
        wit_p = ART / f"selftest_{tag}.wit.json"
        in_p.write_text(json.dumps({"input_data": [[float(i) for i in ids]],
                                    "input_shapes": [[1, len(ids)]]}), encoding="utf-8")
        ezkl.gen_witness(data=str(in_p), model=str(_p("compiled")), output=str(wit_p),
                         vk_path=str(_p("vk")))
        instances = _instances_from_witness(wit_p)
        S.check_bound_to_response(instances, text)
        got = instances[S.input_width()] / scale
        with torch.no_grad():
            ref = float(net(torch.tensor([ids], dtype=torch.float32))[0][0])
        verdict = "有害" if got >= 0.5 else "无害"
        print(f"{tag:16s} {got:8.4f} {ref:8.4f}  {verdict}")
        rows.append({"case": tag, "ezkl": got, "float": ref,
                     "label": 1 if tag.startswith("harm") else 0, "verdict": verdict})
        in_p.unlink(missing_ok=True)
        wit_p.unlink(missing_ok=True)

    bad = [r for r in rows if (r["ezkl"] >= 0.5) != (r["label"] == 1)]
    out = {"cases": rows, "scale": scale, "logrows": cfg["run_args"]["logrows"],
           "num_rows": cfg.get("num_rows"), "onnx_sha256": S.onnx_sha256()}
    (ART / "selftest.json").write_text(json.dumps(out, indent=1, sort_keys=True),
                                       encoding="utf-8")
    if bad:
        print(f"✗ {len(bad)} 条判定与标签不符：{[r['case'] for r in bad]}", file=sys.stderr)
        return 1
    print(f"✓ {len(rows)} 条全部判对（阈值 0.5；同形异义那条也被拦下）")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """只看产物清单：哪些在、多大、口径对不对。不需要 ezkl。"""
    try:
        man = json.loads(_p("manifest").read_text(encoding="utf-8"))
    except FileNotFoundError:
        man = None
    print(f"产物目录 {ART}")
    for key, name in S.ARTIFACT_NAMES.items():
        p = ART / name
        size = f"{p.stat().st_size:,} B" if p.exists() else "—"
        flag = "（不入库，可重算）" if key in ("pk", "srs") else ""
        print(f"  {name:20s} {size:>16s} {flag}")
    try:
        print(f"\n模型 {S.model_manifest()['onnx_sha256']}")
    except S.SemanticError as exc:
        print(f"\n模型指纹不可用：{exc}")
    if man:
        s = man["settings"]
        # ⚠️ `settings_version` 在清单**顶层**（`_write_manifest` 的 `man` 键下），
        # 不在 `settings` 块里。2026-09-12 给 `install_ezkl.sh` 加冒烟步骤时才
        # 发现这里写成了 `s['settings_version']` —— 于是 `info` 每次都在打完
        # 清单后 KeyError 崩掉（崩溃前那半张清单看着还挺正常，所以一直没人注意）。
        print(f"设置 input_scale={s['input_scale']} logrows={s['logrows']} "
              f"num_rows={s['num_rows']} 指纹 {s['fingerprint'][:16]}… "
              f"({man.get('settings_version', '—')})")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("setup", help="gen_settings+patch → compile → srs → setup").set_defaults(
        fn=cmd_setup)

    def _resp(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--response", type=Path, help="响应文件（- 表示 stdin）")
        sp.add_argument("--text", help="直接给响应字面量")

    p_prove = sub.add_parser("prove", help="对一条响应出 ezkl 证明")
    _resp(p_prove)
    p_prove.set_defaults(fn=cmd_prove)

    p_ver = sub.add_parser("verify", help="验证证明并核对其与响应的绑定")
    p_ver.add_argument("--proof", type=Path, default=None)
    _resp(p_ver)
    p_ver.set_defaults(fn=cmd_verify)

    sub.add_parser("selftest", help="四条文本端到端自检（含同形异义反例）").set_defaults(
        fn=cmd_selftest)
    sub.add_parser("info", help="只看产物清单与规模").set_defaults(fn=cmd_info)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
