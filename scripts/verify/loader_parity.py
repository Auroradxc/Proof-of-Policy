#!/usr/bin/env python3
"""策略加载器的**对拍器**：证明「十几份加载器其实是同一件事」是查出来的，不是读出来的。

**为什么需要它。** 仓库里同一个「把策略包 JSON 读成 :class:`Policy`」的动作被抄了
十几份（R7）。它们长得很像，但**像不等于同**：

* 规则名的兜底串，一份写 ``f"r{i}"``、另一份写 ``f"rule-{i}"``；
* 有的把包里声明的 ``semantic`` / ``description`` 带进 :class:`Policy`，有的丢掉、
  让它们落到缺省值；
* 有的用 ``data["rules"]``（缺键就 ``KeyError``），有的用 ``data.get("rules", [])``
  （缺键**静默变成空策略** —— 这是 fail-open，比报错危险得多）。

``description`` 不进 ``policy_hash``（见 ``core/compile.py::_assemble`` 的稳定字段），
但 ``semantic`` **进**。所以「两份加载器不一样」的后果不是报错，是**同一个包被两份
加载器编译出两个哈希**：出证方算一个、验证方算另一个，而两边都自洽 —— 证书在
第三方手里才验不过。

**为什么要先采快照，而不是等改完再测。** 因为 R7 要做的就是**删掉那十几份**。
删完再想「它们当初是不是等价」，已经比不了了。所以顺序必须是
**先采 → 再删 → 用快照核**，快照就是这个工具留下的活口。

**判据是什么。** 逐包比两样东西（见 :func:`_judged`）：**去重后的哈希集合**与
**去重后的签名集合**（``description`` / ``semantic`` / 规则名序列）。取「集合」而不是
「每一份加载器的记录」，是为了让「11 份旧加载器」与「1 份新的统一加载器」可比 ——
两边都归约成同一个问题：*这批包上，出现过几种答案？*

**它能保证什么、不能保证什么**：保证「对这批**随包发行**的策略，新旧加载器给出
同一个 ``policy_hash`` 与同一组非哈希字段」；不保证「对任意 JSON 都等价」——
恰恰相反，把不等价的地方**点名**才是它的用处之一（``differences`` 一节）。

用法::

    python3 scripts/verify/loader_parity.py --snapshot tests/loader_parity_baseline.json
    python3 scripts/verify/loader_parity.py --verify   tests/loader_parity_baseline.json
    python3 scripts/verify/loader_parity.py --verify   tests/loader_parity_baseline.json --against from_dict
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/（_bootstrap 所在）
from _bootstrap import REPO, bootstrap  # noqa: E402

bootstrap()

#: 随包发行的策略。快照只覆盖这些 —— 它们是「必须逐字节不变」的那批。
PACKS = [
    "agent_content_v1.json", "agent_tool_v1.json", "eu_ai_act_v1.json",
    "finance_redaction_v1.json", "multiparty_demo_v1.json",
    "pii_redaction_v1.json", "semantic_demo_v1.json",
]

#: 要拿来对拍的加载器：``(标签, 模块, 函数名)``。标签会写进快照，改名即换基线。
#:
#: 模块一律用**点分路径**导入（``scripts`` 在 py3 下是命名空间包，无需 ``__init__``）。
#: 不要改成「按文件路径加载」：那样合成出来的模块名没有登记进 ``sys.modules``，
#: ``@dataclass`` 会去查 ``sys.modules[cls.__module__]`` 而拿到 ``None``，
#: 于是 ``multiparty`` / ``compose`` / ``service`` 三份会以
#: ``AttributeError: 'NoneType' object has no attribute '__dict__'`` 整体失败 ——
#: 那是采集器的赝品，不是被检代码的问题（踩过）。
LOADERS: List[Tuple[str, str, str]] = [
    ("policydsl/__main__._load_policy", "policydsl.__main__", "_load_policy"),
    ("policydsl/proofs/multiparty._load_policy", "policydsl.proofs.multiparty", "_load_policy"),
    ("policydsl/proofs/compose._load_policy", "policydsl.proofs.compose", "_load_policy"),
    ("policydsl/proofs/session._load_policy", "policydsl.proofs.session", "_load_policy"),
    ("policydsl/runtime/service.load_policy", "policydsl.runtime.service", "load_policy"),
    ("scripts/prove/issue_cert.load_policy", "scripts.prove.issue_cert", "load_policy"),
    ("scripts/prove/prove_policy.load_policy", "scripts.prove.prove_policy", "load_policy"),
    ("scripts/prove/prove_multiparty.load_policy", "scripts.prove.prove_multiparty", "load_policy"),
    ("scripts/prove/compose_proof.load_policy", "scripts.prove.compose_proof", "load_policy"),
    ("scripts/verify/verify_cert.load_policy", "scripts.verify.verify_cert", "load_policy"),
    ("scripts/verify/verify_session.load_policy", "scripts.verify.verify_session", "load_policy"),
]

#: 子进程里跑的采集代码。**一份加载器一个进程**：脚本模块之间会互相 `import`，
#: 挤在一个进程里既要小心模块名撞车，又要小心 `sys.path` 被上一份改过。
_SUB = r'''
import importlib, json, sys
from pathlib import Path
repo, dotted, func_name = sys.argv[1], sys.argv[2], sys.argv[3]
packs = json.loads(sys.argv[4])
sys.path.insert(0, str(Path(repo) / "scripts"))
from _bootstrap import bootstrap
sys.path.insert(0, str(repo))
bootstrap()
mod = importlib.import_module(dotted)
fn = getattr(mod, func_name)
from policydsl.core.compile import compile_policy
out = {}
for p in packs:
    # **按文件名做键**：父进程是按文件名列的包，两边必须同一个键，否则父进程
    # 一条也查不到、却会报出一句恒真的「一致」—— 踩过，见 `_coverage` 的说明。
    name = Path(p).name
    try:
        pol = fn(Path(p))
        out[name] = {
            "policy_hash": compile_policy(pol)["sha256"],
            "policy": {
                "id": pol.id, "version": pol.version,
                "description": pol.description, "semantic": pol.semantic,
                "rules": [[r.name, r.kind, r.params] for r in pol.rules],
            },
        }
    except BaseException as exc:  # SystemExit 也算：__main__ 用它报文件/JSON 错
        out[name] = {"error": type(exc).__name__, "message": str(exc)}
print(json.dumps(out, ensure_ascii=False))
'''


def pack_paths() -> List[Path]:
    return [REPO / "policy_packs" / n for n in PACKS]


def run_loader(dotted: str, func_name: str) -> Dict[str, Any]:
    """在**子进程**里跑一份加载器，返回 ``{包名: 记录}``。"""
    proc = subprocess.run(
        [sys.executable, "-c", _SUB, str(REPO), dotted, func_name,
         json.dumps([str(p) for p in pack_paths()])],
        capture_output=True, text=True, cwd=str(REPO),
    )
    if proc.returncode != 0:
        return {"__loader_failed__": {
            "returncode": proc.returncode, "stderr_tail": proc.stderr[-800:]}}
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _signature(policy: Dict[str, Any]) -> str:
    """一份加载结果里**非哈希**的那部分，拍成一个可比的字符串。"""
    return json.dumps({
        "description": policy["description"],
        "semantic": policy["semantic"],
        "rule_names": [r[0] for r in policy["rules"]],
        "rule_kinds": [r[1] for r in policy["rules"]],
    }, sort_keys=True, ensure_ascii=False)


def _judged(loaders: Dict[str, Any], packs: List[str]) -> Dict[str, Any]:
    """**判据载荷**：逐包的「去重哈希集合」与「去重签名集合」。

    刻意不带加载器的标签与份数 —— 这样「11 份旧加载器」与「1 份统一加载器」
    归约成同一个问题，可以直接逐路径比。
    """
    out: Dict[str, Any] = {}
    for name in packs:
        hashes, sigs = set(), set()
        for rec in loaders.values():
            entry = rec.get(name)
            if not entry or "policy" not in entry:
                continue
            hashes.add(entry["policy_hash"])
            sigs.add(_signature(entry["policy"]))
        out[name] = {"hashes": sorted(hashes), "signatures": sorted(sigs)}
    return out


def _coverage(loaders: Dict[str, Any], packs: List[str]) -> Dict[str, Any]:
    """逐包统计「**真的读到了策略**」的份数，以及读不到时的原因。

    **没有这一道，一条查不到任何东西的对拍会报出恒真的「一致」。** 本工具的第一版
    正是这么坏的：子进程按**绝对路径**做键、父进程按**文件名**查，于是每一份都被
    当成 ``<MISSING>``，7 个包齐刷刷显示「1 种哈希」—— 看起来是最理想的结果。

    空集合上全绿是所有普查工具的默认失败模式（本仓的文档链接普查、跨层常量比对
    各自防过一遍），所以这里把「查到了几份」变成返回值的一部分，由 :func:`main`
    判定够不够数；不够就**拒绝出结果**，而不是照常打印「一致」。
    """
    out: Dict[str, Any] = {}
    for name in packs:
        loaded, reasons = 0, []
        for label, rec in loaders.items():
            entry = rec.get(name)
            if entry is None:
                reasons.append(f"{label}: 没有这个包的记录（键对不上？）")
            elif "policy" in entry:
                loaded += 1
            else:
                reasons.append(f"{label}: {entry.get('error')}: {entry.get('message', '')[:80]}")
        out[name] = {"loaded": loaded, "expected": len(loaders), "reasons": reasons}
    return out


def _undercovered(report: Dict[str, Any]) -> List[str]:
    """哪些包没凑齐（空集合 / 键错位 / 加载器报错，都算）。"""
    bad = []
    for name, cov in report["coverage"].items():
        if cov["loaded"] < cov["expected"]:
            bad.append(f"  {name}: 只读到 {cov['loaded']}/{cov['expected']} 份"
                       + "".join(f"\n      {r}" for r in cov["reasons"]))
    return bad


def _differences(loaders: Dict[str, Any], packs: List[str]) -> Dict[str, Any]:
    """逐包列出**非哈希字段**上的分歧（谁被选了，得由人拍板）。

    这些字段要么不进哈希（``description``），要么进哈希但**恰好一致**（``semantic``）,
    所以它们不会让任何判据变红 —— 正因如此才要单独点名。
    """
    out: Dict[str, Any] = {}
    for name in packs:
        fields: Dict[str, Dict[str, List[str]]] = {"description": {}, "semantic": {}, "rule_names": {}}
        for label, rec in loaders.items():
            pol = (rec.get(name) or {}).get("policy")
            if not pol:
                continue
            fields["description"].setdefault(repr(pol["description"]), []).append(label)
            fields["semantic"].setdefault(repr(pol["semantic"]), []).append(label)
            fields["rule_names"].setdefault(repr([r[0] for r in pol["rules"]]), []).append(label)
        out[name] = {k: {v: sorted(l) for v, l in d.items()}
                     for k, d in fields.items() if len(d) > 1}
    return out


def collect() -> Dict[str, Any]:
    """现算全部加载器 × 全部包的记录（纯 JSON 可序列化）。"""
    packs = [p.name for p in pack_paths()]
    loaders: Dict[str, Any] = {}
    for label, dotted, func_name in LOADERS:
        loaders[label] = run_loader(dotted, func_name)
    return {
        "packs": packs,
        "loaders": loaders,
        "coverage": _coverage(loaders, packs),
        "judged": _judged(loaders, packs),
        "differences": _differences(loaders, packs),
    }


def collect_from_dict(Policy, packs: List[str]) -> Dict[str, Any]:
    """用统一的 ``Policy.from_dict`` 重放一遍，形状与 :func:`collect` 相同。"""
    from policydsl.core.compile import compile_policy
    by_pack: Dict[str, Any] = {}
    for name in packs:
        d = json.loads((REPO / "policy_packs" / name).read_text(encoding="utf-8"))
        pol = Policy.from_dict(d)
        by_pack[name] = {
            "policy_hash": compile_policy(pol)["sha256"],
            "policy": {
                "id": pol.id, "version": pol.version,
                "description": pol.description, "semantic": pol.semantic,
                "rules": [[r.name, r.kind, r.params] for r in pol.rules],
            },
        }
    loaders = {"Policy.from_dict": by_pack}
    return {
        "packs": packs,
        "loaders": loaders,
        "coverage": _coverage(loaders, packs),
        "judged": _judged(loaders, packs),
        "differences": _differences(loaders, packs),
    }


def judged_payload(report: Dict[str, Any]) -> Dict[str, Any]:
    """逐路径对拍时真正比的那部分（标签与份数不进判据）。"""
    return {"packs": report["packs"], "judged": report["judged"]}


def render(report: Dict[str, Any]) -> str:
    """人读版：覆盖多少份、每个包出现过几种答案。"""
    lines = []
    cov = report["coverage"]
    lo = min(c["loaded"] for c in cov.values())
    hi = max(c["expected"] for c in cov.values())
    lines.append(f"  覆盖：每个包都读到了 {lo}/{hi} 份加载器" if lo == hi else
                 f"  覆盖：最少的包只读到 {lo}/{hi} 份 —— 见下")
    for name, j in report["judged"].items():
        n_h, n_s = len(j["hashes"]), len(j["signatures"])
        mark = "一致" if n_h == 1 and n_s == 1 else f"**{n_h} 种哈希 / {n_s} 种签名**"
        lines.append(f"  {name:32} {mark}")
        for h in j["hashes"]:
            who = [lab for lab, rec in report["loaders"].items()
                   if (rec.get(name) or {}).get("policy_hash") == h]
            lines.append(f"      {h[:16]}…  ← {len(who)} 份：{', '.join(sorted(who)) or '(统一加载器)'}")
    for name, fields in report["differences"].items():
        if fields:
            lines.append(f"  {name}: 非哈希分歧 {sorted(fields)}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", type=Path, default=None, help="采集并写入快照")
    ap.add_argument("--verify", type=Path, default=None, help="现算并与快照比对")
    ap.add_argument("--against", choices=("loaders", "from_dict"), default="loaders",
                    help="verify 时拿什么现算：全部旧加载器（缺省）或统一的 Policy.from_dict")
    args = ap.parse_args()

    if args.snapshot:
        report = collect()
        bad = _undercovered(report)
        if bad:
            print("**覆盖不足，拒绝写快照** —— 空集合上全绿比失败更坏：\n" + "\n".join(bad))
            return 2
        args.snapshot.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        print(render(report))
        print(f"\n已写入 {args.snapshot}（{len(report['loaders'])} 份加载器 × "
              f"{len(report['packs'])} 个包）")
        return 0

    if args.verify:
        golden = json.loads(args.verify.read_text(encoding="utf-8"))
        if args.against == "loaders":
            now = collect()
        else:
            from policydsl.core.model import Policy
            now = collect_from_dict(Policy, golden["packs"])
        bad = _undercovered(now)
        if bad:
            print("**覆盖不足，这次对拍不算数**（不打印「一致」）：\n" + "\n".join(bad))
            return 2
        if judged_payload(now) == judged_payload(golden):
            print(render(now))
            print(f"\n等效：与 {args.verify} 逐路径一致（判据 = 逐包的哈希集合与签名集合）")
            return 0
        print("有差异：")
        g, n = judged_payload(golden)["judged"], judged_payload(now)["judged"]
        for key in sorted(set(g) | set(n)):
            if g.get(key) != n.get(key):
                print(f"  [{key}]")
                print(f"    快照: {json.dumps(g.get(key), ensure_ascii=False)[:300]}")
                print(f"    现算: {json.dumps(n.get(key), ensure_ascii=False)[:300]}")
        return 3

    ap.error("要么 --snapshot，要么 --verify")


if __name__ == "__main__":
    sys.exit(main())
