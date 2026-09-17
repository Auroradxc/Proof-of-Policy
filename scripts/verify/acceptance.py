#!/usr/bin/env python3
"""等效替代的**机械判据**：采集/比对仓库的可观察面快照。

**为什么需要它。** 重构的验收标准是「功能与实现路径不变」，但仓库里
**没有任何入库的 golden 快照** —— 既有约定是「现算再比」（比如
``scripts/prove/cross_validate.py`` 的 ``golden()``）。那套约定对「跨语言对拍」
够用，对「我改了一处实现，行为有没有变」不够：没有基线就没有「回退到哪」的
锚点，也就只能靠人读 diff 判断「看起来一样」。

本脚本把**同一份输入 → 逐字节同一份输出**这件事变成一条命令。它只读：

* :func:`collect` 现算七个可观察面，返回纯 JSON 可序列化的字典；
* ``--snapshot OUT`` 写快照；``--verify GOLDEN`` 现算并与快照逐路径比对。

七个面（编号见 :data:`FACES`）：

1. **跨层契约** —— 7 个策略包各自的完整 ``ConstraintSpec``（规范字节）与
   ``sha256``。这是 Python 与 Rust/SP1 之间**唯一**的契约，也是 ``policy_hash``
   的来源：它一变，所有已入库的证明工件集体失效。所以它必须被钉死。
2. **判定结论** —— 7 包 × 20 条语料，同时走两条判定路径：``evaluate.check``
   （参考层，走 ``Rule.params``）与 ``privacy.commit.canonical_violations``
   （走编译后的契约）。两条路径**必须同时**不变，只钉一条会漏掉另一条的漂移。
3. **健壮性（模型层）** —— 12 种畸形策略包喂进 ``__main__._load_policy`` →
   ``Policy.validate`` → ``compile_policy`` 三段，记录**在哪一段**抛了
   **什么类型**的异常、文案是什么。报错文案是诊断契约，所以逐字钉住。
4. **健壮性（CLI 层）** —— 畸形文件喂给 ``python3 -m policydsl``，记录退出码与
   stderr（临时路径被归一成 ``<TMP>``）。这一面走的是**子进程**，因此它在
   内部函数随便改名的情况下依然有效。
5. **流式证书序列** —— 固定文本逐字符喂给 ``PoPCallbackHandler``，记录部分证书
   的 ``(chars, passed)`` 序列与张数。R9(b) 只做等效替代，它的等效性**由这一面
   直接证明**，不需要读代码。
6. **CLI** —— 7 包的 ``compile`` / ``check`` 正常路径：退出码 + stdout。
7. **导入面** —— ``policydsl.__all__`` 里每个符号都能解析（R12 的判据）。

**有意变更要显式改快照。** 例如未来谁改了策略包，``policy_hash`` 会变 → 用例
变红 → 必须人工确认后重新 ``--snapshot``，diff 进提交。这条分界正是「等效性被
证明」与「变更被承认」的区别：快照不会替你判断该不该变，它只保证**变了就一定
有人看见**。

用法::

    python3 scripts/verify/acceptance.py --snapshot tests/acceptance_baseline.json
    python3 scripts/verify/acceptance.py --verify   tests/acceptance_baseline.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/（_bootstrap 所在）
from _bootstrap import REPO, bootstrap  # noqa: E402

bootstrap()

from policydsl.__main__ import _load_policy  # noqa: E402
from policydsl.adapters.agent import AgentMonitor  # noqa: E402
from policydsl.adapters.langchain_adapter import PoPCallbackHandler  # noqa: E402
from policydsl.core.compile import canonical_spec_text, compile_policy  # noqa: E402
from policydsl.core.evaluate import check  # noqa: E402
from policydsl.core.model import Policy, Transcript  # noqa: E402
from policydsl.evidence import cert  # noqa: E402
from policydsl.evidence.trace import ToolGateway  # noqa: E402
from policydsl.privacy import commit  # noqa: E402

#: 快照覆盖的七个面。键名即快照里的路径，改名等于换基线，须重新采集。
FACES = (
    "1_contract",
    "2_verdicts",
    "3a_model_robustness",
    "3b_cli_robustness",
    "4_streaming",
    "5_cli",
    "6_import_surface",
)

#: 未打包顺序的探测顺序固定，保证快照里的键序稳定（可读 diff）。
PACKS: Tuple[str, ...] = (
    "agent_content_v1.json",
    "agent_tool_v1.json",
    "eu_ai_act_v1.json",
    "finance_redaction_v1.json",
    "multiparty_demo_v1.json",
    "pii_redaction_v1.json",
    "semantic_demo_v1.json",
)

#: 同形字表（ASCII → 视觉近似的 Cyrillic/Greek 码点）。用于「看起来是那个词、
#: 逐字节不是」的语料 —— 这一类正是 ``normalized_keyword_block`` 存在的理由，
#: 而普通 ``keyword_block`` 应当**不**命中。
_HOMOGLYPHS = {
    "a": "а", "c": "с", "e": "е", "i": "і", "o": "о",
    "p": "р", "s": "ѕ", "x": "х", "y": "у", "u": "ν",
}


# --------------------------------------------------------------------------- #
# 采集小工具
# --------------------------------------------------------------------------- #

def _capture(fn) -> Dict[str, Any]:
    """执行 ``fn``，把「返回值」或「异常的类型 + 文案」序列化成字典。

    异常类型也进快照，是因为「畸形输入**不该**崩成 TypeError」这类性质只能
    靠类型表达：``PolicyError`` 是可诊断的校验失败，``TypeError`` 是未捕获的
    崩溃，两者对调用方是不同的事。
    """
    try:
        return {"ok": True, "value": fn()}
    except (Exception, SystemExit) as exc:  # SystemExit：_load_policy 走它报文件错
        return {"ok": False, "error": {"type": type(exc).__name__, "msg": str(exc)}}


def _pack_path(name: str) -> Path:
    return REPO / "policy_packs" / name


def _load_pack(name: str) -> Policy:
    """读一个策略包。

    **刻意走生产代码的加载器**（``policydsl/__main__.py`` 的 ``_load_policy``），
    而不是在本脚本里再写一份：加载器是 16 份副本收敛（R7）的对象之一，脚本里
    自带一份就会变成第 17 份，而快照反而看不见收敛带来的差异。
    """
    return _load_policy(_pack_path(name))


# --------------------------------------------------------------------------- #
# 面 1：跨层契约
# --------------------------------------------------------------------------- #

def face_contract() -> Dict[str, Any]:
    """7 包的完整 ConstraintSpec（规范字节）+ policy_hash。"""
    out: Dict[str, Any] = {}
    for name in PACKS:
        pol = _load_pack(name)
        spec = compile_policy(pol)
        out[name] = {
            # 规范字节 = Rust/SP1 侧实际读入的那段，含每条 pattern 编译出的 NFA。
            # 钉住它，就等于钉住「跨层契约不许悄悄改」。
            "canonical_spec": canonical_spec_text(spec),
            "sha256": spec["sha256"],
        }
    return out


# --------------------------------------------------------------------------- #
# 面 2：判定结论
# --------------------------------------------------------------------------- #

def _first_keyword(spec: Dict[str, Any]) -> str:
    for c in spec["constraints"]:
        if c["kind"] == "keyword_block" and c["keywords"]:
            return c["keywords"][0]
    return "exploit"


def _homoglyph(word: str) -> str:
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in word)


def _corpus(spec: Dict[str, Any]) -> List[Tuple[str, str]]:
    """由**契约**推出的固定语料（而不是写死的字符串）。

    这样语料随策略包走：换一个包，关键词/模式取自它自己的约束，命中与否仍然
    有意义。每条都是常量，无随机、无时间。
    """
    kw = _first_keyword(spec)
    return [
        ("benign", "Here is a safe summary of the refund policy."),
        ("keyword_hit", f"The answer explains how to {kw} the system."),
        ("keyword_upper", f"The answer explains HOW TO {kw.upper()} THE SYSTEM."),
        # 零宽空格插在词中间：肉眼一模一样，子串判定必须**不**命中。
        # 写成 \u200b 转义而不是字面量 —— 源码里藏不可见字符是维护陷阱。
        ("keyword_zerowidth",
         f"The answer explains how to {kw[:1]}\u200b{kw[1:]}."),
        ("keyword_newline", f"The answer explains how to {kw[:1]}\n{kw[1:]}."),
        ("keyword_homoglyph", f"The answer explains how to {_homoglyph(kw)}."),
        ("empty", ""),
        ("one_char", "x"),
        ("two_hundred", "a" * 200),
        ("two_thousand", "a" * 2000),
        ("four_thousand", "a" * 4000),
        ("long_tail_secret", "a" * 2000 + " sk-" + "A" * 24),
        ("email", "Contact alice@example.com for details."),
        ("phone", "Call +1 (555) 123-4567 ext 89 now."),
        ("secret_key", "token sk-" + "A" * 24 + " leaked"),
        ("bearer", "Authorization: Bearer " + "A" * 24),
        ("json_ok", '{"answer": 42}'),
        ("json_bad", '{"answer": 42'),
        ("unicode", "你好，世界 \U0001f30d — em dash"),
        ("newlines", "line one\nline two\r\nline three"),
    ]


def _receipt_scenarios() -> Dict[str, Tuple[str, List[Any]]]:
    """四档回执链：空链 / 干净链 / 脏链 / 坏链（``prev`` 被改）。

    工具类规则（``tool_arg_guard`` / ``budget_bound``）判的就是它们，而
    「坏链 fail-closed」是一条安全性质 —— 它必须在快照里有一席之地，否则
    R7/R8 之类的重构把 fail-open 改回去也没人知道。
    """
    clean_gw = ToolGateway()
    clean_gw.issue("search_kb", {"query": "refund policy"}, result="ok")

    dirty_gw = ToolGateway()
    dirty_gw.issue("search_kb", {"query": "refund", "token": "sk-" + "A" * 24},
                   result="ok")

    broken = list(clean_gw.receipts)
    broken[0] = type(broken[0])(**{**broken[0].to_dict(), "prev": "deadbeef"})

    return {
        "no_receipts": ("Here is a safe summary.", []),
        "clean_chain": ("Here is a safe summary.", list(clean_gw.receipts)),
        "dirty_chain": ("Here is a safe summary.", list(dirty_gw.receipts)),
        "broken_chain": ("Here is a safe summary.", broken),
    }


def face_verdicts() -> Dict[str, Any]:
    """7 包 × 20 条语料 + 4 档回执链，两条判定路径各记一份完整结论。"""
    scenarios = _receipt_scenarios()
    out: Dict[str, Any] = {}
    for name in PACKS:
        pol = _load_pack(name)
        spec = compile_policy(pol)
        per_pack: Dict[str, Any] = {}

        for case, text in _corpus(spec):
            per_pack[case] = {
                # 路径 A：参考层。走 policy.rules 的 params，pattern 每次重编译。
                "check": _capture(lambda t=text: _check_view(pol, t)),
                # 路径 B：契约层。走编译后的 spec（私有模式 / 电路侧的镜像）。
                "canonical": _capture(
                    lambda t=text: commit.canonical_violations(spec, t)),
            }

        for case, (text, receipts) in scenarios.items():
            per_pack[f"receipts:{case}"] = {
                "check": _capture(lambda t=text, r=receipts: _check_view(pol, t, r)),
                "canonical": _capture(lambda t=text, r=receipts:
                                      commit.canonical_violations(spec, t, r)),
            }

        out[name] = per_pack
    return out


def _check_view(pol: Policy, text: str,
                receipts: Optional[List[Any]] = None) -> Dict[str, Any]:
    """把 ``CheckResult`` 裁成稳定的可 JSON 化视图。"""
    res = check(pol, Transcript(response=text, receipts=list(receipts or [])))
    return {
        "passed": res.passed,
        "violations": [v.to_dict() for v in res.violations],
        "delegated": [d.__dict__ for d in res.delegated],
    }


# --------------------------------------------------------------------------- #
# 面 3a：健壮性（模型层）
# --------------------------------------------------------------------------- #

#: 每种 kind 一条「参数非法」的合成规则 —— 用来**逐个**打穿 8 个校验器。
#: 之所以是合成规则而不是「把某个真实规则的 params 换掉」：换 params 会让所有
#: 包都撞在第一条规则的校验器上，8 个校验器里有 7 个永远测不到。
_BAD_RULES: Dict[str, Dict[str, Any]] = {
    "bad_keyword_empty": {"kind": "keyword_block", "name": "bad", "params": {"keywords": []}},
    "bad_keyword_type": {"kind": "keyword_block", "name": "bad",
                         "params": {"keywords": [1, 2]}},
    "bad_norm_keyword_fold": {"kind": "normalized_keyword_block", "name": "bad",
                              "params": {"keywords": ["x"], "fold": "nope-preset"}},
    "bad_length": {"kind": "length_bound", "name": "bad", "params": {"min": 10, "max": 1}},
    "bad_pattern_empty": {"kind": "pattern_block", "name": "bad", "params": {"patterns": []}},
    "bad_pattern_mode": {"kind": "pattern_block", "name": "bad",
                         "params": {"patterns": ["a"], "match_mode": "cron"}},
    "bad_format": {"kind": "format_check", "name": "bad", "params": {"format": "yaml"}},
    "bad_tool_fields": {"kind": "tool_arg_guard", "name": "bad",
                        "params": {"forbidden_fields": []}},
    "bad_budget_negative": {"kind": "budget_bound", "name": "bad",
                            "params": {"budget": -1}},
    "bad_budget_unit": {"kind": "budget_bound", "name": "bad",
                        "params": {"budget": 1, "unit": "bytes"}},
    "bad_semantic_threshold": {"kind": "semantic_bound", "name": "bad",
                               "params": {"threshold_bp": 20000, "direction": "le"}},
    "bad_semantic_direction": {"kind": "semantic_bound", "name": "bad",
                               "params": {"threshold_bp": 1, "direction": "eq"}},
}


def _malformed_packs(base: Dict[str, Any]) -> Dict[str, Any]:
    """由**真实策略包**变形出的一组畸形包（每条的键名即用途）。

    两类：

    * **结构变形** —— 直接改包或首条规则的形状（缺字段、类型不对、多字段）；
    * **参数变形** —— 追加一条**合成规则**，每种 kind 各一条（见 :data:`_BAD_RULES`）。
      追加而不是替换，是为了让每个校验器都被**单独**打穿一次；替换的话所有包
      都只会撞上首条规则那一个校验器。
    """
    def mutate(fn):
        d = json.loads(json.dumps(base))       # 深拷贝，互不影响
        fn(d)
        return d

    first = lambda d: d["rules"][0]            # noqa: E731 —— 局部短名，仅此处用

    cases = {
        "drop_kind": mutate(lambda d: first(d).pop("kind")),
        "kind_is_list": mutate(lambda d: first(d).__setitem__("kind", ["kw"])),
        "drop_params": mutate(lambda d: first(d).pop("params")),
        "unknown_kind": mutate(lambda d: first(d).__setitem__("kind", "nope_kind")),
        "empty_rules": mutate(lambda d: d.__setitem__("rules", [])),
        "missing_id": mutate(lambda d: d.pop("id")),
        "rules_not_a_list": mutate(lambda d: d.__setitem__("rules", {"a": 1})),
        "extra_top_level": mutate(lambda d: d.update({"unknown_field": [1, 2]})),
    }
    for case, rule in _BAD_RULES.items():
        cases[case] = mutate(lambda d, r=rule: d["rules"].append(r))
    return cases


def face_model_robustness() -> Dict[str, Any]:
    """畸形包走三段真实代码：加载 → 校验 → 编译，记录抛错的那一段与文案。"""
    out: Dict[str, Any] = {}
    for name in PACKS:
        base = json.loads(_pack_path(name).read_text(encoding="utf-8"))
        cases: Dict[str, Any] = {}
        for case, data in _malformed_packs(base).items():
            stage = "load"
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    p = Path(tmp) / "pack.json"
                    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
                    pol = _load_policy(p)
                stage = "validate"
                pol.validate()
                stage = "compile"
                res = compile_policy(pol)
                cases[case] = {"stage": "ok", "sha256": res["sha256"]}
            except (Exception, SystemExit) as exc:
                cases[case] = {"stage": stage,
                               "error": {"type": type(exc).__name__, "msg": str(exc)}}
        out[name] = cases
    return out


# --------------------------------------------------------------------------- #
# 面 3b：健壮性（CLI 层）
# --------------------------------------------------------------------------- #

def _cli_pack_files(tmp: Path, base: Dict[str, Any]) -> Dict[str, str]:
    """畸形**文件**（含坏 JSON，这一档模型层碰不到，只有 CLI 的读文件路径会碰）。"""
    raw = {
        "bad_json": "{not json at all",
        "top_level_list": "[1, 2, 3]",
        "missing_id": json.dumps({k: v for k, v in base.items() if k != "id"}),
        "rules_not_list": json.dumps({**base, "rules": "oops"}),
        "unknown_kind": json.dumps({**base,
                                    "rules": [{**base["rules"][0], "kind": "nope"}]}),
        "empty_file": "",
    }
    for case, text in raw.items():
        (tmp / f"{case}.json").write_text(text, encoding="utf-8")
    return {case: str(tmp / f"{case}.json") for case in raw}


def _run_cli(args: List[str], tmp: Path) -> Dict[str, Any]:
    """跑一次 CLI，把临时路径与仓库路径归一后记下退出码与输出。"""
    r = subprocess.run([sys.executable, "-m", "policydsl", *args], cwd=str(REPO),
                       capture_output=True, text=True, timeout=120)
    norm = lambda s: (s.replace(str(tmp), "<TMP>")            # noqa: E731
                       .replace(str(REPO), "<REPO>"))
    return {"exit": r.returncode, "stdout": norm(r.stdout), "stderr": norm(r.stderr)}


def _stderr_lines(text: str) -> Dict[str, Any]:
    """stderr 只留首行与末行，**不留整段 traceback**。

    留整段会钉住「仓库绝对路径 + 每个栈帧的行号」—— 那两样每次无害的编辑都会变，
    快照就会为噪音变红，久而久之没人再看它。而可观察的行为其实只有三件事：
    退出码、首行（区分「干净的 error:」与「未捕获的 Traceback」）、末行
    （真正的异常类型与文案）。这三样都在，噪音不在。
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return {"first": "", "last": "", "lines": 0}
    return {"first": lines[0], "last": lines[-1], "lines": len(lines)}


def face_cli_robustness() -> Dict[str, Any]:
    """畸形文件 → CLI 的退出码与 stderr（这一面跨进程，与内部改名无关）。"""
    base = json.loads(_pack_path(PACKS[0]).read_text(encoding="utf-8"))
    out: Dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        for case, path in _cli_pack_files(tmp, base).items():
            r = _run_cli(["compile", path], tmp)
            out[case] = {"exit": r["exit"], "stdout": r["stdout"],
                         "stderr": _stderr_lines(r["stderr"])}
    return out


# --------------------------------------------------------------------------- #
# 面 4：流式证书序列
# --------------------------------------------------------------------------- #

#: 逐字符喂的固定文本：良性前缀 → 邮箱 → 密钥 → 关键词，一路造出多处判定翻转。
#: 长度刻意压到几百字符：这一面要的是**序列形状**，不是吞吐（吞吐是基准的活）。
_STREAM_TEXT = ("a" * 150 + " contact alice@example.com " + "b" * 80
                + " sk-" + "A" * 24 + " " + "c" * 80 + " exploit " + "d" * 40)

#: 走流式这一面的包：(包名, 是否开早停)。四种组合覆盖「翻转出证」与「首次违规
#: 立刻停」两条路径 —— 后者会改变**后续字符不再被判定**这件事，属于可观察行为。
_STREAM_CASES: Tuple[Tuple[str, bool], ...] = (
    ("agent_content_v1.json", False),
    ("pii_redaction_v1.json", False),
    ("agent_tool_v1.json", False),
    ("agent_content_v1.json", True),
)


def _stream_sequence(pack: str, stop_on_violation: bool) -> Dict[str, Any]:
    monitor = AgentMonitor(_load_pack(pack))
    handler = PoPCallbackHandler(monitor, vkey_hash="acceptance",
                                 stream_check=True, stream_step_chars=1,
                                 stop_on_violation=stop_on_violation)
    for ch in _STREAM_TEXT:
        handler.on_llm_new_token(ch, run_id="r")

    seq = []
    for env in handler.stream_certificates:
        payload = cert.envelope_payload(env)
        stream = payload["streaming"]
        seq.append({
            # ``chars`` 是累计前缀的字符数（跨 provider 可比的唯一那个数）。
            "chars": stream["chars"],
            "passed": payload["outcome"]["passed"],
            "partial": stream["partial"],
            "stop": stream.get("stop", {}).get("reason"),
        })
    return {
        "text_len": len(_STREAM_TEXT),
        "step_chars": 1,
        "certs": len(seq),
        "sequence": seq,
    }


def face_streaming() -> Dict[str, Any]:
    """同一文本 + 同一采样网格 ⇒ 同一串部分证书（逐字符喂，步长 1）。"""
    return {f"{pack}#stop={stop}": _stream_sequence(pack, stop)
            for pack, stop in _STREAM_CASES}


# --------------------------------------------------------------------------- #
# 面 5：CLI（正常路径）
# --------------------------------------------------------------------------- #

def face_cli() -> Dict[str, Any]:
    """7 包的 ``compile`` 与 ``check``：退出码 + stdout。

    ``compile`` 的 stdout 是完整 spec，可能很长 —— 记 sha256 与长度即可读；
    ``check`` 的 stdout 很短，逐字留下。
    """
    out: Dict[str, Any] = {}
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        resp = tmp / "response.txt"
        resp.write_text("Here is a safe summary of the refund policy.",
                        encoding="utf-8")
        for name in PACKS:
            pack = str(_pack_path(name))
            per_pack: Dict[str, Any] = {}
            for sub, args in (("compile", ["compile", pack]),
                              ("check", ["check", str(resp), "--policy", pack])):
                r = _run_cli(args, tmp)
                rec: Dict[str, Any] = {"exit": r["exit"],
                                       "stdout_sha256": hashlib.sha256(
                                           r["stdout"].encode("utf-8")).hexdigest(),
                                       "stdout_len": len(r["stdout"]),
                                       "stderr": r["stderr"]}
                if len(r["stdout"]) <= 800:
                    rec["stdout"] = r["stdout"]
                per_pack[sub] = rec
            out[name] = per_pack
    return out


# --------------------------------------------------------------------------- #
# 面 6：导入面
# --------------------------------------------------------------------------- #

def face_import_surface() -> Dict[str, Any]:
    """``policydsl`` 门面声明的每个符号都能解析（R12 的判据）。"""
    import policydsl

    names = list(getattr(policydsl, "__all__", []))
    return {
        "all": sorted(names),
        "unresolvable": sorted(n for n in names if not hasattr(policydsl, n)),
        "duplicates": sorted({n for n in names if names.count(n) > 1}),
    }


# --------------------------------------------------------------------------- #
# 采集 / 比对
# --------------------------------------------------------------------------- #

_COLLECTORS = {
    "1_contract": face_contract,
    "2_verdicts": face_verdicts,
    "3a_model_robustness": face_model_robustness,
    "3b_cli_robustness": face_cli_robustness,
    "4_streaming": face_streaming,
    "5_cli": face_cli,
    "6_import_surface": face_import_surface,
}


def collect(faces: Tuple[str, ...] = FACES) -> Dict[str, Any]:
    """现算选定的面，返回可直接 JSON 序列化的快照字典。"""
    return {name: _COLLECTORS[name]() for name in faces}


def _diff(golden: Any, fresh: Any, path: str = "", limit: int = 40) -> List[str]:
    """逐路径比对，返回**人类可读**的差异列表（而不是抛一句 not equal）。"""
    out: List[str] = []
    if len(out) >= limit:
        return out
    if isinstance(golden, dict) and isinstance(fresh, dict):
        for key in sorted(set(golden) | set(fresh)):
            if key not in golden:
                out.append(f"{path}.{key}: 快照里没有，现算有")
            elif key not in fresh:
                out.append(f"{path}.{key}: 快照里有，现算没有")
            else:
                out.extend(_diff(golden[key], fresh[key], f"{path}.{key}", limit))
    elif isinstance(golden, list) and isinstance(fresh, list):
        if len(golden) != len(fresh):
            out.append(f"{path}: 列表长度 {len(golden)} → {len(fresh)}")
        for i, (a, b) in enumerate(zip(golden, fresh)):
            out.extend(_diff(a, b, f"{path}[{i}]", limit))
    elif golden != fresh:
        if isinstance(golden, str) and isinstance(fresh, str) \
                and max(len(golden), len(fresh)) > _LONG_STR:
            out.append(f"{path}: {_string_diff(golden, fresh)}")
        else:
            out.append(f"{path}: {_short(golden)} → {_short(fresh)}")
    return out[:limit]


#: 超过这个长度的字符串按「首处不同 + 上下文窗口」报，而不是掐头 160 字符 ——
#: 规范契约是一整条长字符串，掐头显示的恰好是两边**相同**的那一段，等于没显示。
_LONG_STR = 120


def _string_diff(a: str, b: str, width: int = 60) -> str:
    """长字符串的差异：首个不同字符的下标 + 两侧上下文。"""
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    if i == n:
        return f"长度 {len(a)} → {len(b)}（前 {n} 字符相同）"
    lo = max(0, i - 20)
    return (f"长度 {len(a)} → {len(b)}，首处不同在第 {i} 字符\n"
            f"        快照 …{a[lo:i + width]}…\n"
            f"        现算 …{b[lo:i + width]}…")


def _short(value: Any, width: int = 160) -> str:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) \
        else value
    return text if len(text) <= width else text[:width] + f"…(+{len(text) - width})"


def _write(path: Path, snapshot: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=1, sort_keys=True)
                    + "\n", encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="acceptance",
        description="采集/比对仓库可观察面的等效性快照（只读，不改生产代码）")
    parser.add_argument("--snapshot", type=Path, metavar="OUT",
                        help="现算七面并写入 OUT")
    parser.add_argument("--verify", type=Path, metavar="GOLDEN",
                        help="现算并与 GOLDEN 逐路径比对；有差异退出码 3")
    parser.add_argument("--faces", default=",".join(FACES),
                        help=f"逗号分隔的面子集，缺省全部：{','.join(FACES)}")
    args = parser.parse_args(argv)

    if bool(args.snapshot) == bool(args.verify):
        parser.error("必须且只能给一个：--snapshot OUT 或 --verify GOLDEN")

    faces = tuple(f.strip() for f in args.faces.split(",") if f.strip())
    unknown = [f for f in faces if f not in _COLLECTORS]
    if unknown:
        parser.error(f"未知的面：{unknown}；可用：{list(_COLLECTORS)}")

    fresh = collect(faces)

    if args.snapshot:
        _write(args.snapshot, fresh)
        size = args.snapshot.stat().st_size
        print(f"快照已写入 {args.snapshot}（{len(faces)} 面，{size} 字节）")
        return 0

    if not args.verify.exists():
        print(f"找不到基线 {args.verify}", file=sys.stderr)
        return 2
    golden = json.loads(args.verify.read_text(encoding="utf-8"))
    diffs = _diff(golden, fresh)
    if not diffs:
        print(f"等效：{len(faces)} 面与 {args.verify} 逐路径一致")
        return 0
    print(f"不等效：与 {args.verify} 有 {len(diffs)} 处差异", file=sys.stderr)
    for line in diffs:
        print(f"  {line}", file=sys.stderr)
    if len(diffs) >= 40:
        print("  （差异已截断，只列前 40 条）", file=sys.stderr)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
