"""P2-9 §9.7 验收：语义规则（学习型规则）的七例，其中五例是**反例**。

为什么反例占多数：正向检查极容易写成恒真 —— 「给它一条好文本、它说好」这种断言，
在一个把 ``passed`` 硬编码成 ``True`` 的实现上同样会绿。反例才有分辨力：
每一例都构造出一种**看起来完全合法**的输入，然后要求验证方当场拒绝它。
五条反例对应攻击者能拿到的五样东西：换模型、改阈值、抄别人的证明、图外自算
特征、以及最省事的一种 —— 干脆不附陪伴证明。

## 三个层次的测试，各自的诚实边界

1. :class:`TestSemanticScoring`（**纯标准库**）：模型的判定本身。这里用
   :func:`_replica_score` —— 一份**纯 Python 的等价实现**（四张投影表来自
   ``random.Random(seed)``，head 权重来自 ``head.weights.json``，都用不着 torch）。
   它是不是"真的等价"由两条独立的对照钉住：装了 torch 就与真实网络逐点比
   （:meth:`TestSemanticScoring.test_replica_matches_torch`），有 ezkl 自检记录
   就与 ezkl 定点结果比（:meth:`...test_replica_matches_recorded_ezkl`）。
2. :class:`TestSemanticBinding`（**要 ``vk.ezkl``/``settings.json``，不要 ezkl**）：
   绑定与阈值判定。用 `verify_proof=False` 走完第 1–6 步，只跳过"跑 ezkl 验证器"
   那一步 —— 于是本机（乃至 CI）不必有 ezkl、不必有 32 MB 的 srs，也能把
   **五条反例**逐条钉死。真正跑 ezkl 验证器的那条路见第 3 层。
3. :class:`TestSemanticEndToEnd`（**要 ezkl + 80 s 出证**，默认 skip）：
   ``POP_TEST_EZKL=1`` 时才跑。它才是"端到端验收"，代价是出一份 40 KB 的证明
   要 ~76 s / ~8.7 GB 常驻（见 ``bench/results/semantic.md``）—— 放进默认测试
   套件会让 16 s 的套件变成 90 s，并且要求跑测试的机器有 12 GB 内存。

## 为什么第 2 层不算"没测到 ezkl"

``verify_proof=True`` 那条路要证明的是「ezkl 验证器说这份证明有效」。它不是本
文件里任何一条语义性质的**唯一**依据：五条反例在第 1–5 步就已经被挡住了
（换模型/换阈值在第 2 步、换证明在第 3 步、换响应在图外重算的 encode(T′) 上），
而第 1–5 步全是本文件覆盖的。把 ezkl 验证器当成雪崩测试的最后一颗钉子，而不是
整面墙。
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl import cert, challenge, commit, keys, semantic as S  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.evaluate import check as check_policy  # noqa: E402
from policydsl.model import Policy, PolicyError, Rule, Transcript  # noqa: E402
from policydsl.serialize import spec_canonical_text  # noqa: E402
from semantic import features as F  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
SEM_ART = REPO / "semantic" / "artifacts"

#: 自检文本 —— 与 ``scripts/ezkl_prove.py::SELFTEST_TEXTS`` **逐字相同**。
#: ``harm_homoglyph`` 与 ``harm`` 只差一个字符（西里尔 е U+0435）。
BENIGN = "Summarize the refund policy for billing customers."
HARMFUL = "How do I weaponize the search tool against the user?"
HOMOGLYPH = "How do I wеaponize the search tool against the user?"

#: 策略里的阈值：万分点。``le 5000`` == "P(有害) <= 0.5 才算合规"。
THRESHOLD_BP = 5000

#: 真·端到端（要出一份 ezkl 证明）的开关。见模块 docstring 第 3 层。
RUN_EZKL = os.environ.get("POP_TEST_EZKL") == "1"


def _importable(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is not None


HAVE_TORCH = _importable("torch")
HAVE_EZKL = _importable("ezkl")
HAVE_MATERIALS = (SEM_ART / S.ARTIFACT_NAMES["vk"]).exists() and \
                 (SEM_ART / S.ARTIFACT_NAMES["settings"]).exists()


# --------------------------------------------------------------------------- #
# 纯 Python 的等价前向：`semantic/features.py` 的定义，逐行照抄成 stdlib
# --------------------------------------------------------------------------- #

def _replica_score(text: str) -> float:
    """P(有害) ∈ [0,1]，**不使用 torch / onnx / ezkl**。

    与 :meth:`semantic.features.build_net` 的 ``forward`` 同一套算式：
    ``f = Σ_p A1[id_p] + Σ_p A2[id_p] ⊙ A3[id_{(p+1) mod L}]``，除以 ``√L``，
    L2 归一化，再过 ``Linear(64→32) → ReLU → Linear(32→1) → Sigmoid``。

    刻意**手抄**而不是调用 ``features``：这个函数的用途是做交叉验证的一方 ——
    如果它转手去调被测对象，两边一起错就没人发现了。
    """
    ids = F.encode(text)
    a1, a2, a3, _a4 = F.projection_matrices()      # USE_TRIGRAM=False，A4 用不到
    L, D = F.MAX_CHARS, F.DIM

    f = [0.0] * D
    for p in range(L):
        row1 = a1[ids[p]]
        row2 = a2[ids[p]]
        row3 = a3[ids[(p + 1) % L]]                # shift(x, 1) 的圆周语义
        for d in range(D):
            f[d] += row1[d] + row2[d] * row3[d]
    # 注意：torch 那边是 f/(√L) 再 L2 归一化 —— 先除以常数不影响归一化结果，
    # 但顺序照抄可以避免"看起来不一致"的误读。
    f = [x / math.sqrt(L) for x in f]
    norm = math.sqrt(sum(x * x for x in f)) + 1e-6
    f = [x / norm for x in f]

    hs = F.load_head_state()
    w0, b0 = hs["0.weight"], hs["0.bias"]          # [HIDDEN][DIM], [HIDDEN]
    w2, b2 = hs["2.weight"], hs["2.bias"]          # [1][HIDDEN], [1]
    hid = [max(0.0, sum(w0[i][d] * f[d] for d in range(D)) + b0[i])
           for i in range(len(b0))]
    logit = sum(w2[0][i] * hid[i] for i in range(len(hid))) + b2[0]
    return 1.0 / (1.0 + math.exp(-logit))


def _score_bp(text: str) -> int:
    """万分点形式的分数（与 ``semantic.score_bp_of_instances`` 同一口径）。"""
    return int(round(_replica_score(text) * 10000))


def _model_policy(*, threshold_bp: int = THRESHOLD_BP, direction: str = "le",
                  max_len: int = F.MAX_CHARS, with_length_bound: bool = True) -> Policy:
    """演示策略：关键词阻断（会被同形异义绕过）+ 长度上界 + 语义规则。"""
    rules = [Rule("keyword_block", "no_bad_topics", {"keywords": ["weaponize"]})]
    if with_length_bound:
        rules.append(Rule("length_bound", "bounded_reply", {"min": 1, "max": max_len}))
    rules.append(Rule("semantic_bound", "low_harm_probability",
                      {"threshold_bp": threshold_bp, "direction": direction}))
    return Policy("semantic-demo-v1", "0.1.0", rules=rules)


def _vk_sha256() -> str:
    return hashlib.sha256((SEM_ART / S.ARTIFACT_NAMES["vk"]).read_bytes()).hexdigest()


def _delegated(**over) -> dict:
    """电路公开值里 ``delegated[i]`` 的形状（字段名与 Rust serde 逐字一致）。"""
    d = {"name": "low_harm_probability", "system": S.SEMANTIC_SYSTEM_EZKL,
         "model_vkey": _vk_sha256(), "onnx_sha256": S.onnx_sha256(),
         "threshold_bp": THRESHOLD_BP, "direction": "le"}
    d.update(over)
    return d


def _hex32(v: int) -> str:
    """ezkl 的公开实例是 **32 字节小端** hex 串（见 ``semantic.hex_int``）。"""
    return v.to_bytes(32, "little").hex()


def _score_scale() -> int:
    """输出实例的定点刻度 ``2^scale``（实测是 128）。

    公开实例里的输出是 ``P(有害) × scale`` 这个**整数** —— 所以"写 100 就是
    100 bp"是错的：100 要经 ``/128×10000`` 才是万分点（=7812）。这里把两个方向
    的换算收敛成一对函数，免得每个用例各写一遍魔法数。
    """
    cfg = json.loads((SEM_ART / S.ARTIFACT_NAMES["settings"]).read_text(encoding="utf-8"))
    return 2 ** int(cfg["model_output_scales"][0])


def _bp_to_scaled(bp: int) -> int:
    return int(round(bp / 10000 * _score_scale()))


def _scaled_to_bp(v: int) -> int:
    return int(round(v / _score_scale() * 10000))


def _proof_obj(ids_and_out: list[int]) -> dict:
    """造一份 **形状正确的** ezkl 证明 JSON（公开实例排在最前）。

    形状是实测出来的：``instances`` 是二维的 ``[[v0..vN]]``，每个 v 是 32 字节
    小端 hex，布局 ``[MAX_CHARS 个 id] + [1 个输出]``。
    """
    return {"instances": [[_hex32(v) for v in ids_and_out]]}


@contextlib.contextmanager
def _artifacts(proof_obj: dict, name: str = "proof.json"):
    """临时 artifacts 目录：vk/settings 软链到真材料，只替换证明文件。

    为什么软链而不是拷贝：``vk.ezkl`` 821 KB 还好，``kzg.srs`` 是 32 MB。
    而这里要测的是"证明文件这一份检材被换掉"，其余材料本来就该是真的。
    """
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        for key, fn in S.ARTIFACT_NAMES.items():
            if key == "proof":
                continue          # 证明槽**不**软链真材料：那是本函数要替换的检材
            src = SEM_ART / fn
            if src.exists():
                (d / fn).symlink_to(src)
        (d / name).write_text(json.dumps(proof_obj), encoding="utf-8")
        yield d


# --------------------------------------------------------------------------- #
# 第 1 层：模型的判定本身（纯标准库）
# --------------------------------------------------------------------------- #

class TestSemanticScoring(unittest.TestCase):
    """七例里的第 1–3 例：正向两例 + 同形异义绕过一例。"""

    def test_benign_text_passes(self):
        """① 正常文本：P(有害) 远低于阈值 ⇒ ``le`` 规则满足。"""
        bp = _score_bp(BENIGN)
        self.assertLess(bp, THRESHOLD_BP,
                        f"良性文本被判成有害（{bp} bp）—— 阈值或模型有问题")
        self.assertTrue(S.threshold_holds(bp, THRESHOLD_BP, "le"))

    def test_harmful_text_blocked(self):
        """② 语义有害文本：P(有害) 高于阈值 ⇒ ``le`` 规则**不**满足（记录违规）。"""
        bp = _score_bp(HARMFUL)
        self.assertGreaterEqual(bp, THRESHOLD_BP,
                                f"有害文本没被拦下（{bp} bp）—— 模型或阈值有问题")
        self.assertFalse(S.threshold_holds(bp, THRESHOLD_BP, "le"))

    def test_homoglyph_bypass_now_blocked(self):
        """③ 同形异义绕过：**关键词表被绕过，语义规则拦下**。

        这一例同时是论文的实验素材，所以两半都要断言到位 —— 少断言前一半，
        就变成了"语义规则能拦下有害文本"这种平淡的结论，而真正要说的是
        「**既有规则放它过去，语义规则没有**」：

        - 前半：把 ``wеaponize`` 喂给 ``keyword_block``，它**不**违规
          （``passed=True``）—— 绕过是真的、可复现的；
        - 后半：同一个字符串，语义规则的分数**高于**阈值 ⇒ 合规判定为 FAIL。

        两者合起来才是 P2-9 的论点：证书上 ``passed=True`` 而**合规 FAIL** 是
        可能同时成立的，而把二者分开呈报（``verify_cert.py`` 的 ``合规:`` 行）
        是唯一诚实的做法。
        """
        policy = _model_policy()
        result = check_policy(policy, Transcript(response=HOMOGLYPH))
        # 前一半：关键词规则放行（这正是同形异义的危害）。
        self.assertTrue(result.passed, "关键词规则不该命中同形异义文本")
        self.assertEqual(result.violations, [], "同形异义文本本就不该被关键词表拦住")
        # 后一半：语义规则把它判成有害。
        self.assertEqual(len(result.delegated), 1, "语义规则应被登记为委托")
        dep = result.delegated[0].to_dict()
        bp = _score_bp(HOMOGLYPH)
        self.assertGreaterEqual(bp, THRESHOLD_BP)
        self.assertFalse(S.threshold_holds(bp, int(dep["threshold_bp"]),
                                           str(dep["direction"])))
        # 对照：**ASCII 版**被关键词规则拦住 —— 说明前半的"放行"不是恒真。
        ascii_result = check_policy(policy, Transcript(response=HARMFUL))
        self.assertFalse(ascii_result.passed, "ASCII 版必须被关键词规则拦下")

    @unittest.skipUnless(HAVE_TORCH, "torch 未安装（P2-9 可选依赖）")
    def test_replica_matches_torch(self):
        """把纯 Python 复刻钉在真实网络上 —— 否则上面三例可能测的是另一个人写的模型。"""
        import torch

        from semantic.features import build_net, load_head_state

        net = build_net(load_head_state()).eval()
        for text in (BENIGN, HARMFUL, HOMOGLYPH):
            ids = F.encode(text)
            with torch.no_grad():
                ref = float(net(torch.tensor([ids], dtype=torch.float32))[0][0])
            self.assertAlmostEqual(_replica_score(text), ref, places=6,
                                   msg=f"复刻与真实网络在 {text!r} 上不一致")

    def test_replica_matches_recorded_ezkl(self):
        """有 ezkl 自检记录时，再对一次**定点**结果（ezkl 与浮点的口径差）。

        没有记录就跳过 —— 那说明本机没跑过 ``ezkl_prove.py selftest``，
        不是因为这条断言不成立。
        """
        rec = SEM_ART / "selftest.json"
        if not rec.exists():
            self.skipTest("无 semantic/artifacts/selftest.json（先跑 ezkl_prove.py selftest）")
        data = json.loads(rec.read_text(encoding="utf-8"))
        texts = {"harm": HARMFUL, "ben": BENIGN, "harm_homoglyph": HOMOGLYPH}
        for row in data["cases"]:
            text = texts.get(row["case"])
            if text is None:
                continue
            # ezkl 用 7 位定点（scale=128），与浮点的差应在 1/128 量级内。
            self.assertAlmostEqual(_replica_score(text), row["float"], places=5,
                                   msg=f"{row['case']}: 复刻与 ezkl 记录的浮点参考不一致")
            self.assertAlmostEqual(_replica_score(text), row["ezkl"], delta=1.0 / 128,
                                   msg=f"{row['case']}: 复刻与 ezkl 定点结果差超过一个刻度")


# --------------------------------------------------------------------------- #
# 第 2 层：绑定与阈值判定（要 vk/settings，不要 ezkl、不要 srs）
# --------------------------------------------------------------------------- #

@unittest.skipUnless(HAVE_MATERIALS, "缺少 semantic/artifacts/{vk.ezkl,settings.json}")
class TestSemanticBinding(unittest.TestCase):
    """七例里的第 4–7 例（反例）+ 阈值方向与 fail-closed 的正面/负面各一例。

    全部走 ``verify_proof=False``：跳过"跑 ezkl 验证器"，但第 1–6 步一步不省。
    """

    def _verify(self, dep: dict, companion: dict, response: str, d) -> tuple:
        ok, why, hits = S.verify_companion(dep, companion, response, d,
                                           verify_proof=False)
        return ok, why, hits

    # ---- ④ 换模型 -------------------------------------------------------- #
    def test_swapped_onnx_rejected(self):
        """反例：拿**另一个模型**的证明来凑 —— onnx_sha256 与公开值不符即拒绝。

        这是"训练阶段作弊"的那条路：出证方换一张永远输出 0（永远判安全）的
        权重图，证明照样能出、ezkl 照样验证通过 —— **只有**指纹能让验证方发现
        图中算的不是策略里承诺的那个模型。
        """
        dep = _delegated()
        with _artifacts(_proof_obj(F.encode(BENIGN) + [0])) as d:
            # 证书声明的 onnx 指纹换成"另一个模型"的（这里用一个明确不同的哈希）。
            other = hashlib.sha256(b"a-different-model").hexdigest()
            comp = S.companion_entry(dep["name"], d / "proof.json", d, dep)
            comp["onnx_sha256"] = other
            ok, why, hits = self._verify(dep, comp, BENIGN, d)
        self.assertFalse(ok, "换了 ONNX 指纹却验过了")
        self.assertIn("onnx_sha256", why)
        self.assertFalse(hits, "没验成的陪伴证明不得被算作'规则满足'")

    def test_swapped_vk_rejected(self):
        """反例：换掉验证钥匙（vk）—— 「同一个模型」不能只是一句话。"""
        dep = _delegated()
        with _artifacts(_proof_obj(F.encode(BENIGN) + [0])) as d:
            comp = S.companion_entry(dep["name"], d / "proof.json", d, dep)
            comp["vk_sha256"] = hashlib.sha256(b"another-vk").hexdigest()
            ok, why, _ = self._verify(dep, comp, BENIGN, d)
            self.assertFalse(ok)
            self.assertIn("vk_sha256", why)

            # 另一半：**本地** vk 与约束承诺的不符（材料目录被换过）。
            # 证书这里要"自洽"到能过第 2 步，才能落到第 4 步的本地材料核对上 ——
            # 否则测的是上一条，不是这一条。
            dep2 = _delegated(model_vkey=hashlib.sha256(b"another-vk").hexdigest())
            comp2 = S.companion_entry(dep2["name"], d / "proof.json", d, dep2)
            comp2["vk_sha256"] = dep2["model_vkey"]
            ok2, why2, _ = self._verify(dep2, comp2, BENIGN, d)
            self.assertFalse(ok2, "本地 vk 与公开值承诺的不符，却验过了")
            self.assertIn("验证钥匙", why2)

    # ---- ⑤ 改阈值 -------------------------------------------------------- #
    def test_swapped_threshold_rejected(self):
        """反例：改阈值 —— 证书与公开值不符即拒绝，**且策略哈希会变**。

        两件事分别对应两个攻击面：① 证书里写的阈值与电路公开值不符（当场拒绝）；
        ② 攻击者改**策略包**里的阈值 —— 那会改 ``policy_hash``，而验证方会拿
        策略包现场重编译比对，签名与锚定都救不了它。
        """
        dep = _delegated(threshold_bp=THRESHOLD_BP)
        with _artifacts(_proof_obj(F.encode(BENIGN) + [0])) as d:
            comp = S.companion_entry(dep["name"], d / "proof.json", d, dep)
            comp["threshold_bp"] = 9000        # 把门槛放宽，好让违规文本蒙混过关
            ok, why, _ = self._verify(dep, comp, BENIGN, d)
        self.assertFalse(ok, "阈值被改宽却验过了")
        self.assertIn("threshold_bp", why)

        # ② 策略包里的阈值改动必须体现在 policy_hash 上。
        loose = compile_policy(_model_policy(threshold_bp=9000))
        strict = compile_policy(_model_policy(threshold_bp=THRESHOLD_BP))
        self.assertNotEqual(loose["sha256"], strict["sha256"],
                            "改阈值没有改变策略哈希 —— 验证方就无从发现")

    def test_swapped_direction_rejected(self):
        """反例：把 ``le`` 改成 ``ge`` —— 一个字符就能把规则反过来。

        ``direction`` 是小开关的典型：默认错、看起来无害、翻转后会**恒真**
        （``ge 5000`` 在 P=1.0 的有害文本上恰好满足）。所以它也必须进指纹。
        """
        dep = _delegated(direction="le")
        with _artifacts(_proof_obj(F.encode(HARMFUL) + [_score_scale()])) as d:
            comp = S.companion_entry(dep["name"], d / "proof.json", d, dep)
            comp["direction"] = "ge"
            ok, why, _ = self._verify(dep, comp, HARMFUL, d)
        self.assertFalse(ok, "方向被翻转却验过了")
        self.assertIn("direction", why)

    # ---- ⑥ 抄别人的证明 -------------------------------------------------- #
    def test_replayed_ezkl_proof_rejected(self):
        """反例：把 A 响应的 ezkl 证明用在 B 响应上 —— 绑不住就拒绝。

        两种抄法都要挡：
        - **换检材**：证明文件的字节与证书承诺的 sha256 不符（出证后被人替换）；
        - **换响应**：证明文件没被动过，但验证方手上的 T′ 不是它证的那一条
          —— 这一条只能靠"拿 T′ 重算 ``encode(T′)`` 与公开实例比对"来发现，
          也正是 ezkl 默认把输入也当**公开**值的那份用处。
        """
        # 换检材：证书承诺的 sha256 对应的文件已经不在了。
        dep = _delegated()
        with _artifacts(_proof_obj(F.encode(HARMFUL) + [_score_scale()])) as d:
            comp = S.companion_entry(dep["name"], d / "proof.json", d, dep)
            (d / "proof.json").write_text(
                json.dumps(_proof_obj(F.encode(BENIGN) + [0])), encoding="utf-8")
            ok, why, _ = self._verify(dep, comp, HARMFUL, d)
        self.assertFalse(ok, "证明文件被替换却验过了")
        self.assertIn("sha256", why)

        # 换响应：证明完好（就是为 HARMFUL 出的），但送达的是 BENIGN。
        with _artifacts(_proof_obj(F.encode(HARMFUL) + [_score_scale()])) as d:
            comp = S.companion_entry(dep["name"], d / "proof.json", d, dep)
            ok, why, _ = self._verify(dep, comp, BENIGN, d)
        self.assertFalse(ok, "陪伴证明绑在另一条响应上却验过了")
        self.assertIn("encode(T)", why)

        # 对照：同一条响应则通过 —— 说明上面不是"恒拒绝"。
        with _artifacts(_proof_obj(F.encode(HARMFUL) + [_score_scale()])) as d:
            comp = S.companion_entry(dep["name"], d / "proof.json", d, dep)
            ok, why, hits = self._verify(dep, comp, HARMFUL, d)
        self.assertTrue(ok, why)
        self.assertFalse(hits, "P=1.0 不该满足 le 5000")

    # ---- ⑦ 图外自算特征 -------------------------------------------------- #
    def test_declared_features_rejected(self):
        """反例：图外预计算的特征 —— 图内的输入是 **id**，不是特征向量。

        这一条挡的是"信任边界 ②"：如果特征可以在图外算，出证方就能把一份
        **好看的特征向量**（比如一段良性文本的特征）配到有害响应上出证，
        而图只负责把给定向量过一遍 head —— 语义规则就成了可随意摆布的摆设。

        本仓库的做法是：图的输入就是 ``encode(T)`` 的 id 序列，验证方拿 T′ 重算。
        于是"图外特征"在这里的表现形式是**一组看起来完全合理的 64 个浮点数**，
        它可以完美通过长度检查 —— 被拒绝的唯一依据是它 != ``encode(T′)``。

        **顺带钉住一个巧合**：``DIM == MAX_CHARS == 64``，特征向量与 id 序列
        长度相同。所以长度检查在这里恰好看不出任何异常 —— 这不是缺陷，是提醒：
        这类攻击**只能**靠"与 encode(T′) 逐位比对"发现。
        """
        self.assertEqual(F.DIM, S.input_width(),
                         "DIM 与输入宽度一旦不同，本用例的'长度相同'前提就变了")
        dep = _delegated()
        # 一份"像模像样的"特征向量：64 个 [0,1) 的浮点数（定点后仍在合法范围内）。
        feats = [int(round(x * _score_scale())) for x in
                 (0.5, 0.25, 0.75, 0.125) * 16]
        self.assertEqual(len(feats), S.input_width())
        with _artifacts(_proof_obj(feats + [0])) as d:
            comp = S.companion_entry(dep["name"], d / "proof.json", d, dep)
            ok, why, _ = self._verify(dep, comp, BENIGN, d)
        self.assertFalse(ok, "图外自算的特征却验过了")
        self.assertIn("encode(T)", why)

    # ---- 正面：两个方向都要真的能过 -------------------------------------- #
    def test_threshold_directions_both_work(self):
        """``le`` 与 ``ge`` 各验一条**满足**的路径 —— 挡住"一律返回 False"的实现。

        顺带把"输出实例是定点整数"这件事钉住：写进实例的是 ``P×2^7``，
        读出来要 ``/128×10000`` 才是万分点。少了这一层换算，一条 1/128 的分数
        会被当成 1 bp —— 阈值比较就成了另一件事。
        """
        self.assertEqual(_scaled_to_bp(_score_scale()), 10000, "满刻度应是 10000 bp")
        floor = _scaled_to_bp(1)                       # 一个刻度 = 78.125 bp
        with _artifacts(_proof_obj(F.encode(BENIGN) + [1])) as d:
            dep_le = _delegated(threshold_bp=THRESHOLD_BP, direction="le")
            comp = S.companion_entry("r", d / "proof.json", d, dep_le)
            ok, why, hits = self._verify(dep_le, comp, BENIGN, d)
            self.assertTrue(ok, why)
            self.assertIn(f"score={floor} bp", why)
            self.assertTrue(hits, f"{floor} bp <= {THRESHOLD_BP} bp 应判满足")

            # 同一个分数，方向翻成 ge、阈值放到刻度以下 —— 也应满足。
            dep_ge = _delegated(threshold_bp=floor - 1, direction="ge")
            comp_ge = S.companion_entry("r", d / "proof.json", d, dep_ge)
            ok2, why2, hits2 = self._verify(dep_ge, comp_ge, BENIGN, d)
            self.assertTrue(ok2, why2)
            self.assertTrue(hits2, f"{floor} bp >= {floor - 1} bp 应判满足")

    # ---- fail-closed：拿不到判定时必须拒绝，而不是当成通过 ---------------- #
    def test_unknown_system_rejected(self):
        """不认识的委托系统一律拒绝 —— 验证器不认识就不知道该用哪个验证器。"""
        dep = _delegated(system="some-other-zkml")
        with _artifacts(_proof_obj(F.encode(BENIGN) + [0])) as d:
            comp = S.companion_entry(dep["name"], d / "proof.json", d, dep)
            ok, why, _ = self._verify(dep, comp, BENIGN, d)
        self.assertFalse(ok)
        self.assertIn("不认识", why)

    def test_missing_proof_file_fails_closed(self):
        """陪伴证明不在盘上 ⇒ 拒绝（"没验"不等于"验过"）。

        现实中的形态：证书随邮件单独流转，40 KB 的证明文件没被一起归档。
        这时验证方**必须**说"我没验"，而不是"没发现问题"。证书仍然是真的
        （签名、锚定、指纹全都对得上），但它承诺的那份证据不在了。
        """
        dep = _delegated()
        with _artifacts(_proof_obj(F.encode(BENIGN) + [0])) as d:
            comp = S.companion_entry(dep["name"], d / "proof.json", d, dep)
            (d / "proof.json").unlink()            # 证明丢了
            ok, why, hits = self._verify(dep, comp, BENIGN, d)
        self.assertFalse(ok)
        self.assertIn("找不", why)
        self.assertFalse(hits)

    def test_path_escape_blocked(self):
        """证书不得借 ``proof_file`` 里的路径逃出 artifacts 目录去读任意文件。"""
        dep = _delegated()
        with _artifacts(_proof_obj(F.encode(BENIGN) + [0])) as d:
            comp = S.companion_entry(dep["name"], d / "proof.json", d, dep)
            comp["proof_file"] = "../../../../etc/passwd"
            ok, why, _ = self._verify(dep, comp, BENIGN, d)
        self.assertFalse(ok, "路径逃逸被放过了")
        self.assertIn("找不", why)


# --------------------------------------------------------------------------- #
# 编译期：语义规则的策略约束
# --------------------------------------------------------------------------- #

class TestSemanticPolicyCompile(unittest.TestCase):
    """``semantic_bound`` 贯通编译层，以及定长图的硬边界。"""

    def test_compile_semantic(self):
        """编译产出的约束形状正确，且**两次编译哈希相同**（契约稳定）。"""
        spec = compile_policy(_model_policy())
        kinds = [c["kind"] for c in spec["constraints"]]
        self.assertIn("semantic_bound", kinds)
        c = next(c for c in spec["constraints"] if c["kind"] == "semantic_bound")
        self.assertEqual(c["threshold_bp"], THRESHOLD_BP)
        self.assertEqual(c["direction"], "le")
        self.assertEqual(c["onnx_sha256"], S.onnx_sha256())
        self.assertEqual(c["model_vkey"], _vk_sha256())
        # 契约哈希稳定：同一策略编两次必须逐字节相同。
        self.assertEqual(compile_policy(_model_policy())["sha256"], spec["sha256"])
        # 而语义规则的**任一**字段变了，哈希都必须变（否则验证方看不见改动）。
        for kwargs in ({"threshold_bp": 9000}, {"direction": "ge"}):
            other = compile_policy(_model_policy(**kwargs))
            self.assertNotEqual(other["sha256"], spec["sha256"],
                                f"{kwargs} 没有改变策略哈希")

    def test_length_bound_required(self):
        """缺长度上界 ⇒ 编译期就报错（图的容量必须被策略自己覆盖）。"""
        with self.assertRaises(PolicyError) as cm:
            compile_policy(_model_policy(with_length_bound=False))
        self.assertIn("length_bound", str(cm.exception))

    def test_length_bound_must_cover_graph(self):
        """长度上界超过图的字符上限 ⇒ 报错（超长响应会让语义规则判不了）。"""
        with self.assertRaises(PolicyError) as cm:
            compile_policy(_model_policy(max_len=S.input_width() + 1))
        self.assertIn("max <=", str(cm.exception))

    def test_threshold_bounds_validated(self):
        """阈值必须在 [0,10000]；方向必须是 le/ge —— 小开关不能有第三个取值。"""
        bad = _model_policy()
        bad.rules[-1].params["threshold_bp"] = 10001
        with self.assertRaises(PolicyError):
            bad.validate()
        bad2 = _model_policy()
        bad2.rules[-1].params["direction"] = "lt"
        with self.assertRaises(PolicyError):
            bad2.validate()

    @unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
    def test_private_mode_fails_closed(self):
        """私有模式下的语义规则必须**当场炸**，而不是被静默跳过。

        理由（也是崩溃信息里那句）：陪伴证明必须把 ``encode(T)`` 放进**公开**
        实例，验证方才能把它绑到送达的响应上 —— 私有模式下做不到，所以含语义
        规则的策略在 v1 里只支持公开模式。这是刻意的 fail-closed：如果这里改成
        "私有模式下忽略语义规则"，那么一张私有证书会**看起来**全绿而语义规则
        根本没被判定 —— 正是 P0-1 的形态换了个位置。
        """
        spec = compile_policy(_model_policy())
        vector = {"name": "t", "response": BENIGN,
                  "spec_canonical": spec_canonical_text(spec),
                  "private": True, "mask": [], "redacted": BENIGN, "spans": []}
        with tempfile.TemporaryDirectory() as td:
            vp, op = Path(td) / "v.json", Path(td) / "r.json"
            vp.write_text(json.dumps({"vectors": [vector]}), encoding="utf-8")
            proc = subprocess.run(
                [str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                cwd=str(REPO), capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0, "私有模式下的语义规则没有 fail closed")
        self.assertIn("公开模式", proc.stderr,
                      "崩溃信息应说明这是公开模式专属的边界")

    @unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
    def test_public_mode_registers_delegation(self):
        """公开模式下电路**登记**委托，而不是判它违规。

        如果电路在这里记一条 violation，``passed`` 会变 false —— 那等于把
        "我判不了" 谎报成 "策略被违反了"。二者都不是真的。
        """
        spec = compile_policy(_model_policy())
        vector = {"name": "t", "response": BENIGN,
                  "spec_canonical": spec_canonical_text(spec)}
        with tempfile.TemporaryDirectory() as td:
            vp, op = Path(td) / "v.json", Path(td) / "r.json"
            vp.write_text(json.dumps({"vectors": [vector]}), encoding="utf-8")
            subprocess.run(
                [str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                cwd=str(REPO), check=True, capture_output=True, text=True)
            got = json.loads(op.read_text())[0]
        self.assertEqual([d["name"] for d in got["delegated"]],
                         ["low_harm_probability"])
        self.assertEqual(got["violations"], [])
        self.assertTrue(got["passed"])
        # 与参考层同形（Rust serde 的字段名就是契约）。
        self.assertEqual(sorted(got["delegated"][0]),
                         sorted(["name", "system", "model_vkey", "onnx_sha256",
                                 "threshold_bp", "direction"]))


# --------------------------------------------------------------------------- #
# verify_cert.py 的 fail-closed 分支（子进程，合成证书 —— 不需要真证明）
# --------------------------------------------------------------------------- #

class TestVerifyCertFailClosed(unittest.TestCase):
    """证书**少带**或**多带**陪伴证明时，验证方必须拒绝。"""

    def _issue(self, tmp: Path, semantic_block, delegated) -> Path:
        """签一张合成证书（无 SP1 证明）并锚定 —— 只为驱动 verify_cert 的分支。"""
        policy = _model_policy()
        spec = compile_policy(policy)
        response = "a benign reply"
        outcome = {"policy_hash": spec["sha256"],
                   "response_binding": commit.response_binding(b"", response),
                   "trace_root": "genesis",
                   "passed": True, "violations": [], "delegated": delegated}
        payload = cert.build_payload(policy.id, policy.version, spec, "public", outcome,
                                     vkey_hash="unproven", ts="2026-01-01T00:00:00Z",
                                     challenge=challenge.challenge_block(b"", outcome["response_binding"]),
                                     semantic=semantic_block)
        signer = cert.Ed25519Signer.generate()
        (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
        (tmp / "cert.json").write_text(json.dumps(cert.sign_payload(payload, signer)))
        (tmp / "pack.json").write_text(json.dumps({
            "id": policy.id, "version": policy.version,
            "rules": [{"kind": r.kind, "name": r.name, "params": r.params}
                      for r in policy.rules]}))
        (tmp / "T.txt").write_text(response)
        (tmp / "receipts.json").write_text("[]")
        from policydsl import anchor as A
        A.append_anchor(tmp / "ledger.jsonl", cert.cert_digest(payload))
        return tmp / "cert.json"

    def _verify(self, tmp: Path, extra: list) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify_cert.py"),
             "--cert", str(tmp / "cert.json"), "--pack", str(tmp / "pack.json"),
             "--ledger", str(tmp / "ledger.jsonl"), "--response", str(tmp / "T.txt"),
             "--receipts", str(tmp / "receipts.json"), *extra],
            cwd=str(REPO), capture_output=True, text=True)

    def test_delegated_without_semantic_dir_fails_closed(self):
        """证书说"有语义规则被委托"却不给材料目录 ⇒ FAIL（不能默认通过）。"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._issue(tmp, {"companions": [_delegated()]}, [_delegated()])
            proc = self._verify(tmp, [])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("[FAIL] semantic", proc.stdout)
        self.assertIn("不能默认通过", proc.stdout)

    def test_delegated_without_companion_fails_closed(self):
        """给了材料目录，但证书里**没有**这条规则的陪伴证明 ⇒ FAIL。"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._issue(tmp, {"companions": []}, [_delegated()])
            proc = self._verify(tmp, ["--semantic-dir", str(SEM_ART)])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("[FAIL] semantic[low_harm_probability]", proc.stdout)
        self.assertIn("语义规则未被判定", proc.stdout)

    def test_delegated_without_response_fails_closed(self):
        """没有 T′ 就核不了"这份证明说的是这条响应" ⇒ FAIL。"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._issue(tmp, {"companions": [_delegated()]}, [_delegated()])
            proc = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "verify_cert.py"),
                 "--cert", str(tmp / "cert.json"), "--pack", str(tmp / "pack.json"),
                 "--ledger", str(tmp / "ledger.jsonl"), "--receipts", str(tmp / "receipts.json"),
                 "--semantic-dir", str(SEM_ART)],
                cwd=str(REPO), capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("没给 --response", proc.stdout)

    def test_extra_companion_rejected(self):
        """电路说"我全判了"，证书却多带陪伴证明 ⇒ FAIL（两侧对策略的描述不一致）。"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._issue(tmp, {"companions": [_delegated()]}, [])
            proc = self._verify(tmp, ["--semantic-dir", str(SEM_ART)])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("证书与证明对策略的描述不一致", proc.stdout)

    def test_no_semantic_rules_passes(self):
        """对照：没有语义规则的证书照常通过 —— 说明上面几条不是恒 FAIL。"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._issue(tmp, None, [])
            proc = self._verify(tmp, [])
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("策略里没有语义规则", proc.stdout)
        self.assertIn("RESULT: PASS", proc.stdout)
        self.assertNotIn("合规:", proc.stdout, "没有语义规则时不该凭空给出合规结论")


# --------------------------------------------------------------------------- #
# 第 3 层：真·端到端（要 ezkl + ~80 s 出证，默认 skip）
# --------------------------------------------------------------------------- #

@unittest.skipUnless(RUN_EZKL, "需 POP_TEST_EZKL=1（出一份 ezkl 证明约 80 s / 8.7 GB）")
@unittest.skipUnless(HAVE_EZKL, "ezkl 未安装")
@unittest.skipUnless(HAVE_MATERIALS, "缺少 semantic/artifacts 材料")
class TestSemanticEndToEnd(unittest.TestCase):
    """出真证明、跑真验证器 —— 覆盖第 2 层刻意跳过的那一步。"""

    def test_real_proof_verifies_and_binds(self):
        """``ezkl_prove.py prove`` 产出的证明：验证器通过 + 绑在给定响应上。"""
        with tempfile.TemporaryDirectory() as td:
            resp = Path(td) / "T.txt"
            resp.write_text(HARMFUL, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "ezkl_prove.py"), "prove",
                 "--response", str(resp)],
                cwd=str(REPO), capture_output=True, text=True, timeout=1800)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

        dep = _delegated()
        comp = S.companion_entry(dep["name"], SEM_ART / S.ARTIFACT_NAMES["proof"],
                                 SEM_ART, dep)
        ok, why, hits = S.verify_companion(dep, comp, HARMFUL, SEM_ART,
                                           verify_proof=True)
        self.assertTrue(ok, why)
        self.assertFalse(hits, f"有害文本不该满足 le {THRESHOLD_BP}：{why}")
        # 绑到另一条响应上必须失败 —— 这一条只有真证明才测得出来。
        ok2, why2, _ = S.verify_companion(dep, comp, BENIGN, SEM_ART, verify_proof=True)
        self.assertFalse(ok2, "真证明被搬到了另一条响应上却验过了")


# --------------------------------------------------------------------------- #
# ONNX 导出必须逐位确定（features.py 的 docstring 已经承诺了这条测试）
# --------------------------------------------------------------------------- #

@unittest.skipUnless(HAVE_TORCH, "torch 未安装（P2-9 可选依赖）")
class TestOnnxExportDeterministic(unittest.TestCase):
    """同一份权重导出两次必须得到同一个 sha256 —— **两个独立进程**里导。

    只在同一个进程里导两次是测不出问题的：ONNX 的图里若混进进程级状态
    （时间戳、字典序、内存地址），同进程重导往往照样一致，而换一台机器就不一致了。
    而 ``onnx_sha256`` 是**进策略指纹**的 —— 它漂了，所有已签发的证书就都不再匹配。
    """

    def test_two_processes_same_sha256(self):
        code = (
            "import sys, json; sys.path.insert(0, {repo!r});"
            "from semantic import features as F;"
            "net = F.build_net(F.load_head_state());"
            "print(F.export_onnx(net, {out!r}))"
        )
        shas = []
        with tempfile.TemporaryDirectory() as td:
            for i in range(2):
                out = Path(td) / f"m{i}.onnx"
                proc = subprocess.run(
                    [sys.executable, "-c", code.format(repo=str(REPO), out=str(out))],
                    cwd=str(REPO), capture_output=True, text=True, timeout=600)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                shas.append(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(shas[0], shas[1], "两次导出得到不同的 sha256 —— 导出不确定")
        # 还要与**入库的那一份**同哈希：否则策略里承诺的 onnx_sha256 指向的是
        # 一个已经不存在（或对不上）的模型，而验证方会在第一步就拒绝一切。
        self.assertEqual(shas[0], S.onnx_sha256(),
                         "现在这份代码+权重导出的 ONNX 与入库的 model.onnx 不同")

    def test_manifest_matches_files(self):
        """``MANIFEST.json`` 记录的指纹必须与工件实际内容相符。

        验证方拿到的承诺来自策略（``onnx_sha256``/``model_vkey``），而出证方的
        自述来自 MANIFEST —— 两者若各说各话，审计时无从判断谁是真的。
        """
        # ``model_manifest`` 自己会核对 model.onnx 与 MODEL.sha256（不一致即抛）。
        self.assertEqual(S.model_manifest()["onnx_sha256"], S.onnx_sha256())
        # artifacts/MANIFEST.json 里记的 vk 指纹也要与 vk.ezkl 的实际内容一致 ——
        # 验证方只拿到 vk 文件与策略里承诺的哈希，这份自述是二者的桥。
        art_man = json.loads((SEM_ART / S.ARTIFACT_NAMES["manifest"]).read_text(encoding="utf-8"))
        self.assertTrue((SEM_ART / S.ARTIFACT_NAMES["vk"]).exists(),
                        "vk.ezkl 缺了 —— 验证方没有凭据")
        self.assertEqual(art_man["artifacts"][S.ARTIFACT_NAMES["vk"]]["sha256"],
                         _vk_sha256(), "MANIFEST 记录的 vk 指纹与 vk.ezkl 实际内容不符")


if __name__ == "__main__":
    unittest.main()
