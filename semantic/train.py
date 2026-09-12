"""训练并导出语义规则的 head（P2-9 §9.2）。

    python3 -m semantic.train            # 训练 + 导出 + 写 MODEL.sha256
    python3 -m semantic.train --check    # 只核验已入库的模型（不重新训练）

**训练只发生在这一处，且只训练 head。** 特征图（:mod:`semantic.features`）是
固定随机投影，没有可训练参数 —— 这是信任边界条件 ② 的直接后果：特征必须由
输入确定性派生，否则「证明者声明特征」就等于 P0-1 的漏洞换个马甲。

产出（全部入库，因为它们是**契约的一部分**）：

| 文件 | 作用 |
|---|---|
| ``semantic/model.onnx`` | 被 ezkl 编译、被 ``onnx_sha256`` 承诺的图 |
| ``semantic/head.weights.json`` | head 权重（人类可读，便于复现与审计） |
| ``semantic/MODEL.sha256`` | ONNX 的 sha256 —— 约束里的 ``onnx_sha256`` 就取它 |
| ``semantic/training_report.json`` | 超参、留出集指标、**两次独立导出的哈希** |

**为什么把「两次导出哈希相同」写进报告**：ONNX 导出是否逐字节确定，取决于
torch 版本与导出器实现，不是可以假定的事实。报告里存着两个**独立子进程**跑出来的
哈希，一旦哪天不等，``--check`` 会立刻炸掉，而不是让 ``onnx_sha256`` 悄悄漂移。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:       # 允许 python3 semantic/train.py 直接跑
    sys.path.insert(0, str(REPO))

from semantic import dataset as ds          # noqa: E402
from semantic import features as F          # noqa: E402

__all__ = ["train", "evaluate", "export_and_write", "main"]

EPOCHS = 400
LR = 5e-3
BATCH = 64


def _tensorize(rows: Sequence[Tuple[str, int]]):
    """把 ``[(text, label)]`` 变成 ``(X, y)`` 两个 torch 张量。

    注意输入是**浮点 id**（图的第一层就是浮点，与 ezkl 的量化口径一致）。
    """
    import torch

    x = torch.tensor([F.encode(t) for t, _ in rows], dtype=torch.float32)
    y = torch.tensor([[float(lab)] for _, lab in rows], dtype=torch.float32)
    return x, y


def evaluate(net, rows: Sequence[Tuple[str, int]]) -> Dict[str, object]:
    """在给定行上算指标 + 误判清单（误判要能看见，不能只报一个准确率）。"""
    import torch

    x, y = _tensorize(rows)
    with torch.no_grad():
        p = net(x).flatten()
    wrong = [(rows[i][0], int(y[i].item()), float(p[i].item()))
             for i in range(len(rows)) if (p[i] >= 0.5).item() != (y[i] >= 0.5).item()]
    acc = 1.0 - len(wrong) / max(len(rows), 1)
    harmful = [float(p[i]) for i in range(len(rows)) if y[i].item() == 1.0]
    benign = [float(p[i]) for i in range(len(rows)) if y[i].item() == 0.0]
    return {
        "n": len(rows),
        "accuracy": acc,
        "min_harmful_score": min(harmful) if harmful else None,
        "max_benign_score": max(benign) if benign else None,
        "misclassified": wrong[:10],
        "n_misclassified": len(wrong),
    }


def train(seed: int = 20260912, per_class: int = 300, epochs: int = EPOCHS):
    """训练 head，返回 ``(net, report)``。**确定性**（同种子同结果）。"""
    import torch

    torch.manual_seed(seed)
    rows = ds.build_dataset(per_class=per_class, seed=seed)
    train_rows, test_rows = ds.split_dataset(rows)
    x, y = _tensorize(train_rows)

    net = F.build_net()
    # 只优化 head；投影表是 buffer，本来也不在参数里 —— 显式再滤一遍，
    # 免得日后有人往模块里加了可训练参数却不知情。
    params = [p for p in net.parameters() if p.requires_grad]
    opt = torch.optim.Adam(params, lr=LR)
    lossf = torch.nn.BCEWithLogitsLoss()

    n = len(train_rows)
    for ep in range(epochs):
        perm = torch.randperm(n)
        total = 0.0
        for i in range(0, n, BATCH):
            idx = perm[i:i + BATCH]
            opt.zero_grad()
            loss = lossf(net.logits(x[idx]), y[idx])
            loss.backward()
            opt.step()
            total += float(loss.item()) * len(idx)
        if ep % 100 == 0 or ep == epochs - 1:
            print(f"  epoch {ep:3d}  loss={total / n:.4f}")

    return net, {
        "seed": seed,
        "epochs": epochs,
        "lr": LR,
        "batch": BATCH,
        "per_class": per_class,
        "n_train": len(train_rows),
        "train": evaluate(net, train_rows),
        "holdout": evaluate(net, test_rows),
        "feature_version": F.FEATURE_VERSION,
        "projection_fingerprint": F.state_dict_fingerprint(),
    }


def export_and_write(net, report: Dict[str, object]) -> Dict[str, object]:
    """导出 ONNX + head 权重 + MODEL.sha256 + 训练报告（全部落盘）。"""
    onnx_path = F.MODEL_DIR / F.ONNX_NAME
    sha = F.export_onnx(net, onnx_path)
    (F.MODEL_DIR / "head.weights.json").write_text(
        json.dumps(F.head_state_dict(net), indent=1, sort_keys=True), encoding="utf-8")
    (F.MODEL_DIR / "MODEL.sha256").write_text(sha + "\n", encoding="utf-8")

    report = dict(report)
    report["onnx_sha256"] = sha
    report["onnx_bytes"] = onnx_path.stat().st_size
    report["dims"] = {"max_chars": F.MAX_CHARS, "dim": F.DIM,
                      "hidden": F.HIDDEN, "vocab": F.VOCAB_SIZE}
    (F.MODEL_DIR / "training_report.json").write_text(
        json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")
    return report


def export_in_subprocess() -> str:
    """在**独立子进程**里重新导出一遍（不训练），返回其 sha256。

    同进程里导两次是测不出问题的：任何进程级缓存都会掩盖不确定性。这条路径
    也正是 ``train.main`` 与 ``--check`` 用来钉死「导出逐字节确定」的机制。
    """
    code = (
        "import sys; sys.path.insert(0, {repo!r});"
        "from semantic import features as F;"
        "net = F.build_net(F.load_head_state());"
        "print(F.export_onnx(net, {out!r}))"
    ).format(repo=str(REPO), out=str(F.MODEL_DIR / "model.resmoke.onnx"))
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          cwd=str(REPO), timeout=1800)
    if proc.returncode != 0:
        raise RuntimeError(f"子进程导出失败：\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout.strip().splitlines()[-1]


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="训练并导出语义规则的 head（P2-9）")
    ap.add_argument("--check", action="store_true", help="只核验已入库的模型，不重新训练")
    ap.add_argument("--epochs", type=int, default=EPOCHS)
    ap.add_argument("--per-class", type=int, default=300)
    ap.add_argument("--seed", type=int, default=20260912)
    args = ap.parse_args(argv)

    if args.check:
        return _check()

    print(f"训练：per_class={args.per_class} epochs={args.epochs} seed={args.seed}")
    net, report = train(seed=args.seed, per_class=args.per_class, epochs=args.epochs)
    report = export_and_write(net, report)

    again = export_in_subprocess()
    (F.MODEL_DIR / "model.resmoke.onnx").unlink(missing_ok=True)
    report["onnx_sha256_repeat"] = again
    report["export_deterministic"] = (again == report["onnx_sha256"])
    (F.MODEL_DIR / "training_report.json").write_text(
        json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")

    print(f"onnx_sha256 = {report['onnx_sha256']}")
    print(f"重复导出     = {again}  {'一致' if report['export_deterministic'] else '不一致 ✗'}")
    print(f"训练集 acc={report['train']['accuracy']:.4f}  "
          f"留出集 acc={report['holdout']['accuracy']:.4f}  "
          f"(误判 {report['holdout']['n_misclassified']}/{report['holdout']['n']})")
    if not report["export_deterministic"]:
        print("✗ 导出不确定 —— onnx_sha256 会漂移，不能作为契约字段", file=sys.stderr)
        return 1
    return 0


def _check() -> int:
    """核验入库产物自洽：sha256 与文件一致、重复导出一致、报告指标可复算。"""
    onnx_path = F.MODEL_DIR / F.ONNX_NAME
    sha_file = F.MODEL_DIR / "MODEL.sha256"
    if not onnx_path.exists() or not sha_file.exists():
        print("✗ 模型未入库 —— 先跑 python3 -m semantic.train", file=sys.stderr)
        return 1
    want = sha_file.read_text(encoding="utf-8").strip()
    got = hashlib.sha256(onnx_path.read_bytes()).hexdigest()
    print(f"model.onnx sha256 = {got}")
    print(f"MODEL.sha256      = {want}")
    if want != got:
        print("✗ 不符", file=sys.stderr)
        return 1

    net = F.build_net(F.load_head_state())
    rep = json.loads((F.MODEL_DIR / "training_report.json").read_text(encoding="utf-8"))
    rows = ds.build_dataset(per_class=rep.get("per_class", 300), seed=rep.get("seed", 0))
    _, test_rows = ds.split_dataset(rows)
    got_holdout = evaluate(net, test_rows)
    print(f"留出集复算 acc = {got_holdout['accuracy']:.4f} "
          f"(报告 {rep['holdout']['accuracy']:.4f})")
    if abs(got_holdout["accuracy"] - rep["holdout"]["accuracy"]) > 1e-9:
        print("✗ 留出集指标与报告不符", file=sys.stderr)
        return 1

    again = export_in_subprocess()
    (F.MODEL_DIR / "model.resmoke.onnx").unlink(missing_ok=True)
    print(f"重复导出 sha256   = {again}  {'一致' if again == got else '不一致 ✗'}")
    return 0 if again == got else 1


if __name__ == "__main__":
    raise SystemExit(main())
