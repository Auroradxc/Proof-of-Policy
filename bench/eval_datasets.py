#!/usr/bin/env python3
"""一键跑完三个外部数据集的评测（XSTest / Enron / τ-bench）+ 跨语言对拍。

把「数据集 → 策略包 + 测试向量 + 评测 + 电路层一致性」整条链路固化成一条命令，
结果汇成一张表，便于复现与写进报告。

用法（从仓库根）：
    python3 bench/eval_datasets.py \
        --xstest /path/to/xstest_prompts.csv \
        --enron  /path/to/enron_mail.tar.gz \
        --taubench /path/to/gpt-4o-airline.json

缺省会找 /tmp 下的同名文件；找不到则跳过对应数据集（如实标注）。

产出：
    policy_packs/{safety_xstest,pii_enron,toolarg_taubench,budget_taubench}_v1.json
    scripts/examples/datasets/*_vectors.json / *_results.json
    bench/results/datasets_summary.json
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DS = REPO / "scripts" / "datasets"

DEFAULTS = {
    "xstest": "/tmp/xstest_prompts.csv",
    "enron": "/home/dong/.claude/jobs/a8adbc15/tmp/enron_mail.tar.gz",
    "taubench": "/home/dong/.claude/jobs/a8adbc15/tmp/taubench_airline.json",
}


def parse_args(argv):
    d = dict(DEFAULTS)
    i = 1
    while i < len(argv):
        if argv[i] == "--xstest":
            d["xstest"] = argv[i + 1]; i += 2
        elif argv[i] == "--enron":
            d["enron"] = argv[i + 1]; i += 2
        elif argv[i] == "--taubench":
            d["taubench"] = argv[i + 1]; i += 2
        else:
            i += 1
    return d


def run(cmd):
    print(f"\n$ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=str(REPO), check=False).returncode


def main() -> int:
    paths = parse_args(sys.argv)

    status = {}
    # 1) XSTest
    if Path(paths["xstest"]).exists():
        rc = run([sys.executable, str(DS / "xstest2pack.py"), paths["xstest"]])
        status["xstest"] = "ok" if rc == 0 else f"fail({rc})"
    else:
        print(f"\n[XSTest] 跳过：找不到 {paths['xstest']}")
        status["xstest"] = "skipped"

    # 2) Enron
    if Path(paths["enron"]).exists():
        rc = run([sys.executable, str(DS / "enron2pack.py"), paths["enron"], "80"])
        status["enron"] = "ok" if rc == 0 else f"fail({rc})"
    else:
        print(f"\n[Enron] 跳过：找不到 {paths['enron']}")
        status["enron"] = "skipped"

    # 3) τ-bench
    if Path(paths["taubench"]).exists():
        rc = run([sys.executable, str(DS / "taubench2pack.py"), paths["taubench"]])
        status["taubench"] = "ok" if rc == 0 else f"fail({rc})"
    else:
        print(f"\n[τ-bench] 跳过：找不到 {paths['taubench']}")
        status["taubench"] = "skipped"

    # 3.5) 语义规则（演示模型 on XSTest）
    if status.get("xstest") == "ok":
        rc = run([sys.executable, str(DS / "semantic_xstest.py"), paths["xstest"]])
        status["semantic"] = "ok" if rc == 0 else f"fail({rc})"
    else:
        print("\n[语义规则] 跳过：XSTest 未就绪")
        status["semantic"] = "skipped"

    # 4) 跨语言对拍
    if status.get("xstest") == "ok" and status.get("enron") == "ok":
        run([sys.executable, str(DS / "cross_validate_datasets.py")])
        status["cross_validate"] = "ok"
    else:
        print("\n[跨语言对拍] 跳过：XSTest/Enron 未就绪")
        status["cross_validate"] = "skipped"

    # 汇总
    print("\n" + "=" * 60)
    print("数据集评测汇总")
    print("=" * 60)
    summary = {"status": status, "metrics": {}}
    for name, f in [("xstest", "xstest_results.json"),
                    ("enron", "enron_results.json"),
                    ("taubench", "taubench_results.json")]:
        p = REPO / "scripts" / "examples" / "datasets" / f
        if p.exists():
            d = json.loads(p.read_text())
            summary["metrics"][name] = d
            if name == "xstest":
                print(f"XSTest     : P={d['precision']} R={d['recall']} F1={d['f1']}")
            elif name == "enron":
                print(f"Enron      : 脱敏覆盖率={d['pii_coverage']} 类型={d['pii_types']}")
            else:
                tg = d["tool_arg_guard"]; bg = d["budget_bound"]
                print(f"τ-bench    : tool_arg F1={tg['f1']}  budget F1={bg['f1']}")

    sem_p = REPO / "scripts" / "examples" / "datasets" / "semantic_xstest_results.json"
    if sem_p.exists():
        d = json.loads(sem_p.read_text())
        summary["metrics"]["semantic"] = d
        print(f"语义模型   : XSTest 准确率={d['accuracy']}（阈值 {d['threshold']}，演示模型）")

    out = REPO / "bench" / "results" / "datasets_summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\n汇总已写: bench/results/datasets_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
