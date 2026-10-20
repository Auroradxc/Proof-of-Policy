#!/usr/bin/env python3
"""Enron 邮件 → 策略包 + 测试向量 + 评测（PII 检测 + 脱敏覆盖率）

Enron 是真实企业邮件，From/To/CC 头与正文里天然含 email 地址、姓名、电话号码，
是测 pattern_block（PII 规则）最经典的真实语料。

用法：
    python3 scripts/datasets/enron2pack.py [enron_mail.tar.gz] [抽样数]

产出：
    policy_packs/pii_enron_v1.json          策略包（email/phone/SSN 正则）
    scripts/examples/datasets/enron_vectors.json  测试向量
    scripts/examples/datasets/enron_results.json  评测（含 PII 占比、检测覆盖率）
"""
import json
import re
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from policydsl.core.model import Policy
from policydsl.core.evaluate import check

# 与策略包一致的 PII 正则（用于 ground-truth 计数与 pattern_block 规则，同一口径）
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
SSN_RE = re.compile(r"\d{3}-\d{2}-\d{4}")


def count_pii(text: str):
    """ground truth：统计一段文本里的 email/phone/SSN 实例数。"""
    return {
        "email": len(EMAIL_RE.findall(text)),
        "phone": len(PHONE_RE.findall(text)),
        "ssn": len(SSN_RE.findall(text)),
    }


def main() -> int:
    tar_path = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/dong/.claude/jobs/a8adbc15/tmp/enron_mail.tar.gz"
    sample_n = int(sys.argv[2]) if len(sys.argv) > 2 else 60

    # 1. 从 tar.gz 抽样邮件（不整包解压，流式读取头 + 体）
    emails = []
    with tarfile.open(tar_path, "r:gz") as tar:
        members = [m for m in tar.getmembers() if m.isfile()]
        step = max(1, len(members) // sample_n)
        for m in members[::step][:sample_n]:
            f = tar.extractfile(m)
            if f:
                try:
                    emails.append(f.read().decode("utf-8", errors="ignore"))
                except Exception:
                    pass

    if not emails:
        print("未抽到任何邮件（tar 路径或内容有误）", file=sys.stderr)
        return 1

    # 2. 构建 PII 策略包
    pack = {
        "id": "pii-enron-v1",
        "version": "0.1.0",
        "description": "PII redaction policy over real Enron emails "
                       "(email / phone / SSN patterns).",
        "semantic": "and",
        "rules": [
            {"kind": "pattern_block", "name": "no_pii_email",
             "params": {"patterns": [EMAIL_RE.pattern]}},
            {"kind": "pattern_block", "name": "no_pii_phone",
             "params": {"patterns": [PHONE_RE.pattern]}},
            {"kind": "pattern_block", "name": "no_pii_ssn",
             "params": {"patterns": [SSN_RE.pattern]}},
        ],
    }
    policy = Policy.from_dict(pack)

    # 3. 逐封邮件判定 + 统计
    vectors = []
    n_contain_pii = 0
    n_flagged = 0
    n_covered = 0  # 含 PII 且被判违规（= 检测覆盖）
    total_pii = 0
    pii_types = {"email": 0, "phone": 0, "ssn": 0}

    for i, text in enumerate(emails):
        gt = count_pii(text)
        has_pii = sum(gt.values()) > 0
        result = check(policy, text)
        flagged = not result.passed
        hit_kinds = [v.rule.name for v in result.violations]

        if has_pii:
            n_contain_pii += 1
        if flagged:
            n_flagged += 1
        if has_pii and flagged:
            n_covered += 1

        total_pii += sum(gt.values())
        pii_types["email"] += gt["email"]
        pii_types["phone"] += gt["phone"]
        pii_types["ssn"] += gt["ssn"]

        vectors.append({
            "id": i, "has_pii": has_pii,
            "pii_count": gt, "predicted": "violation" if flagged else "pass",
            "hit_rules": hit_kinds,
            "snippet": text[:200],
        })

    coverage = n_covered / n_contain_pii if n_contain_pii else 0.0

    # 4. 落盘
    out_dir = REPO / "scripts" / "examples" / "datasets"
    out_dir.mkdir(parents=True, exist_ok=True)
    (REPO / "policy_packs" / "pii_enron_v1.json").write_text(
        json.dumps(pack, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "enron_vectors.json").write_text(
        json.dumps(vectors, ensure_ascii=False, indent=2), encoding="utf-8")

    results = {
        "dataset": "enron", "n_sampled": len(emails),
        "n_contain_pii": n_contain_pii, "n_flagged": n_flagged,
        "n_covered": n_covered,
        "pii_coverage": round(coverage, 4),
        "pii_types": pii_types,
        "total_pii_instances": total_pii,
    }
    (out_dir / "enron_results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    # 5. 打印
    print(f"Enron PII 评测（{len(emails)} 封抽样邮件）")
    print(f"  含 PII 的邮件       = {n_contain_pii}")
    print(f"  被判违规的邮件     = {n_flagged}")
    print(f"  检测覆盖（含 PII 且被拦）= {n_covered}")
    print(f"  邮件级脱敏覆盖率   = {coverage:.4f}")
    print(f"  PII 类型分布       = email:{pii_types['email']} "
          f"phone:{pii_types['phone']} ssn:{pii_types['ssn']}")
    print(f"\n产出: policy_packs/pii_enron_v1.json")
    print(f"      scripts/examples/datasets/enron_vectors.json / enron_results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
