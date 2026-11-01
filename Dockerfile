# 纯 Python 复现镜像：只覆盖参考层 + 证书/验证链路。
#
# 刻意**不**安装 SP1、ezkl、torch、langchain 等重依赖：
#   证明（core/compressed/groth16）需要 ~10 GiB 内存与数分钟，且不属于本镜像的复现范围。
# 构建上下文由 .dockerignore 控制（.git、circuits/target、bench/results、.pop-keys 等不进镜像）。
#
# 用法：
#   docker build -t pop-artifact .
#   docker run --rm pop-artifact
#   docker run --rm pop-artifact python3 -m unittest tests.test_dsl tests.test_normalize
#   docker run --rm pop-artifact python3 -m policydsl compile policy_packs/eu_ai_act_v1.json
#
# 宿主机上的完整 fast demo（需要 pop-script 驱动）见 docs/artifact/README.md。

FROM python:3.10-slim

# 证书签名/验证用 Ed25519（policydsl/evidence/{cert,keys}.py）。
RUN pip install --no-cache-dir "cryptography==50.0.1" \
 && useradd --create-home --uid 10001 pop

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --chown=pop:pop . /app

USER pop

# 默认冒烟：策略承诺（BHV 定理 D/E4a）+ Ed25519 证书 + 序列化契约。
# 刻意不跑：
#   · tests.test_scripts_layout —— 它会导入 scripts/datasets/*.py，其中一个在
#     模块级 `import numpy`；本镜像只装 cryptography，不装 ezkl/torch 栈。
#   · tests.test_doc_links —— 镜像按 .dockerignore 排除了 bench/results，
#     而 docs 内部有链接指向 bench/results/*.md。
# 这两项在宿主机上跑（见 docs/artifact/README.md）。
CMD ["python3", "-m", "unittest", \
     "tests.test_policy_commit", \
     "tests.test_cert", \
     "tests.test_serialize"]
