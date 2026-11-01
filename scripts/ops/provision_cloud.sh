#!/usr/bin/env bash
# Wave 2 X1 云机 provisioning 清单（**只打印，不执行**）。
#
# 为什么只打印：sudo 行需要你在自己的终端里跑（本仓库的 WSL2 约束），
# 而且云机镜像各不相同；把命令逐条摆出来比脚本擅自改系统更可控。
#
# 用法：
#   bash scripts/ops/provision_cloud.sh            # 打印清单
#   bash scripts/ops/provision_cloud.sh --verify   # 只跑环境体检
#
# 目标机器：64–128 GB RAM / 32+ vCPU / 200 GB SSD / Ubuntu 22.04 x86-64。
set -euo pipefail

cd "$(dirname "$0")/../.."

if [[ "${1:-}" == "--verify" ]]; then
  exec python3 scripts/ops/check_wave2_env.py --require P0-06_groth16,P0-08_scale
fi

cat <<'EOF'
============================================================
Wave 2 X1 云机 provisioning（逐条复制到你的终端）
============================================================

0) 机器规格
   - RAM  : ≥64 GB（128 GB 推荐；groth16 本机 12 GB 必 OOM）
   - vCPU : ≥32
   - 磁盘 : ≥200 GB SSD
   - OS   : Ubuntu 22.04 x86-64

1) 系统包（需要 sudo；请在你的终端里跑）
   sudo apt-get update
   sudo apt-get install -y build-essential pkg-config libssl-dev git curl jq \
       python3 python3-pip python3-venv

2) Rust（用户级，不需要 sudo）
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   source "$HOME/.cargo/env"
   rustc --version

3) SP1 工具链（用户级）
   curl -L https://sp1.succinct.xyz | bash
   source "$HOME/.bashrc"
   cargo prove install
   cargo prove --version        # 目标：v6.7.0（与 circuits/Cargo.lock 对齐）

4) Go ≥1.24（SP1 的 gnark 包装器需要）
   sudo apt-get install -y golang-go        # 或从 https://go.dev/dl/ 下 1.24+
   go version

5) Python 依赖（可选，按你跑哪条线）
   python3 -m pip install --user -r requirements-frameworks.txt   # LangChain/MCP
   python3 -m pip install --user -r requirements-ezkl.txt         # 语义规则/ezkl
   python3 -m pip install --user transformers accelerate          # X2 本地模型

6) 运行时环境
   export SP1_PROVER=cpu
   ulimit -n 65535 || true
   # 关键：同一台机器一次只跑一个证明进程（每个 ~10 GiB，groth16 更高）。
   # run_wave2_cloud.sh 用 flock 拒绝并发。

7) 体检（必须全 PASS 才开跑）
   python3 scripts/ops/check_wave2_env.py --require P0-06_groth16,P0-08_scale

8) 开跑（按阶段）
   bash scripts/ops/run_wave2_cloud.sh --stage groth16 --budget-min 600
   bash scripts/ops/run_wave2_cloud.sh --stage surface --timeout 3600
   bash scripts/ops/run_wave2_cloud.sh --stage scale   --budget-min 600

9) 产物
   bench/results/scale-cloud.json / .md
   bench/results/privacy_surface.json / .md

10) 常见失败
   - OOM 在 ~10.15 GiB：检查是否并发跑了两个证明；检查机器总内存。
   - groth16 很慢：先跑 --stage groth16 --budget-min 60 看一个点，再放大。
   - cargo prove 版本不对：以 circuits/Cargo.lock 为准，不要用 latest。
   - 不要在云机上跑全量 unittest（会与证明抢内存/CPU，且部分测试需要本机工件）。
============================================================
EOF
