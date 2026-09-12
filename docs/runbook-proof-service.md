# 单机 runbook：证明服务（`scripts/proof_service.py`）

> 面向**运维这个服务的人**，不是面向读代码的人。回答四个问题：跑起来要什么、
> 怎么确认它是好的、满载时它怎么表现、出事怎么办。
>
> 接口定义与设计理由见 [`dev-plan.md` §5.2](dev-plan.md)；实现见
> [`policydsl/service.py`](../policydsl/service.py)（库）与
> [`scripts/proof_service.py`](../scripts/proof_service.py)（HTTP 驱动）。

---

## 0. 一句话

两段式：`POST /v1/check` 毫秒级出**宿主判定**证书（`unproven`），
`POST /v1/attest` 入队出**真证明**证书（真 vkey）。两段用同一个 `nonce` 时绑的是
同一条响应。

---

## 1. 起服务

### 1.1 依赖

| 项 | `--host-check`（演示/边缘） | 真证明（默认） |
|---|---|---|
| Python | 3.10+，**标准库** | 同左 |
| `circuits/target/release/pop-script` | **需要**（宿主判定也走它，只是加 `--check`） | 需要 |
| Rust + SP1 工具链 | 不需要 | **需要**（`SP1_PROVER=cpu`） |
| 内存 | 可忽略 | **≥12 GB，且同时只能有一个证明器**（固定地板 ~10.15 GiB，见 [`bench/results/proofs.md`](../bench/results/proofs.md)）。⚠️ 「≥12 GB」是**刚好装得下**而不是「有余量」：11.7 GiB 的机器上实测 `MemAvailable` 会掉到 0.15 GiB 并靠 swap 撑住 —— 同时有别的进程在占内存就会 OOM。**出证前先腾内存** |
| 磁盘 | 每张 check 证书 ~10 KB | 每份作业 ~4 MB（`proof.bin`） |
| 网络 | 无 | 无（出证不需要联网；上链才需要 RPC） |

```bash
cd Proof-of-Policy/03_代码仓库/zk-policy

# A. 演示 / 边缘：宿主判定，作业几秒完成，证书如实标注 unproven
python3 scripts/proof_service.py --host-check

# B. 真证明：每个作业 ~2.5 分钟、峰值 ~10.2 GiB
SP1_PROVER=cpu python3 scripts/proof_service.py
```

**默认只绑 `127.0.0.1:8787`，且没有任何鉴权。** 放到网络上之前必须先加一层
（反向代理 + mTLS/OIDC，或只对本机/内网开放）—— 服务本身不判断「你是谁」，
谁能连上谁就能出证、就能读别人的作业产物。

### 1.2 关键参数

| 参数 | 缺省 | 说明 |
|---|---|---|
| `--concurrency` | **1** | 证明器线程数。**不要随手上调**：~10.15 GiB 是 SP1 core 证明的固定地板，12 GB 机器上跑两个是 OOM（不是慢） |
| `--max-queue` | 8 | **等待中**的作业上限（不含正在证的）。满了返 `429` |
| `--pack` | `policy_packs/*.json` | 可重复。注册表按 `policy.id` 索引 |
| `--out-dir` | `scripts/examples/out/service` | 作业、证书、账本的落盘根 |
| `--ledger` | `<out-dir>/ledger.jsonl` | 锚定账本（仅追加、哈希链） |
| `--key` | `$POP_SIGNING_KEY` → `.pop-keys/signing.key` | Ed25519 签名钥，见 §4 |
| `--rpc` / `--contract` | 无 | 给了就**同时**把证书摘要登记上链 |

并发上限的口径是 `concurrency + max_queue`（缺省 9）。`GET /v1/health` 里
`capacity` 就是这个数，`outstanding` 是当前占用的。

---

## 2. 冒烟测试（起了服务之后）

```bash
curl -s localhost:8787/v1/health | python3 -m json.tool      # 看 concurrency/policies
curl -s localhost:8787/v1/policies | python3 -m json.tool    # 看 serviceable

# ① 在线段：毫秒级
curl -s -X POST localhost:8787/v1/check -H 'Content-Type: application/json' \
  -d '{"policy_id":"agent-content-v1","response":"Leak sk-abcdefghijklmnopqrstuvwxyz now"}' \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["passed"], d["proof_mode"])'
# 期望：False unproven

# ② 离线段：入队 → 轮询
JOB=$(curl -s -X POST localhost:8787/v1/attest -H 'Content-Type: application/json' \
  -d '{"policy_id":"agent-content-v1","response":"Leak sk-abcdefghijklmnopqrstuvwxyz now"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')
watch -n5 "curl -s localhost:8787/v1/attest/$JOB | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"state\"])'"
# 期望：queued → proving → done（真证明下 proving 约 2.5 分钟）

# ③ 第三方验证：把上一步响应里的 verify_hint 整行粘进终端
```

`verify_hint` 是**可以直接粘贴的一整行命令**，它带上 `--proof`（真证明时）与
`--receipts`（调用方给了回执时）。期望以 `RESULT: PASS` 结尾。

**没有回执、也没有证明时 `trace_binding` 会如实报 FAIL（"binding uncheckable"）**
—— 那不是故障，是那句大实话：证明没在手上、回执也没有，链尾摘要就只有证书
自己说了算。要么传 `receipts`，要么走 `/v1/attest`。

---

## 3. 满载时的行为（**这是设计，不是退化**）

| 情况 | 响应 | 为什么 |
|---|---|---|
| 队列满了 | **429** + `Retry-After: 30` | 拒绝而不是无限收下。无限收下会把「做不到」推迟到几十分钟后以 OOM 爆发，而那时客户端已经排了半天队 |
| 策略没注册 | 404 | 报错里**列出**已注册的 id |
| 策略含语义规则 | 400 | 服务不生成 ezkl 陪伴证明，出的证书会「看起来验过了」。见 §5 |
| 请求体超 1 MiB | 413（**不读正文**就回） | 防御：`http.server` 会把声明的字节全读进内存 |
| 作业内证明失败 | `state: failed` + `error` | 工作线程不退出，后面的作业照跑；队列位当场还回来 |

轮询 `queued` 里带的 `queue_position` 是**前面还有几个没开工的**。它只对
`queued` 有意义（开工后返回 `null`）。

### 3.1 关于 `/v1/check` 的吞吐

在线段不占证明队列，但它**每调用一次就签一张证书并锚定一条账本记录**。文件账本的
`append` 是「读全表 → 算前驱哈希 → 追加」，所以账本越长，单次 `check` 越慢
（O(n)）。演示量级完全没问题；真要对它做高并发，先把账本换成 RPC 后端
（`--rpc`/`--contract`），或者自己给账本加周期性的滚动归档。

---

## 4. 换签名钥

服务的签名钥**整套服务共用一把**（同一进程内所有证书的 `keyid` 相同）。
公钥随每张证书落在 `<cert-dir>/key.json`，第三方验签只需要它。

```bash
# 换一把新的（PKCS#8 PEM，带口令时读 $POP_KEY_PASSPHRASE）
export POP_SIGNING_KEY=/etc/pop/signing.key
```

**换钥的后果**：`<out-dir>` 里已有的证书仍用旧钥验签（它们各自带着自己的
`key.json`），但「服务只有一把钥」这个说法就不成立了。要保留审计链，就把
`--out-dir` 一起换掉，让每一段时期有自己的目录。

私钥**绝不进 git**：`.pop-keys/`、`*.key`、`*.pub.hex` 都在 `.gitignore` 里。

---

## 5. 已知边界（说清楚，不是待办里不提）

1. **无鉴权**（§1.1）。服务不区分调用方，也没有速率限制 —— 限流交给前面那层。
2. **语义规则策略不受支持**。`semantic_bound` 由 ezkl 陪伴证明判定，而该证明只
   在 `scripts/issue_cert.py` 那条命令行路径里生成。服务**当场拒**这类请求
   （400），`GET /v1/policies` 里也如实标 `serviceable: false` —— 而不是发一张
   `delegated` 非空却没有 companion 的证书（那会被 `verify_cert.py` 判 FAIL，
   但在那之前它看起来是正常的）。
3. **作业状态只在内存里**。进程重启后，`<out-dir>/jobs/<job_id>/` 里的产物还在
   （证书、证明、账本都在），但 `GET /v1/attest/{job}` 会 404。要恢复「谁问过
   什么」，读账本，不要读服务内存。
4. **证明作业不可中断**。`SIGINT`/`Ctrl-C` 会等手上的作业做完再退（缺省
   `drain=True`）；一个已经进入 `proving` 的作业不能取消。强行 `SIGKILL` 会留下
   一个半截目录 —— 它的证书不会签发，账本也不会多出一条，所以**只是一份垃圾文件**，
   不会变成假证据。
5. **同一秒 + 同一个 nonce + 同一条响应 = 同一张证书**（载荷里的 `ts` 是秒级）。
   这是确定性，不是缺陷；账本里会出现两条内容相同的锚定记录，链仍然自洽。

---

## 6. 出了一件事，先看哪里

| 症状 | 先看 |
|---|---|
| 服务起不来 | `--pack` 指向的文件是否存在且是合法 JSON；启动日志里 `⚠ 跳过策略包` 那几行 |
| `/v1/attest` 一直 `proving` | `free -g` 看是不是在换页；真证明 2.5 分钟是正常的，明显更久多半是内存不够 |
| 作业 `failed` | `GET /v1/attest/{job}` 的 `error` 字段；工作线程把异常记在那里 |
| `error` 里写着「被 SIGKILL 杀死」 | **内存**。SP1 core 证明的地板 ~10.15 GiB，而 12 GB 机器只是「刚好装得下」（§1.1）。先腾内存再重试；核实 `dmesg \| grep -i 'killed process'`。**调大 `--concurrency` 只会更快 OOM** |
| `verify_cert.py` 报 `anchor chain=bad` | 账本被改过或被并发写过。服务内部用 `threading.Lock` 串行化追加，**手动**编辑或另一个进程同时写会打断哈希链 |
| `trace_binding` FAIL | 是否漏了 `--receipts`；没有回执时它本来就验不了（§2） |
| 429 | 队列满。看 `GET /v1/health` 的 `outstanding`/`capacity`；要么退避重试，要么换机器（别把 `--concurrency` 调大） |
