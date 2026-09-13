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

# C. 真证明 + 鉴权（生产的样子）
export POP_SIGNING_KEY=/etc/pop/signing.key
SP1_PROVER=cpu python3 scripts/proof_service.py \
  --auth-file /etc/pop/tokens --auth-admin ops --require-auth
```

**默认只绑 `127.0.0.1:8787`，且默认没有鉴权。** 见 §1.3：没配 token 时服务**照常
能起**（本机演示不该被逼着先造密钥），但会在启动横幅和 `/v1/health` 里如实写
`auth: "none"` —— 「有没有在鉴权」必须是运维**能问出来**的，而不是靠读文档。
生产上开 `--require-auth`，它在没配 token 时**拒绝启动**。

### 1.2 关键参数

| 参数 | 缺省 | 说明 |
|---|---|---|
| `--concurrency` | **1** | 证明器线程数。**不要随手上调**：~10.15 GiB 是 SP1 core 证明的固定地板，12 GB 机器上跑两个是 OOM（不是慢） |
| `--max-queue` | 8 | **等待中**的作业上限（不含正在证的）。满了返 `429` |
| `--pack` | `policy_packs/*.json` | 可重复。注册表按 `policy.id` 索引 |
| `--out-dir` | `scripts/examples/out/service` | 作业、证书、账本的落盘根 |
| `--ledger` | `<out-dir>/ledger.jsonl` | 锚定账本（仅追加、哈希链） |
| `--key` | `$POP_SIGNING_KEY` → `.pop-keys/signing.key` | Ed25519 签名钥，见 §4 |
| `--rpc` / `--contract` | 无 | 给了就**同时**把证书摘要登记上链（§7） |
| `--auth-token` | 无 | 一把 API key，格式 `label:secret`，**可重复**。见 §1.3 |
| `--auth-file` | 无 | token 文件：一行一个 `label:secret`，`#` 开头是注释 |
| `--auth-admin` | 无 | 把某个标签设为管理员（可读**所有**作业、不限流），可重复 |
| `--require-auth` | 关 | 没配任何 token 就**拒绝启动**。生产上开它 |
| `--rate` / `--burst` | 10 / 30 | 每个 token 的配额（次/秒）与令牌桶容量。`--rate 0` 关掉限流 |

并发上限的口径是 `concurrency + max_queue`（缺省 9）。`GET /v1/health` 里
`capacity` 就是这个数，`outstanding` 是当前占用的。

### 1.3 鉴权（`policydsl/auth.py`）

```bash
export POP_SERVICE_TOKEN="app:$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
python3 scripts/proof_service.py --auth-token "ops:$OPS_KEY" --auth-file /etc/pop/tokens
```

**三处凭据合起来生效**（命令行 + 文件 + 环境变量），不是后者覆盖前者 ——
否则「文件里的常备钥」会在某个命令行参数出现之后**静默消失**。

| 行为 | 结果 |
|---|---|
| 没带 / 带错 `Authorization` | **401** + `WWW-Authenticate: Bearer realm="pop-proof-service"` |
| token 格式不对（漏了 `Bearer`） | **401**，且报错**说明是格式问题** —— 否则 401 会把人引去怀疑 token 本身 |
| 别人的作业 | **404**，措辞与「这个 job_id 不存在」**逐字相同** |
| 超出配额 | **429** + `Retry-After` |
| 管理员 token | 可读所有作业、**不限流**（事故里运维要能一直读 health，而那正是配额最容易被自己打满的时候） |

**为什么别人的作业返 404 而不是 403**：403 等于确认「这个 job_id 存在」，
那它就成了一个探测别家 job_id 的预言机。两种情况从外部必须完全不可区分。

**配额按 token 分桶，不按 IP**：一个 IP 后面可能是一整个 NAT 出口，按 IP 限流会
让互不相干的两家互相饿死；按 token 限流限的正是「谁在花钱出证」。桶是**令牌桶**
而不是固定窗口 —— 固定窗口在边界上允许 2× 突发，而那恰是最容易被写脚本利用的时刻。

**secret 绝不进日志**：日志与 `/v1/health` 里只有**标签**（`alice`）和 `token_id`
（secret 的 sha256 前 12 位）。明文 secret 短于 **16** 字符会被**当场拒收**：
一个「看起来配了鉴权、实际一撞就开」的服务比明说「我没配鉴权」更危险。

**token 是明文过网的** —— 绑非本机地址时启动横幅会 `⚠`。放到网络上必须在前面
加 TLS 终结；`--auth-file` 权限过宽（非 `0600`）时每次启动都会警告。

---

## 2. 冒烟测试（起了服务之后）

```bash
# 开了鉴权时每条请求都要带这把钥（下例假设 `export AUTH="Authorization: Bearer $TOK"`）
curl -s localhost:8787/v1/health -H "$AUTH" | python3 -m json.tool   # 看 auth/concurrency
curl -s localhost:8787/v1/policies -H "$AUTH" | python3 -m json.tool # 看 serviceable

# ⓪ 先确认鉴权真的开着（**这一条最该先做**）
curl -s -i localhost:8787/v1/health | head -1
# 期望：没带 token 时是 401，而不是 200 —— 200 说明没人拦

# ① 在线段：毫秒级
curl -s -X POST localhost:8787/v1/check -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"policy_id":"agent-content-v1","response":"Leak sk-abcdefghijklmnopqrstuvwxyz now"}' \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["passed"], d["proof_mode"])'
# 期望：False unproven

# ② 离线段：入队 → 轮询
JOB=$(curl -s -X POST localhost:8787/v1/attest -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"policy_id":"agent-content-v1","response":"Leak sk-abcdefghijklmnopqrstuvwxyz now"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')
watch -n5 "curl -s localhost:8787/v1/attest/$JOB -H '$AUTH' | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"state\"])'"
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
| 没带 / 带错 token | **401** + `WWW-Authenticate` | 只在配了 token 时。见 §1.3 |
| 某把 token 打满配额 | **429** + `Retry-After` | 按 token 分桶；管理员豁免。见 §1.3 |
| 队列满了 | **429** + `Retry-After: 30` | 拒绝而不是无限收下。无限收下会把「做不到」推迟到几十分钟后以 OOM 爆发，而那时客户端已经排了半天队 |
| 策略没注册 | 404 | 报错里**列出**已注册的 id |
| **别人的作业** | 404（与「不存在」逐字相同） | 403 会确认「这个 id 存在」，那就成了探测预言机。见 §1.3 |
| 策略含语义规则 | 400 | 服务不生成 ezkl 陪伴证明，出的证书会「看起来验过了」。见 §5 |
| 请求体超 1 MiB | 413（**不读正文**就回） | 防御：`http.server` 会把声明的字节全读进内存 |
| 作业内证明失败 | `state: failed` + `error` | 工作线程不退出，后面的作业照跑；队列位当场还回来 |

**两种 429 要分得开**：看报错文案 —— 「队列已满」是服务忙（等，或换机器），
「超出配额」是**你这把 token** 打太快（降速；换一把钥不会更快，它只是换了个桶）。

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

1. ~~**无鉴权**~~ **已闭（鉴权层，2026-09-13）**。见 §1.3：bearer token（三处来源
   合并）、401/404/429 的口径、按 token 的令牌桶。**仍然不设防的两件事**如实留下：
   (a) **token 是明文过网的** —— 绑非本机地址必须在前面加 TLS 终结；
   (b) **不区分角色的权限** —— 除了 `--auth-admin` 这个二元开关，没有「只能 check
   不能 attest」这类细粒度授权。真要多角色，把两段拆到两个端口、各自一套 token。
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
| 服务起不来 | `--pack` 指向的文件是否存在且是合法 JSON；启动日志里 `⚠ 跳过策略包` 那几行；`--require-auth` 下没配 token 会直接拒启（**这是设计**） |
| 所有请求都 401 | 先看 `/v1/health` 的 `auth.mode`：`none` 说明**根本没配 token**（那不该返 401）；`bearer` 说明配了，核对 `Authorization: Bearer <token>` 的写法 |
| 明明配了 token 还是放行 | 看启动横幅那行 `鉴权: bearer，N 把钥`。没有这一行 ⇒ 凭据没读到（env 名写错？`--auth-file` 路径写错会**拒启**，不会静默） |
| 读不到某个作业（404）但产物在磁盘上 | 那个作业不是这把 token 提的。用 `--auth-admin` 的标签去读，或直接看 `<out-dir>/jobs/<job_id>/job.json` 里的 `submitted_by` |
| 突然大量 429 | 分清是哪种：报错里「队列已满」⇒ 服务忙；「超出配额」⇒ 这把 token 太快。`/v1/health` 的 `auth.rate_per_sec`/`burst` 是当前口径 |
| `/v1/attest` 一直 `proving` | `free -g` 看是不是在换页；真证明 2.5 分钟是正常的，明显更久多半是内存不够 |
| 作业 `failed` | `GET /v1/attest/{job}` 的 `error` 字段；工作线程把异常记在那里 |
| `error` 里写着「被 SIGKILL 杀死」 | **内存**。SP1 core 证明的地板 ~10.15 GiB，而 12 GB 机器只是「刚好装得下」（§1.1）。先腾内存再重试；核实 `dmesg \| grep -i 'killed process'`。**调大 `--concurrency` 只会更快 OOM** |
| `verify_cert.py` 报 `anchor chain=bad` | 账本被改过或被并发写过。服务内部用 `threading.Lock` 串行化追加，**手动**编辑或另一个进程同时写会打断哈希链 |
| `trace_binding` FAIL | 是否漏了 `--receipts`；没有回执时它本来就验不了（§2） |
| 429 | 队列满。看 `GET /v1/health` 的 `outstanding`/`capacity`；要么退避重试，要么换机器（别把 `--concurrency` 调大） |
