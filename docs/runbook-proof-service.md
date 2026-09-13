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
| `--rpc` / `--contract` | 无 | 给了就**同时**把证书摘要登记上链（§1.4、§7）。**两个必须同时给**，只给一个拒绝启动 |
| `--private-key` | Anvil 测试键 | 上链提交交易用的私钥。**生产上必须显式给**，缺省那把是公开的测试键 |
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

### 1.4 账本后端：文件 vs 链上

给出 `--rpc` 与 `--contract` 就**同时**把证书摘要登记进 `Anchor` 合约（部署见 §7）。

```bash
python3 scripts/proof_service.py --rpc http://127.0.0.1:8545 --contract 0x<addr>
```

| 行为 | 结果 |
|---|---|
| 只给 `--rpc` 或只给 `--contract` | **拒绝启动**，退出码 2 |
| 启动横幅 | 打印 `链上 : <合约> @ <rpc> → ✅ 连通 / ❌ <原因>` |
| `/v1/health` | 多出 `anchor_backend: "rpc"` 与 `chain: {healthy, detail, contract, rpc_url, checked_at, age}` |
| 链已知断 | `/v1/check` 与 `/v1/attest` 都返 **503**，且明说「**没有签发证书**」 |
| 提交作业时链已知断 | **拒收**（503），不进队列 |
| 链在自己这边挂掉 | 作业 `failed`，`error` 里说清「没有签发证书」并指路 `chain.healthy` |

**四个刻意的设计点**：

- **配一半要拒绝启动，不能静默退回文件账本。** 那种错最坏的地方是它**没有症状**：
  证书照样签得出来、账本照样自洽、`/v1/health` 也照样说 ok；等到有人去链上查那份
  摘要，才发现从来没有过。
- **`chain.healthy` 报的是「知不知道」，不是「好不好」**。自检有 30 秒 TTL，所以
  带 `age`/`checked_at` —— 一个**看不出多旧**的健康值比没有更糟，它会把「十分钟前
  是好的」读成「是好的」。实现里 `AnchorBackend.healthy()` 的缺省值是
  **unhealthy**：漏写自检的远端后端报「不知道」，而不是继承一句假的 ok。
- **先锚定，再落证书文件**。锚定是唯一会**对外失败**的一步（RPC 连不上、nonce
  重放、gas 不够），反过来的顺序会让一次链上故障留下一份完整、带签名的证书。
  `verify_cert.py` 当然会判它 FAIL，但**它已经发得出去**了。
- **收下作业之前先探链**。锚定发生在证明**之后**：链已知断还收下作业，等于用
  ~2.5 分钟 + ~10.2 GiB 去回答一个启动时就有答案的问题，还白占一个队列位
  （`capacity` 缺省只有 9，真证明下同时只能有 1 个在跑）。TTL 是 30 秒，
  一次瞬时抖动最多造成 30 秒的 503 —— 调用方退避重试即可，比白烧一次证明划算。

**`/v1/check` 也会被坏链拦下**，这不是疏漏：它签的是一张**真的**证书（只是
`unproven`），所以同样要锚定。顺手给链上后端开一条「只有 attest 走链」的旁路是
个陷阱 —— 那样 `check` 会签出链上查不到的证书，而它恰恰是最常被调用的那条路。

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
| **链上账本不可用** | **503**，明说「没有签发证书」 | 不是 500：500 是「这个服务坏了，别重试」，503 是「依赖暂时不可用」。见 §1.4 |
| 作业内证明失败 | `state: failed` + `error` | 工作线程不退出，后面的作业照跑；队列位当场还回来 |

**两种 429 要分得开**：看报错文案 —— 「队列已满」是服务忙（等，或换机器），
「超出配额」是**你这把 token** 打太快（降速；换一把钥不会更快，它只是换了个桶）。

轮询 `queued` 里带的 `queue_position` 是**前面还有几个没开工的**。它只对
`queued` 有意义（开工后返回 `null`）。

### 3.1 关于 `/v1/check` 的吞吐

在线段不占证明队列，但它**每调用一次就签一张证书并锚定一条账本记录**。文件账本的
`append` 原本是「读全表 → 算前驱哈希 → 追加」，所以账本越长单次 `check` 越慢
（O(n)）。**已修**（2026-09-13）：`policydsl/anchor.py` 现在按
`(文件大小, mtime_ns)` 给账本尾部加缓存，追加是 O(1) —— 记账长度只与文件系统的
stat 有关。

两件值得知道的事：

- **换成 RPC 后端并不解决这个问题**。（本节早先的建议就是这么写的，是错的。）
  `RpcAnchorBackend.anchor()` 在给了 `ledger_path` 时**照样**调 `append_anchor`，
  换后端只是多了一条链上记录。O(n) 在那一步里，只能在账本自己身上修。
- **缓存的失效靠文件戳，所以绕过 `append_anchor` 的手工编辑会被察觉**（戳变了就
  全表重读）。真正需要滚动归档的是**磁盘**而不是 CPU：账本只追加、从不改写，
  长期运行请定期切分并保留旧段（它同时是审计材料）。

**为什么这会成为一个真问题**：`/v1/check` 是那条毫秒级的在线路径。如果它的耗时
随调用次数线性增长，服务就从「边缘可跑」退化成「跑一会儿就得重启」—— 而这两者的
区别恰恰是这个服务存在的理由。

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
| 服务起不来 | `--pack` 指向的文件是否存在且是合法 JSON；启动日志里 `⚠ 跳过策略包` 那几行；`--require-auth` 下没配 token、`--rpc`/`--contract` 只给一个，都会**拒启并退出码 2**（**这是设计**） |
| 启动横幅里 `链上 … ❌` | 那是**启动那一刻**的自检结果：RPC 达不达得到、该地址上有没有合约代码。三种常见原因：RPC 没起、地址打错、合约没部署（§7） |
| 请求返 503 且写着「没有签发证书」 | 链上账本不可用。看 `/v1/health` 的 `chain.detail`（原始 `cast` 报错）与 `age`。**这次没有产物**，不要去找 `cert.json`；修好 RPC 后重试即可 |
| `/v1/attest` 返 202、轮询后才 `failed`，`error` 指向 `chain.healthy` | 提交时链是通的、证明跑完登记才失败（RPC 中途没了 / nonce 重放 / gas 不够）。**这次同样没有 `cert.json`** —— 目录里只有 `vectors.json`/`results.json` 这类输入与中间产物 |
| 链上查不到某张证书的摘要 | 先看该证书目录里有没有 `anchor.json`（没有 ⇒ 当初就没签发成功）；再核对 `/v1/health` 的 `chain.contract` 与 `verify_digest_on_chain` 用的是不是同一个合约地址 |
| 所有请求都 401 | 先看 `/v1/health` 的 `auth.mode`：`none` 说明**根本没配 token**（那不该返 401）；`bearer` 说明配了，核对 `Authorization: Bearer <token>` 的写法 |
| 明明配了 token 还是放行 | 看启动横幅那行 `鉴权: bearer，N 把钥`。没有这一行 ⇒ 凭据没读到（env 名写错？`--auth-file` 路径写错会**拒启**，不会静默） |
| 读不到某个作业（404）但产物在磁盘上 | 多半是那个作业不属于这把 token（也可能是作业状态只在内存里，见 §5.3）。用 `--auth-admin` 的标签去问 —— **磁盘上没有提交者信息**，`<out-dir>/jobs/<job_id>/` 里只有输入与产物 |
| 突然大量 429 | 分清是哪种：报错里「队列已满」⇒ 服务忙；「超出配额」⇒ 这把 token 太快。`/v1/health` 的 `auth.rate_per_sec`/`burst` 是当前口径 |
| `/v1/attest` 一直 `proving` | `free -g` 看是不是在换页；真证明 2.5 分钟是正常的，明显更久多半是内存不够 |
| 作业 `failed` | `GET /v1/attest/{job}` 的 `error` 字段；工作线程把异常记在那里 |
| `error` 里写着「被 SIGKILL 杀死」 | **内存**。SP1 core 证明的地板 ~10.15 GiB，而 12 GB 机器只是「刚好装得下」（§1.1）。先腾内存再重试；核实 `dmesg \| grep -i 'killed process'`。**调大 `--concurrency` 只会更快 OOM** |
| `verify_cert.py` 报 `anchor chain=bad` | 账本被改过或被并发写过。服务内部用 `threading.Lock` 串行化追加，**手动**编辑或另一个进程同时写会打断哈希链 |
| `trace_binding` FAIL | 是否漏了 `--receipts`；没有回执时它本来就验不了（§2） |
| 429 | 队列满。看 `GET /v1/health` 的 `outstanding`/`capacity`；要么退避重试，要么换机器（别把 `--concurrency` 调大） |
