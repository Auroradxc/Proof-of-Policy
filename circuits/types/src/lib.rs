//! Proof-of-Policy 的共享（反）序列化类型。
//!
//! `ProofRequest` 是 SP1 程序消费的输入：**策略的规范 JSON 字节** + 响应 +
//! 工具回执链（P1-5；回执由工具网关签发，不再是 agent 的自述）。
//! `Outcome` 是它作为公开值（public values）承诺的输出，其中**必然携带
//! `policy_hash`**。
//!
//! ## 健全性的核心约定
//!
//! 策略以**规范字节**（`spec_canonical`）的形式传入，guest 从中
//! **同时**得到两样东西：
//!
//! 1. `policy_hash = SHA256(spec_canonical)` —— 进公开值；
//! 2. 解析出的 `ConstraintSpec.constraints` —— 实际参与判定。
//!
//! 二者同源、不可分离。若策略以「独立的结构化字段」传入而公开值里不含其
//! 哈希，证明者就能用空策略（恒通过）判定、再在证书里声称哈希对应真实策略 ——
//! 那样证明的义务会退化为「存在某个策略通过」，而非「策略 π 通过」。
//!
//! 这些类型是 `no_std` + `alloc`，因此既能编译进 RISC-V guest，也能编译进
//! 宿主驱动。`SpecConstraint` 用 serde **内部标签**（`"kind"`）直接吃
//! `policydsl/compile.py` 产出的形状 —— 这样「被哈希的文本」与「被解析的文本」
//! 是同一份，无需在两套序列化之间做映射（映射本身就是漏洞温床）。

#![no_std]

extern crate alloc;

use alloc::{collections::{BTreeMap, BTreeSet}, format, string::String, vec, vec::Vec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 工具网关对**一次工具调用**签发的回执（P1-5）。
///
/// 在 P1-5 之前，`tool_calls` 是证明者自填的私有输入 —— 想通过
/// `tool_arg_guard`，把它填成空列表即可。回执改由**真正执行工具的那一方**
/// （网关）签发，agent 只能转发，于是 `tool_arg_guard`/`budget_bound` 判的
/// 不再是证明者的一面之词。
///
/// **`sig` 字段刻意不在这里**：Ed25519 验签在**链下**由网关公钥完成（zkVM 内
/// 验签代价高，取舍见 `docs/plan-p0p1p2.md` §P1-5）。serde 默认忽略未知字段，
/// 所以带 `sig` 的 JSON 能正常反序列化 —— 而摘要不覆盖 `sig`，两边算出的
/// 字节仍然一致。电路内验证的是链的**结构**（`verify_receipt_chain`）：
/// 每条回执的摘要由它自己的内容重算，`seq` 连续、`prev` 逐条咬合。
/// 「回执可信」的根源是签名，由验证方在链下核对。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolReceipt {
    /// 序号（从 0 起）。
    pub seq: u32,
    pub tool: String,
    /// 调用的**明文参数**。计划稿里写的是 `args_digest`，但摘要撑不起
    /// `tool_arg_guard` —— 电路拿哈希无从判断参数里有没有 `password` 这个键。
    /// 参数是证明的私有输入、不进公开值，放明文不额外泄露什么；保证它没被
    /// 篡改的是网关签名。
    #[serde(default)]
    pub args: BTreeMap<String, String>,
    /// 执行结果的承诺（结果可能很长，且没有任何规则去读它）。
    #[serde(default)]
    pub result_digest: String,
    #[serde(default)]
    pub ts: String,
    /// 前一条回执的 `receipt_digest`；首条为 `"genesis"`。
    #[serde(default = "trace_genesis")]
    pub prev: String,
    /// 签发者密钥标识（含方案前缀，如 `"ed25519:ab12…"`）。
    #[serde(default)]
    pub keyid: String,
}

fn trace_genesis() -> String {
    String::from(TRACE_GENESIS)
}

/// 回执摘要与签名的域分隔前缀（对应 `policydsl.trace.TRACE_DOMAIN`）。
pub const TRACE_DOMAIN: &[u8] = b"pop-trace-v1";
/// 空链的链尾（对应 `policydsl.trace.GENESIS`）。
pub const TRACE_GENESIS: &str = "genesis";

/// 长度前缀：`u32_be(len) ‖ data`。没有它，「拼起来」就有歧义。
fn push_lp(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// 回执的规范字节编码（**签名与摘要的共同原像**）。
///
/// `TRACE_DOMAIN ‖ u32_be(seq) ‖ lp(tool) ‖ u32_be(len(args)) ‖
/// [lp(k) ‖ lp(v)]_按键升序 ‖ lp(result_digest) ‖ lp(ts) ‖ lp(prev) ‖ lp(keyid)`
///
/// 刻意**不用 JSON**：JSON 规范化（键序、数字格式、转义、空白）是个聊不完的
/// 话题，而这里只需要一串**唯一**的字节。字段齐全、顺序写死、长度前缀防歧义 ——
/// 必须与 `policydsl.trace.canonical_receipt_bytes` 逐字节一致
/// （`tests/test_trace.py` 逐长度核对）。
pub fn canonical_receipt_bytes(r: &ToolReceipt) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(TRACE_DOMAIN);
    out.extend_from_slice(&r.seq.to_be_bytes());
    push_lp(&mut out, r.tool.as_bytes());
    out.extend_from_slice(&(r.args.len() as u32).to_be_bytes());
    // BTreeMap 迭代即按键升序，与 Python 的 sorted(args) 一致
    for (k, v) in r.args.iter() {
        push_lp(&mut out, k.as_bytes());
        push_lp(&mut out, v.as_bytes());
    }
    push_lp(&mut out, r.result_digest.as_bytes());
    push_lp(&mut out, r.ts.as_bytes());
    push_lp(&mut out, r.prev.as_bytes());
    push_lp(&mut out, r.keyid.as_bytes());
    out
}

/// 单条回执的摘要（十六进制）—— 下一条回执的 `prev` 就是它。
pub fn receipt_digest(r: &ToolReceipt) -> String {
    hex(&Sha256::digest(canonical_receipt_bytes(r)))
}

/// 链尾摘要（空链 → `"genesis"`）—— 随证明一起进公开值。
///
/// 公开值里放**链尾**而不是整条链：链可能很长，而验证方手上本来就有网关发的
/// 回执，它要的只是「这份证明绑定的是哪条链」这一个可离线核对的值 ——
/// 与 `response_binding` 之于响应的作用完全对称。
pub fn trace_root(receipts: &[ToolReceipt]) -> String {
    match receipts.last() {
        Some(r) => receipt_digest(r),
        None => String::from(TRACE_GENESIS),
    }
}

/// **结构**检查：`seq` 必须等于下标、`prev` 必须逐条咬合。
///
/// 这是电路内做的那一层：它只保证链自身自洽，**不**保证内容属实 —— 后者靠
/// 签名，由验证方在链下核对（见 `ToolReceipt` 的说明）。空链是**合法**的
/// （一次工具都没调用）。
///
/// 错误串与 `policydsl.trace.chain_ok` 逐字符一致：它会作为违规证据进证书，
/// 两边不一致就等于证书里写着一条链上算不出来的证据。
pub fn verify_receipt_chain(receipts: &[ToolReceipt]) -> Result<(), String> {
    for (i, r) in receipts.iter().enumerate() {
        if r.seq as usize != i {
            return Err(format!("receipt {}: seq={} != {}", i, r.seq, i));
        }
        let expected = if i == 0 {
            String::from(TRACE_GENESIS)
        } else {
            receipt_digest(&receipts[i - 1])
        };
        if r.prev != expected {
            return Err(format!("receipt {}: prev mismatch", i));
        }
    }
    Ok(())
}

/// 该字节是否算分词空白 —— **取死**的六个字节，与
/// `policydsl.trace.TOKEN_SPACE` 一致。刻意不用 Unicode White_Space：
/// 那份定义会随 Unicode 版本漂移，而电路与参考实现必须永远给出同一个数。
pub fn is_token_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// 响应的确定性 token 数：按固定空白集合切分后的 run 个数。
///
/// 这不是任何真实 LLM 的分词器 —— 它**不假装是**。选它的理由只有一条：
/// 电路内能廉价、确定地算出来，从而 `budget_bound(unit="tokens")` 的输入不再
/// 是证明者的一面之词（P1-5 的语义变更，见论文 §4.2）。
pub fn token_count(text: &str) -> u32 {
    let mut n: u32 = 0;
    let mut in_run = false;
    for b in text.as_bytes() {
        if is_token_space(*b) {
            in_run = false;
        } else if !in_run {
            in_run = true;
            n += 1;
        }
    }
    n
}

/// `format_check` 声明的响应格式。
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormatKind {
    #[default]
    Json,
    Int,
    Float,
}

/// `budget_bound` 的计量单位。
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetUnit {
    #[default]
    Calls,
    Tokens,
}

/// 编译后的 NFA（Thompson 构造），由 `policydsl.nfa` 产出并序列化进
/// ConstraintSpec。这是 pattern_block 的跨层契约。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NfaSpec {
    pub start: u32,
    pub accept: Vec<u32>,
    pub states: Vec<NfaState>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NfaState {
    pub eps: Vec<u32>,
    pub edges: Vec<NfaEdge>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NfaEdge {
    pub to: u32,
    /// 闭区间 [lo, hi] 码点范围；已合并 + 排序（见 policydsl.nfa）。
    pub ranges: Vec<(u32, u32)>,
}

/// pattern_block 在电路内的匹配方式（消融开关）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternMode {
    /// Pike VM：对文本做单遍扫描，同时追踪全部 NFA 状态。
    #[default]
    Pike,
    /// 朴素：在每个起点重新跑一次匹配器（O(n^2)）。
    Naive,
}

/// 来自 ConstraintSpec 的一条约束 —— **直接映射 `policydsl/compile.py` 产出的
/// 规范 JSON 形状**（内部标签 `"kind"`，值取 snake_case 变体名）。
///
/// 之所以用内部标签而不是外部标签：电路消费的约束与「被哈希的规范字节」必须
/// 是**同一份文本**。见 `ConstraintSpec` 与 `run_job` 的说明。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpecConstraint {
    /// 响应不得包含 `keywords` 中任意关键词（不区分大小写，ASCII）。
    KeywordBlock { name: String, keywords: Vec<String> },
    /// 响应长度（码点数）必须满足 `min <= len <= max`。
    LengthBound { name: String, min: u32, max: u32 },
    /// 响应不得匹配任意编译后的模式（子串匹配，`patterns[i]` 的正则
    /// 编译为 `nfa.compiled[i]`）。
    PatternBlock {
        name: String,
        patterns: Vec<String>,
        nfa: NfaBlock,
        #[serde(default)]
        mode: PatternMode,
    },
    /// 响应必须能按声明格式解析（规范子集）。
    FormatCheck { name: String, format: FormatKind },
    /// 工具调用参数里的被禁键（可选用 `tools` 限定范围）。
    ToolArgGuard {
        name: String,
        #[serde(default)]
        tools: Vec<String>,
        forbidden_fields: Vec<String>,
    },
    /// 累计预算：工具调用次数，或声明的 `token_count`。
    BudgetBound { name: String, budget: u32, unit: BudgetUnit },
}

/// `pattern_block.nfa` 的包装（Python 侧为 `{"nfa": {"compiled": [...]}}`）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NfaBlock {
    pub compiled: Vec<NfaSpec>,
}

/// 完整的 ConstraintSpec —— 跨层契约的**规范化 JSON 文本**解析结果。
///
/// **健全性关键**：本结构是从 `spec_canonical` 那段字节解析出来的，而
/// `policy_hash = SHA256(spec_canonical)` 是对**同一段字节**求哈希。因此
/// 「被哈希的策略」与「被判定的策略」在构造上不可分离：证明者无法一边用
/// 空策略（恒通过）判定、一边声称哈希对应真实策略。
///
/// 注意：`sha256` 字段**不在**规范字节里（它是对规范字节本身的哈希），
/// 所以这里也不需要它。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConstraintSpec {
    pub spec_version: String,
    pub policy_id: String,
    pub policy_version: String,
    pub semantic: String,
    pub constraints: Vec<SpecConstraint>,
}

/// 本程序实现的契约版本（对应 `policydsl.compile.SPEC_VERSION`）。
pub const SPEC_VERSION: &str = "v1";

/// 本程序实现的规则组合语义：全部规则都要通过（对应 `Policy` 的默认值）。
pub const SEMANTIC_AND: &str = "and";

/// 挑战-响应绑定的域分隔前缀（对应 `policydsl.commit.BIND_DOMAIN`）。
/// 换个用途（如将来绑定工具轨迹）就用另一段前缀，两个域的哈希永不碰撞。
pub const BIND_DOMAIN: &[u8] = b"pop-bind-v1";

/// prover 的输入：agent 响应、规范策略字节、以及**工具回执链**
/// （供 tool_arg_guard / budget_bound 使用）。
///
/// **为什么标 `deny_unknown_fields`**：P1-5 移除了 `tool_calls` /
/// `token_count` 这两个「证明者自填」的字段。若不拒绝未知字段，拿旧向量出证会
/// **静默**变成「零次工具调用 ⇒ tool_arg_guard 通过」—— 旧路径看起来仍然能用，
/// 实际上 P1-5 一点没生效。标上之后，旧向量在反序列化这一步就失败
/// （guest panic ⇒ 产不出证明），这正是想要的 fail-closed。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofRequest {
    /// 策略的规范 JSON 文本（`policydsl.compile.canonical_spec_bytes` 产出）。
    /// 唯一真相源：既用于派生 `policy_hash`，也用于解析要判定的约束。
    pub spec_canonical: String,
    pub response: String,
    /// 一次性挑战值（客户端/验证者出题）。空 = 未走挑战流程，仍然会给出一份
    /// 「绑定到空挑战」的承诺（格式统一，见 `response_binding`）。
    #[serde(default)]
    pub nonce: Vec<u8>,
    /// 工具回执链（P1-5）。空链 = 一次工具都没调用，合法。
    #[serde(default)]
    pub receipts: Vec<ToolReceipt>,
}

/// 一条被违反的规则（仅在未通过时非空）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Violation {
    /// 规则名（与策略包里一致）。
    pub rule: String,
    /// 约束类型，如 "keyword_block" | "length_bound"。
    pub kind: String,
    /// 简短可读证据，如命中的关键词或长度。
    pub evidence: String,
}

/// 程序承诺的公开输出。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProofOutput {
    /// 被判定策略的哈希 = SHA256(规范字节)。**由电路内计算**，验证方据此确认
    /// 「这条证明确实是对声明的策略 π 做的判定」，而不是别的策略。
    pub policy_hash: String,
    /// 挑战-响应绑定 = SHA256(BIND_DOMAIN ‖ len(nonce) ‖ nonce ‖ T)（见
    /// `response_binding`）。持 T 与 nonce 者可**离线**核对「被证明的就是送达的
    /// 那条响应」，无需在公开值里泄露 T。
    pub response_binding: String,
    /// 工具回执链的链尾摘要（`trace_root`；空链为 `"genesis"`）。
    ///
    /// 与 `response_binding` 同一个用途，只是对象换成了**轨迹**：公开值里放它，
    /// 是为了让「这份证明绑定的到底是哪条工具链」可被离线核对 —— 验证方拿网关
    /// 发给它的回执重算一遍链尾即可。没有这一项，证明里的 `receipts` 就只是
    /// 又一串「证明者说它是这样」的私有输入。
    ///
    /// **边界**（论文 §4.2 如实标注）：电路内只验证这条链的**结构**
    /// （`verify_receipt_chain`），Ed25519 验签在链下完成。因此本字段说明的是
    /// 「证明绑定了一条自洽的链」，而不是「这条链里的签名已被电路验证过」。
    pub trace_root: String,
    pub passed: bool,
    pub violations: Vec<Violation>,
}

// --------------------------------------------------------------------------- //
// NFA 匹配（镜像 policydsl.nfa.match_search：Pike VM，基于码点的无锚点
// 存在性搜索）。放在这里使 guest 与未来任何宿主工具共享同一实现；
// spec 区间已合并 + 排序。
// --------------------------------------------------------------------------- //

/// 计算给定种子状态的 ε-闭包（含自身），返回布尔向量。
fn eps_closure(spec: &NfaSpec, seeds: &[u32]) -> Vec<bool> {
    let n = spec.states.len();
    let mut seen = vec![false; n];
    let mut stack: Vec<u32> = seeds.to_vec();
    while let Some(s) = stack.pop() {
        let idx = s as usize;
        if seen[idx] {
            continue;
        }
        seen[idx] = true;
        for &e in &spec.states[idx].eps {
            if !seen[e as usize] {
                stack.push(e);
            }
        }
    }
    seen
}

/// 判断码点 cp 是否落在某条（已按 lo 升序排序的）区间内。
fn in_ranges(cp: u32, ranges: &[(u32, u32)]) -> bool {
    for &(lo, hi) in ranges {
        if cp > hi {
            continue;
        }
        return cp >= lo; // 区间按 lo 升序排序
    }
    false
}

/// 当前状态集是否命中任意接受状态。
fn reached_accept(spec: &NfaSpec, cur: &[bool]) -> bool {
    spec.accept.iter().any(|&a| cur[a as usize])
}

/// 朴素匹配器（消融实验用）：在每个起点重新锚定跑一次 NFA，任一起点接受即停。
/// 语义与 `nfa_match`（匹配存在性）一致，但 O(n^2) —— 用于量化 Pike VM 的优势。
pub fn nfa_match_naive(spec: &NfaSpec, text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    for start in 0..chars.len() {
        let mut cur = eps_closure(spec, core::slice::from_ref(&spec.start));
        if reached_accept(spec, &cur) {
            return true;
        }
        for i in start..chars.len() {
            let cp = chars[i] as u32;
            let mut nxt = vec![false; spec.states.len()];
            for (s, present) in cur.iter().enumerate() {
                if !present {
                    continue;
                }
                for e in &spec.states[s].edges {
                    if in_ranges(cp, &e.ranges) {
                        let cl = eps_closure(spec, core::slice::from_ref(&e.to));
                        for (k, v) in cl.into_iter().enumerate() {
                            if v {
                                nxt[k] = true;
                            }
                        }
                    }
                }
            }
            cur = nxt;
            if !cur.iter().any(|&x| x) {
                break;
            }
            if reached_accept(spec, &cur) {
                return true;
            }
        }
    }
    false
}

/// `text` 是否含有匹配 `spec` 的子串（在受支持正则子集上的 re.search 语义）。
/// ASCII/Unicode：按码点操作。
pub fn nfa_match(spec: &NfaSpec, text: &str) -> bool {
    let mut cur = eps_closure(spec, core::slice::from_ref(&spec.start));
    if reached_accept(spec, &cur) {
        return true; // 匹配空前缀
    }
    for ch in text.chars() {
        let cp = ch as u32;
        // 每个字符位置都允许「重新从 start 出发」，覆盖「匹配不从头开始」的情况
        let mut nxt = eps_closure(spec, core::slice::from_ref(&spec.start));
        for (s, present) in cur.iter().enumerate() {
            if !present {
                continue;
            }
            for e in &spec.states[s].edges {
                if in_ranges(cp, &e.ranges) {
                    let cl = eps_closure(spec, core::slice::from_ref(&e.to));
                    for (k, v) in cl.into_iter().enumerate() {
                        if v {
                            nxt[k] = true;
                        }
                    }
                }
            }
        }
        cur = nxt;
        if reached_accept(spec, &cur) {
            return true;
        }
    }
    false
}

// --------------------------------------------------------------------------- //
// 约束评估（SP1 guest 与宿主侧检查共用）。
// 对电路内规则类型镜像 policydsl.evaluate.check。
// --------------------------------------------------------------------------- //

/// 仅对 ASCII 做小写化（与链下 `_ascii_lower` 保持字节级一致）。
fn ascii_lower(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

/// FormatKind → 字符串名。
fn format_name(f: FormatKind) -> &'static str {
    match f {
        FormatKind::Json => "json",
        FormatKind::Int => "int",
        FormatKind::Float => "float",
    }
}

/// BudgetUnit → 字符串名。
fn budget_unit_name(u: BudgetUnit) -> &'static str {
    match u {
        BudgetUnit::Calls => "calls",
        BudgetUnit::Tokens => "tokens",
    }
}

/// 规范的 `format_check` 解析器 —— 接受的子集被刻意收紧，使 Python golden 与
/// zkVM 完全一致：
///   int:   可选符号 + 1..=19 位 ASCII 数字（无下划线、无 unicode 数字）
///   float: Rust `f64` 解析，拒绝下划线 / nan / inf 写法
///   json:  `serde_json`（拒绝 NaN/Infinity，正如 golden 被强制的那样）
pub fn parse_int_ok(s: &str) -> bool {
    let t = s.trim();
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    !digits.is_empty() && digits.len() <= 19 && digits.bytes().all(|b| b.is_ascii_digit())
}

pub fn parse_float_ok(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.contains('_') {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    if lower.contains("nan") || lower.contains("inf") {
        return false;
    }
    t.parse::<f64>().is_ok()
}

pub fn parse_json_ok(s: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(s).is_ok()
}

/// 依据约束判定一个响应（六类规则全部入电路）：
/// keyword_block（ASCII 不区分大小写子串）、length_bound（码点长度）、
/// pattern_block（通过编译后 NFA 的子串正则）、format_check（规范解析子集）、
/// tool_arg_guard（**回执**参数里的被禁键）、budget_bound（回执条数 / **电路内
/// 自算**的 token 数）。
///
/// `receipts` 是工具网关签发的回执链（P1-5）。电路内只验证链的**结构**
/// （见 `verify_receipt_chain`），签名由验证方在链下核对；链尾摘要进公开值，
/// 供验证方与手上的网关回执比对。
///
/// `policy_hash` 由调用方（`run_job`）从**同一段规范字节**派生后传入，
/// 保证公开值里的策略哈希与实际参与判定的约束同源、不可分离。同理，
/// `nonce` 也由调用方（同一次请求）传入，判定结果与响应绑定在电路内一起承诺，
/// 使「被证明的 T」与「送达的 T′」可比对（见 `response_binding`）。
pub fn evaluate(
    policy_hash: &str,
    constraints: &[SpecConstraint],
    response: &str,
    nonce: &[u8],
    receipts: &[ToolReceipt],
) -> ProofOutput {
    let mut violations: Vec<Violation> = Vec::new();

    // 回执链的**结构**校验，只做一次（tool_arg_guard / budget_bound/calls
    // 都要用）。空链合法 —— 一次工具都没调用是正常情形，不是「链坏了」。
    let chain: Result<(), String> = verify_receipt_chain(receipts);
    // token 数在电路内自算（P1-5）：不再接受证明者自填的值。
    let tokens: u32 = token_count(response);

    for c in constraints {
        match c {
            SpecConstraint::KeywordBlock { name, keywords } => {
                // 关键词阻断：小写化后检查是否包含任意禁用词
                let text = ascii_lower(response);
                if let Some(hit) = keywords.iter().find(|kw| text.contains(kw.as_str())) {
                    violations.push(Violation {
                        rule: name.clone(),
                        kind: "keyword_block".into(),
                        evidence: hit.clone(),
                    });
                }
            }
            SpecConstraint::LengthBound { name, min, max } => {
                // 长度边界：按码点数计长
                let n = response.chars().count() as u32;
                if n < *min || n > *max {
                    violations.push(Violation {
                        rule: name.clone(),
                        kind: "length_bound".into(),
                        evidence: format!("len={}", n),
                    });
                }
            }
            SpecConstraint::PatternBlock { name, patterns, nfa, mode } => {
                // 正则阻断：按编译顺序逐条匹配，命中即记证据并跳出
                for (i, spec) in nfa.compiled.iter().enumerate() {
                    let hit = match mode {
                        PatternMode::Pike => nfa_match(spec, response),
                        PatternMode::Naive => nfa_match_naive(spec, response),
                    };
                    if hit {
                        violations.push(Violation {
                            rule: name.clone(),
                            kind: "pattern_block".into(),
                            evidence: patterns.get(i).cloned().unwrap_or_default(),
                        });
                        break;
                    }
                }
            }
            SpecConstraint::FormatCheck { name, format } => {
                // 格式校验：按声明格式解析
                let ok = match format {
                    FormatKind::Json => parse_json_ok(response),
                    FormatKind::Int => parse_int_ok(response),
                    FormatKind::Float => parse_float_ok(response),
                };
                if !ok {
                    violations.push(Violation {
                        rule: name.clone(),
                        kind: "format_check".into(),
                        evidence: format_name(*format).into(),
                    });
                }
            }
            SpecConstraint::ToolArgGuard { name, tools, forbidden_fields } => {
                // 工具参数防护：检查（可选白名单限定后的）**回执**参数是否含被禁字段。
                // 链不自洽 ⇒ fail-closed：一条规则都不放行，而不是「链读不出来就
                // 当作没有调用」—— 那样伪造一条坏链就能让规则静默失效。
                if let Err(why) = &chain {
                    violations.push(Violation {
                        rule: name.clone(),
                        kind: "trace_unbound".into(),
                        evidence: why.clone(),
                    });
                    continue;
                }
                for r in receipts {
                    if !tools.is_empty() && !tools.contains(&r.tool) {
                        continue;
                    }
                    if let Some(f) = forbidden_fields.iter().find(|f| r.args.contains_key(*f)) {
                        violations.push(Violation {
                            rule: name.clone(),
                            kind: "tool_arg_guard".into(),
                            evidence: format!("{}:{}", r.tool, f),
                        });
                        break; // 每个工具调用至多记一条违规
                    }
                }
            }
            SpecConstraint::BudgetBound { name, budget, unit } => {
                // 预算边界：按 calls 计回执条数，按 tokens 计**电路内自算**的 token 数
                let total: u32 = match unit {
                    BudgetUnit::Tokens => tokens,
                    BudgetUnit::Calls => {
                        if let Err(why) = &chain {
                            violations.push(Violation {
                                rule: name.clone(),
                                kind: "trace_unbound".into(),
                                evidence: why.clone(),
                            });
                            continue;
                        }
                        receipts.len() as u32
                    }
                };
                if total > *budget {
                    violations.push(Violation {
                        rule: name.clone(),
                        kind: "budget_bound".into(),
                        evidence: format!("{}={}/{}", budget_unit_name(*unit), total, budget),
                    });
                }
            }
        }
    }

    // 坏链即使没有任何工具规则「接住」它也要记一笔：否则一条只有内容规则的策略
    // 会带着一条明显自相矛盾的回执链出证，而证书上什么都看不出来。
    // 规则名用带尖括号的占位符，与策略里的规则名（标识符）不可能撞车。
    if let Err(why) = &chain {
        if !violations.iter().any(|v| v.kind == "trace_unbound") {
            violations.push(Violation {
                rule: "<trace>".into(),
                kind: "trace_unbound".into(),
                evidence: why.clone(),
            });
        }
    }

    ProofOutput {
        policy_hash: String::from(policy_hash),
        response_binding: response_binding(nonce, response),
        trace_root: trace_root(receipts),
        passed: violations.is_empty(),
        violations,
    }
}

// --------------------------------------------------------------------------- //
// 私有模式：响应承诺 + 选择性披露 + 脱敏证明。
// 镜像 policydsl.commit。
// --------------------------------------------------------------------------- //

/// 十六进制字母表。
const HEX: &[u8; 16] = b"0123456789abcdef";

/// 字节 → 小写十六进制（匹配 Python `bytes.hex()`）。
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// 对 UTF-8 字节求 SHA-256，返回小写十六进制（匹配 hashlib.sha256().hexdigest()）。
pub fn sha256_hex(text: &str) -> String {
    hex(&Sha256::digest(text.as_bytes()))
}

/// P0-2 挑战-响应绑定：`SHA256(BIND_DOMAIN ‖ len(nonce) ‖ nonce ‖ T_utf8)`。
///
/// 存在的理由：证明的是「某条 T 满足 π」，但**证明里的 T 与客户端收到的 T′
/// 没有任何联系**。公开模式下 T 是证明的私有输入、证书里不出现；私有模式下
/// 更只有一个 `response_commitment`（它说明「存在某个通过判定的 T」，却说不出
/// 是哪一个）。于是中间人可以拿一条合规的 T 去换一条不合规的 T′ 送达 ——
/// 证明依然有效，因为它压根没提过 T′。
///
/// 绑定的做法是让**验证者出题**：客户端给出一次性 nonce，电路把 (nonce, T)
/// 一起承诺进公开值。持 (T′, nonce) 的一方离线重算即可确认 T′ = T。
///
/// 关于 `len(nonce)` 这个前缀：没有它，`nonce="ab", T="cd"` 与
/// `nonce="abcd", T=""` 会哈希出同一个值（拼接的经典歧义）。挑战值通常是定长
/// 的，但把无歧义性建立在调用方的自觉上不是个好买卖 —— 加 4 字节长度前缀后，
/// 无论 nonce 多长，(nonce, T) 到字节串的映射都是单射。这与 Python 侧
/// `policydsl.commit.response_binding` 必须逐字节一致。
///
/// nonce 为空是合法的（= 没走挑战流程）：那时绑定退化为「对一个空挑战的承诺」，
/// **不提供任何重放防护**，但格式与其他情况一致，验证方无需分支处理。
pub fn response_binding(nonce: &[u8], response: &str) -> String {
    let mut h = Sha256::new();
    h.update(BIND_DOMAIN);
    h.update((nonce.len() as u32).to_be_bytes());
    h.update(nonce);
    h.update(response.as_bytes());
    hex(&h.finalize())
}

/// 私有模式下披露的一条违规：rule + kind + 对证据片段的*承诺*
/// （片段本身不泄露）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateViolation {
    pub rule: String,
    pub kind: String,
    pub evidence_commitment: String,
}

/// 证明脱敏串与原串「仅在掩码位置不同」（VDR 风格选择性披露）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedactionProof {
    pub redacted_commitment: String,
    pub mask_count: u32,
    pub redaction_ok: bool,
    /// 每个掩码位置都落在*真实*模式匹配内（见证区间在电路内验证）—— mask ⊆ matches。
    pub mask_covered: bool,
}

/// 私有模式输入。`mask` 是允许不同（置为 `*`）的字符下标；`redacted` 是要
/// 验证的候选脱敏串（可选）；`spans` 是证明这些位置为真实匹配的见证字符区间。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRequest {
    /// 策略的规范 JSON 文本（与 `ProofRequest::spec_canonical` 同义，唯一真相源）。
    pub spec_canonical: String,
    pub response: String,
    /// 一次性挑战值（与 `ProofRequest::nonce` 同义）。
    #[serde(default)]
    pub nonce: Vec<u8>,
    #[serde(default)]
    pub mask: Vec<u32>,
    #[serde(default)]
    pub redacted: Option<String>,
    #[serde(default)]
    pub spans: Vec<(u32, u32)>,
    /// 工具回执链（与 `ProofRequest::receipts` 同义）。
    #[serde(default)]
    pub receipts: Vec<ToolReceipt>,
}

/// 私有模式公开输出：不含响应明文，只有其承诺与逐违规的证据承诺
/// （+ 可选的脱敏证明）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateOutput {
    /// 被判定策略的哈希 = SHA256(规范字节)，由电路内计算（见 `ProofOutput`）。
    pub policy_hash: String,
    /// 挑战-响应绑定（见 `ProofOutput::response_binding`）。私有模式下这是验证者
    /// **唯一**能确认「送来的 T′ 就是被证明的 T」的手段 —— 因为 T 不出现在这里。
    pub response_binding: String,
    /// 响应本身的承诺 SHA256(T)。它只说明「某个 T 通过了」，不说「哪个 T」；
    /// 要把它拴到一次具体会话上，靠的是上面那条 `response_binding`。
    pub response_commitment: String,
    /// 工具回执链的链尾摘要（见 `ProofOutput::trace_root`）。私有模式下回执链
    /// 本身不进公开值，验证方拿到的是这一个摘要。
    pub trace_root: String,
    pub passed: bool,
    pub violations: Vec<PrivateViolation>,
    pub redaction: Option<RedactionProof>,
}

/// 程序调度的顶层任务（一个 ELF 服务两种模式）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Job {
    Public(ProofRequest),
    Private(PrivateRequest),
}

/// 顶层承诺的结果。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Outcome {
    Public(ProofOutput),
    Private(PrivateOutput),
}

/// 把承诺的 `Outcome` 摊平成验证方可直接比对的 JSON 形状（**唯一真相源**）。
///
/// 证明方（`pop-script`）与验证者（`pop-verify`）必须产出**同形**的 outcome：
/// 否则「证书载荷里写的 outcome」与「证明公开值解出来的 outcome」无法逐字段
/// 比对，验证方就只能退回「信任证书自称的字段」—— 那正是 P0-1 要消除的模式。
/// 把摊平逻辑放在共享类型里，两边都调用同一个函数，形状就不可能漂移。
///
/// **本函数不含 `name`**：那是调用方按需追加的展示元信息，不参与承诺。
/// `mode` 则如实保留（它由 `Outcome` 的变体决定，是承诺语义的一部分）。
pub fn outcome_value(out: &Outcome) -> serde_json::Value {
    match out {
        Outcome::Public(o) => serde_json::json!({
            "mode": "public",
            "policy_hash": o.policy_hash,
            "response_binding": o.response_binding,
            "trace_root": o.trace_root,
            "passed": o.passed,
            "violations": o.violations,
        }),
        Outcome::Private(o) => serde_json::json!({
            "mode": "private",
            "policy_hash": o.policy_hash,
            "response_binding": o.response_binding,
            "trace_root": o.trace_root,
            "passed": o.passed,
            "response_commitment": o.response_commitment,
            "violations": o.violations,
            "redaction": o.redaction,
        }),
    }
}

/// VDR 风格脱敏检查：码点等长、掩码位置为 `*`、其余位置不变。
/// 镜像 `policydsl.commit.redaction_ok`。
pub fn redaction_ok(response: &str, redacted: &str, mask: &[u32]) -> bool {
    let r: Vec<char> = response.chars().collect();
    let d: Vec<char> = redacted.chars().collect();
    if r.len() != d.len() {
        return false;
    }
    let n = r.len() as u32;
    let masked: BTreeSet<u32> = mask.iter().copied().collect();
    for &i in &masked {
        if i >= n {
            return false;
        }
    }
    for (i, (a, b)) in r.iter().zip(d.iter()).enumerate() {
        if masked.contains(&(i as u32)) {
            if *b != '*' {
                return false;
            }
        } else if a != b {
            return false;
        }
    }
    true
}

/// `chars[start..end]` 是否「完整」匹配 `spec`（两端锚定），至少消耗 1 个字符。
/// 用于验证脱敏见证区间。
fn anchored_full_match(spec: &NfaSpec, chars: &[char], start: usize, end: usize) -> bool {
    if end > chars.len() || start >= end {
        return false;
    }
    let mut cur = eps_closure(spec, core::slice::from_ref(&spec.start));
    if reached_accept(spec, &cur) {
        return false; // 空匹配；区间必须消耗 >= 1 个字符
    }
    for i in start..end {
        let cp = chars[i] as u32;
        let mut nxt = vec![false; spec.states.len()];
        for (s, present) in cur.iter().enumerate() {
            if !present {
                continue;
            }
            for e in &spec.states[s].edges {
                if in_ranges(cp, &e.ranges) {
                    let cl = eps_closure(spec, core::slice::from_ref(&e.to));
                    for (k, v) in cl.into_iter().enumerate() {
                        if v {
                            nxt[k] = true;
                        }
                    }
                }
            }
        }
        cur = nxt;
        if !cur.iter().any(|&x| x) {
            return false;
        }
    }
    reached_accept(spec, &cur)
}

/// 每个区间都必须是某条 pattern_block 模式的真实完整匹配。
fn spans_valid(constraints: &[SpecConstraint], chars: &[char], spans: &[(u32, u32)]) -> bool {
    let specs: Vec<&NfaSpec> = constraints
        .iter()
        .filter_map(|c| match c {
            SpecConstraint::PatternBlock { nfa, .. } => Some(nfa.compiled.iter()),
            _ => None,
        })
        .flatten()
        .collect();
    spans
        .iter()
        .all(|&(s, e)| specs.iter().any(|sp| anchored_full_match(sp, chars, s as usize, e as usize)))
}

/// 每个掩码下标都落在某区间内（mask ⊆ spans）。
fn mask_within_spans(mask: &[u32], spans: &[(u32, u32)]) -> bool {
    mask.iter().all(|&m| spans.iter().any(|&(s, e)| m >= s && m < e))
}

/// 判定私有请求：做（共享的）评估，但只披露 rule/kind + 证据承诺，加上
/// 响应承诺与可选的脱敏证明。
pub fn evaluate_private(req: &PrivateRequest, policy_hash: &str,
                        constraints: &[SpecConstraint]) -> PrivateOutput {
    let public = evaluate(policy_hash, constraints, &req.response, &req.nonce,
                          &req.receipts);
    let violations = public
        .violations
        .iter()
        .map(|v| PrivateViolation {
            rule: v.rule.clone(),
            kind: v.kind.clone(),
            evidence_commitment: sha256_hex(&v.evidence),
        })
        .collect();
    let redaction = req.redacted.as_ref().map(|red| {
        let chars: Vec<char> = req.response.chars().collect();
        let covered = spans_valid(constraints, &chars, &req.spans)
            && mask_within_spans(&req.mask, &req.spans);
        RedactionProof {
            redacted_commitment: sha256_hex(red),
            mask_count: req.mask.len() as u32,
            redaction_ok: redaction_ok(&req.response, red, &req.mask),
            mask_covered: covered,
        }
    });
    PrivateOutput {
        policy_hash: public.policy_hash.clone(),
        response_binding: public.response_binding.clone(),
        response_commitment: sha256_hex(&req.response),
        trace_root: public.trace_root.clone(),
        passed: public.passed,
        violations,
        redaction,
    }
}

/// 从规范字节解析 `ConstraintSpec`，并派生策略哈希。
///
/// **健全性的锚点**：`policy_hash = SHA256(spec_canonical)` 与「解析出的约束」
/// 来自**同一段字节**，因此证明者无法一边用空策略（恒通过）判定、一边声称
/// 哈希对应真实策略 —— 这正是此前版本的漏洞（`constraints` 是独立私有输入，
/// 公开值里什么都没有）。
///
/// 解析失败直接 panic：电路内 fail-closed（产出不了证明），不做静默降级。
///
/// 还要挡住一类同型脱钩：**进了哈希却没被判定使用**的字段。当前有两位：
///
/// * `semantic` —— `evaluate` 只实现 `"and"`；放行 `"or"` 之类的值，契约里
///   就多出一个「被承诺、却对结果毫无影响」的字段。
/// * `spec_version` —— 契约格式的版本号；版本不同意味着字段语义可能不同，
///   按当前版本去解读一个未来版本会静默得出错误结论。
///
/// 二者都 fail-closed，而不是默默按当前语义判定。Python 侧（`Policy.validate()`
/// 只接受 `"and"`、`SPEC_VERSION = "v1"`）正常路径不会触发；这道闸门挡住的是
/// **绕过编译器手搓规范字节**的路径。
fn parse_spec(spec_canonical: &str) -> (String, ConstraintSpec) {
    let spec: ConstraintSpec = serde_json::from_str(spec_canonical)
        .expect("spec_canonical is not a valid ConstraintSpec");
    assert!(
        spec.semantic == SEMANTIC_AND,
        "unsupported semantic '{}': the evaluator only implements '{}'",
        spec.semantic,
        SEMANTIC_AND
    );
    assert!(
        spec.spec_version == SPEC_VERSION,
        "unsupported spec_version '{}': this program implements '{}'",
        spec.spec_version,
        SPEC_VERSION
    );
    (sha256_hex(spec_canonical), spec)
}

/// 把一个任务分派到其结果（guest 与宿主检查共用）。
pub fn run_job(job: &Job) -> Outcome {
    match job {
        Job::Public(r) => {
            let (hash, spec) = parse_spec(&r.spec_canonical);
            Outcome::Public(evaluate(&hash, &spec.constraints, &r.response, &r.nonce,
                                     &r.receipts))
        }
        Job::Private(r) => {
            let (hash, spec) = parse_spec(&r.spec_canonical);
            Outcome::Private(evaluate_private(r, &hash, &spec.constraints))
        }
    }
}
