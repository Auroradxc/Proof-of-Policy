//! Proof-of-Policy 的共享（反）序列化类型。
//!
//! `ProofRequest` 是 SP1 程序消费的输入：**策略的规范 JSON 字节** + 响应 +
//! 工具调用轨迹。`Outcome` 是它作为公开值（public values）承诺的输出，
//! 其中**必然携带 `policy_hash`**。
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

/// agent 轨迹里的一次工具调用（用于 tool/budget 规则）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub args: BTreeMap<String, String>,
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

/// prover 的输入：agent 响应、规范策略字节、以及工具调用轨迹
/// （供 tool_arg_guard / budget_bound 使用）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProofRequest {
    /// 策略的规范 JSON 文本（`policydsl.compile.canonical_spec_bytes` 产出）。
    /// 唯一真相源：既用于派生 `policy_hash`，也用于解析要判定的约束。
    pub spec_canonical: String,
    pub response: String,
    /// 一次性挑战值（客户端/验证者出题）。空 = 未走挑战流程，仍然会给出一份
    /// 「绑定到空挑战」的承诺（格式统一，见 `response_binding`）。
    #[serde(default)]
    pub nonce: Vec<u8>,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    #[serde(default)]
    pub token_count: Option<u32>,
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
/// tool_arg_guard（工具参数被禁键）、budget_bound（calls / tokens）。
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
    tool_calls: &[ToolCall],
    token_count: Option<u32>,
) -> ProofOutput {
    let mut violations: Vec<Violation> = Vec::new();

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
                // 工具参数防护：检查（可选白名单限定后的）调用参数是否含被禁字段
                for call in tool_calls {
                    if !tools.is_empty() && !tools.contains(&call.name) {
                        continue;
                    }
                    if let Some(f) = forbidden_fields.iter().find(|f| call.args.contains_key(*f)) {
                        violations.push(Violation {
                            rule: name.clone(),
                            kind: "tool_arg_guard".into(),
                            evidence: format!("{}:{}", call.name, f),
                        });
                        break; // 每个工具调用至多记一条违规
                    }
                }
            }
            SpecConstraint::BudgetBound { name, budget, unit } => {
                // 预算边界：按 calls 计调用次数，按 tokens 计 token_count
                let total: u32 = match unit {
                    BudgetUnit::Calls => tool_calls.len() as u32,
                    BudgetUnit::Tokens => token_count.unwrap_or(0),
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

    ProofOutput {
        policy_hash: String::from(policy_hash),
        response_binding: response_binding(nonce, response),
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
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    #[serde(default)]
    pub token_count: Option<u32>,
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
            "passed": o.passed,
            "violations": o.violations,
        }),
        Outcome::Private(o) => serde_json::json!({
            "mode": "private",
            "policy_hash": o.policy_hash,
            "response_binding": o.response_binding,
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
                          &req.tool_calls, req.token_count);
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
                                     &r.tool_calls, r.token_count))
        }
        Job::Private(r) => {
            let (hash, spec) = parse_spec(&r.spec_canonical);
            Outcome::Private(evaluate_private(r, &hash, &spec.constraints))
        }
    }
}
