//! Proof-of-Policy 的共享（反）序列化类型。
//!
//! `ProofRequest` 是 SP1 程序消费的输入（响应 + 编译后的约束）；
//! `ProofOutput` 是它作为公开值（public values）承诺的输出。这些类型是
//! `no_std` + `alloc`，因此既能编译进 RISC-V guest，也能编译进宿主驱动。
//! JSON 表示镜像了 Rust 枚举布局（serde 外部标签），使 Python 参考层能
//! 产出/消费同一份 schema。

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

/// 来自 ConstraintSpec 的一条编译后约束。
///
/// 阶段一至二覆盖 `KeywordBlock`、`LengthBound` 与 `PatternBlock`；更多变体
/// 在后续阶段落地。字段值遵循 `policydsl/compile.py`。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Constraint {
    /// 响应不得包含 `keywords` 中任意关键词（不区分大小写，ASCII）。
    KeywordBlock { name: String, keywords: Vec<String> },
    /// 响应长度（码点数）必须满足 `min <= len <= max`。
    LengthBound { name: String, min: u32, max: u32 },
    /// 响应不得匹配任意编译后的模式（子串匹配，`patterns[i]` 的正则
    /// 编译为 `specs[i]`）。
    PatternBlock {
        name: String,
        patterns: Vec<String>,
        specs: Vec<NfaSpec>,
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

/// prover 的输入：agent 响应、要检查的约束、以及工具调用轨迹
/// （供 tool_arg_guard / budget_bound 使用）。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProofRequest {
    pub response: String,
    pub constraints: Vec<Constraint>,
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

/// 依据约束判定一个 ProofRequest。阶段一至二规则类型：
/// keyword_block（ASCII 不区分大小写子串）、length_bound（码点长度）、
/// pattern_block（通过编译后 NFA 的子串正则）。
pub fn evaluate(req: &ProofRequest) -> ProofOutput {
    let mut violations: Vec<Violation> = Vec::new();

    for c in &req.constraints {
        match c {
            Constraint::KeywordBlock { name, keywords } => {
                // 关键词阻断：小写化后检查是否包含任意禁用词
                let text = ascii_lower(&req.response);
                if let Some(hit) = keywords.iter().find(|kw| text.contains(kw.as_str())) {
                    violations.push(Violation {
                        rule: name.clone(),
                        kind: "keyword_block".into(),
                        evidence: hit.clone(),
                    });
                }
            }
            Constraint::LengthBound { name, min, max } => {
                // 长度边界：按码点数计长
                let n = req.response.chars().count() as u32;
                if n < *min || n > *max {
                    violations.push(Violation {
                        rule: name.clone(),
                        kind: "length_bound".into(),
                        evidence: format!("len={}", n),
                    });
                }
            }
            Constraint::PatternBlock { name, patterns, specs, mode } => {
                // 正则阻断：按编译顺序逐条匹配，命中即记证据并跳出
                for (i, spec) in specs.iter().enumerate() {
                    let hit = match mode {
                        PatternMode::Pike => nfa_match(spec, &req.response),
                        PatternMode::Naive => nfa_match_naive(spec, &req.response),
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
            Constraint::FormatCheck { name, format } => {
                // 格式校验：按声明格式解析
                let ok = match format {
                    FormatKind::Json => parse_json_ok(&req.response),
                    FormatKind::Int => parse_int_ok(&req.response),
                    FormatKind::Float => parse_float_ok(&req.response),
                };
                if !ok {
                    violations.push(Violation {
                        rule: name.clone(),
                        kind: "format_check".into(),
                        evidence: format_name(*format).into(),
                    });
                }
            }
            Constraint::ToolArgGuard { name, tools, forbidden_fields } => {
                // 工具参数防护：检查（可选白名单限定后的）调用参数是否含被禁字段
                for call in &req.tool_calls {
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
            Constraint::BudgetBound { name, budget, unit } => {
                // 预算边界：按 calls 计调用次数，按 tokens 计 token_count
                let total: u32 = match unit {
                    BudgetUnit::Calls => req.tool_calls.len() as u32,
                    BudgetUnit::Tokens => req.token_count.unwrap_or(0),
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

/// 对 UTF-8 字节求 SHA-256，返回小写十六进制（匹配 hashlib.sha256().hexdigest()）。
pub fn sha256_hex(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
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
    pub response: String,
    pub constraints: Vec<Constraint>,
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
fn spans_valid(constraints: &[Constraint], chars: &[char], spans: &[(u32, u32)]) -> bool {
    let specs: Vec<&NfaSpec> = constraints
        .iter()
        .filter_map(|c| match c {
            Constraint::PatternBlock { specs, .. } => Some(specs.iter()),
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
pub fn evaluate_private(req: &PrivateRequest) -> PrivateOutput {
    let public = evaluate(&ProofRequest {
        response: req.response.clone(),
        constraints: req.constraints.clone(),
        tool_calls: req.tool_calls.clone(),
        token_count: req.token_count,
    });
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
        let covered = spans_valid(&req.constraints, &chars, &req.spans)
            && mask_within_spans(&req.mask, &req.spans);
        RedactionProof {
            redacted_commitment: sha256_hex(red),
            mask_count: req.mask.len() as u32,
            redaction_ok: redaction_ok(&req.response, red, &req.mask),
            mask_covered: covered,
        }
    });
    PrivateOutput {
        response_commitment: sha256_hex(&req.response),
        passed: public.passed,
        violations,
        redaction,
    }
}

/// 把一个任务分派到其结果（guest 与宿主检查共用）。
pub fn run_job(job: &Job) -> Outcome {
    match job {
        Job::Public(r) => Outcome::Public(evaluate(r)),
        Job::Private(r) => Outcome::Private(evaluate_private(r)),
    }
}
