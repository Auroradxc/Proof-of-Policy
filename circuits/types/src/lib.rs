//! Shared (de)serializable types for Proof-of-Policy.
//!
//! `ProofRequest` is what the SP1 program consumes (response + compiled
//! constraints); `ProofOutput` is what it commits as public values. These
//! types are `no_std` + `alloc` so they compile for the RISC-V guest and for
//! the host driver alike. JSON representation mirrors the Rust enum layout
//! (serde externally-tagged) so the Python reference layer can emit/consume
//! the same schema.

#![no_std]

extern crate alloc;

use alloc::{collections::{BTreeMap, BTreeSet}, format, string::String, vec, vec::Vec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A tool invocation in an agent trace (used by tool/budget rules).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub args: BTreeMap<String, String>,
}

/// Declared response format for `format_check`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormatKind {
    #[default]
    Json,
    Int,
    Float,
}

/// Unit for `budget_bound`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetUnit {
    #[default]
    Calls,
    Tokens,
}

/// Compiled NFA (Thompson), produced by `policydsl.nfa` and serialized into
/// the ConstraintSpec. This is the cross-layer contract for pattern_block.
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
    /// Inclusive [lo, hi] code-point ranges; merged + sorted (see policydsl.nfa).
    pub ranges: Vec<(u32, u32)>,
}

/// How pattern_block matching is performed in-circuit (ablation switch).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternMode {
    /// Pike VM: single pass over the text, all NFA states tracked together.
    #[default]
    Pike,
    /// Naive: re-run the matcher anchored at every start position (O(n^2)).
    Naive,
}

/// A compiled constraint from the ConstraintSpec.
///
/// Phase 1-2 covers `KeywordBlock`, `LengthBound` and `PatternBlock`; more
/// variants land in later phases. Field values follow `policydsl/compile.py`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Constraint {
    /// Response must not contain any of `keywords` (case-insensitive, ASCII).
    KeywordBlock { name: String, keywords: Vec<String> },
    /// Response length (code points) must satisfy `min <= len <= max`.
    LengthBound { name: String, min: u32, max: u32 },
    /// Response must not match any of the compiled patterns (substring, the
    /// `patterns[i]` regex compiled to `specs[i]`).
    PatternBlock {
        name: String,
        patterns: Vec<String>,
        specs: Vec<NfaSpec>,
        #[serde(default)]
        mode: PatternMode,
    },
    /// Response must parse as the declared format (canonical subset).
    FormatCheck { name: String, format: FormatKind },
    /// Forbidden keys in tool-call arguments (optionally restricted to `tools`).
    ToolArgGuard {
        name: String,
        #[serde(default)]
        tools: Vec<String>,
        forbidden_fields: Vec<String>,
    },
    /// Cumulative budget: number of tool calls, or declared `token_count`.
    BudgetBound { name: String, budget: u32, unit: BudgetUnit },
}

/// Input to the prover: the agent response, the constraints to check, and the
/// tool-call trace (used by tool_arg_guard / budget_bound).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProofRequest {
    pub response: String,
    pub constraints: Vec<Constraint>,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    #[serde(default)]
    pub token_count: Option<u32>,
}

/// A single violated rule (only populated when not passed).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Violation {
    /// Rule name as given in the policy pack.
    pub rule: String,
    /// Constraint kind, e.g. "keyword_block" | "length_bound".
    pub kind: String,
    /// Short human-readable evidence, e.g. the matched keyword or the length.
    pub evidence: String,
}

/// Public output committed by the program.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProofOutput {
    pub passed: bool,
    pub violations: Vec<Violation>,
}

// --------------------------------------------------------------------------- //
// NFA matching (mirrors policydsl.nfa.match_search: Pike VM, unanchored
// existence over code points). Kept here so the guest and any future host
// utility share one implementation; spec ranges are merged + sorted.
// --------------------------------------------------------------------------- //

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

fn in_ranges(cp: u32, ranges: &[(u32, u32)]) -> bool {
    for &(lo, hi) in ranges {
        if cp > hi {
            continue;
        }
        return cp >= lo; // ranges sorted ascending by lo
    }
    false
}

fn reached_accept(spec: &NfaSpec, cur: &[bool]) -> bool {
    spec.accept.iter().any(|&a| cur[a as usize])
}

/// Naive matcher (ablation): re-run the NFA anchored at each start position and
/// stop as soon as any start accepts. Semantically identical to `nfa_match`
/// (existence of a match) but O(n^2) — used to quantify the Pike VM's advantage.
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

/// True iff `text` contains a substring matching `spec` (re.search semantics
/// over the supported regex subset). ASCII/Unicode: operates on code points.
pub fn nfa_match(spec: &NfaSpec, text: &str) -> bool {
    let mut cur = eps_closure(spec, core::slice::from_ref(&spec.start));
    if reached_accept(spec, &cur) {
        return true; // matches empty prefix
    }
    for ch in text.chars() {
        let cp = ch as u32;
        let mut nxt = eps_closure(spec, core::slice::from_ref(&spec.start)); // fresh start here
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
// Constraint evaluation (shared by the SP1 guest and host-side checks).
// Mirrors policydsl.evaluate.check for the in-circuit rule kinds.
// --------------------------------------------------------------------------- //
fn ascii_lower(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

fn format_name(f: FormatKind) -> &'static str {
    match f {
        FormatKind::Json => "json",
        FormatKind::Int => "int",
        FormatKind::Float => "float",
    }
}

fn budget_unit_name(u: BudgetUnit) -> &'static str {
    match u {
        BudgetUnit::Calls => "calls",
        BudgetUnit::Tokens => "tokens",
    }
}

/// Canonical `format_check` parsers — the accepted subset is deliberately narrow
/// so the Python golden and the zkVM agree exactly:
///   int:   optional sign + 1..=19 ASCII digits (no underscores, no unicode digits)
///   float: Rust `f64` parse, rejecting underscores / nan / inf spellings
///   json:  `serde_json` (which rejects NaN/Infinity, like the golden is forced to)
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

/// Judge a ProofRequest against its constraints. Phase 1-2 rule kinds:
/// keyword_block (ASCII case-insensitive substring), length_bound (code-point
/// length), pattern_block (substring regex via compiled NFA).
pub fn evaluate(req: &ProofRequest) -> ProofOutput {
    let mut violations: Vec<Violation> = Vec::new();

    for c in &req.constraints {
        match c {
            Constraint::KeywordBlock { name, keywords } => {
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
                        break; // at most one violation per tool call
                    }
                }
            }
            Constraint::BudgetBound { name, budget, unit } => {
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
// Private mode: response commitment + selective disclosure + redaction proof.
// Mirrors policydsl.commit.
// --------------------------------------------------------------------------- //

const HEX: &[u8; 16] = b"0123456789abcdef";

/// SHA-256 of the UTF-8 bytes, lowercase hex (matches hashlib.sha256().hexdigest()).
pub fn sha256_hex(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// A violation disclosed in private mode: rule + kind + a *commitment* to the
/// evidence fragment (the fragment itself is not revealed).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateViolation {
    pub rule: String,
    pub kind: String,
    pub evidence_commitment: String,
}

/// Proof that a redacted string differs from the original only at masked
/// positions (VDR-style selective disclosure).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RedactionProof {
    pub redacted_commitment: String,
    pub mask_count: u32,
    pub redaction_ok: bool,
    /// Every masked position lies inside a *genuine* pattern match (witness
    /// spans validated in-circuit) — mask ⊆ matches.
    pub mask_covered: bool,
}

/// Private-mode input. `mask` are the char indices allowed to differ (hold
/// `*`); `redacted` is the candidate redaction to verify (optional); `spans`
/// are witness char ranges proving those positions are genuine matches.
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

/// Private-mode public output: no response text, only its commitment and
/// per-violation evidence commitments (+ optional redaction proof).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateOutput {
    pub response_commitment: String,
    pub passed: bool,
    pub violations: Vec<PrivateViolation>,
    pub redaction: Option<RedactionProof>,
}

/// Top-level job dispatched by the program (one ELF serves both modes).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Job {
    Public(ProofRequest),
    Private(PrivateRequest),
}

/// Top-level committed outcome.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Outcome {
    Public(ProofOutput),
    Private(PrivateOutput),
}

/// VDR-style redaction check: equal code-point length, masked positions hold
/// `*`, every other position unchanged. Mirrors `policydsl.commit.redaction_ok`.
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

/// True iff `chars[start..end]` fully matches `spec` (both ends anchored),
/// consuming at least one char. Used to validate redaction witness spans.
fn anchored_full_match(spec: &NfaSpec, chars: &[char], start: usize, end: usize) -> bool {
    if end > chars.len() || start >= end {
        return false;
    }
    let mut cur = eps_closure(spec, core::slice::from_ref(&spec.start));
    if reached_accept(spec, &cur) {
        return false;
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

/// Every span must be a genuine full match of some pattern_block pattern.
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

/// Every masked index lies inside some span (mask ⊆ spans).
fn mask_within_spans(mask: &[u32], spans: &[(u32, u32)]) -> bool {
    mask.iter().all(|&m| spans.iter().any(|&(s, e)| m >= s && m < e))
}

/// Judge a private request: compute the (shared) evaluation, but disclose only
/// rule/kind + evidence commitments, plus the response commitment and an
/// optional redaction proof.
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

/// Dispatch a job to its outcome (used by the guest and host checks).
pub fn run_job(job: &Job) -> Outcome {
    match job {
        Job::Public(r) => Outcome::Public(evaluate(r)),
        Job::Private(r) => Outcome::Private(evaluate_private(r)),
    }
}
