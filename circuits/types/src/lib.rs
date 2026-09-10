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

use alloc::{collections::BTreeSet, format, string::String, vec, vec::Vec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    PatternBlock { name: String, patterns: Vec<String>, specs: Vec<NfaSpec> },
}

/// Input to the prover: the agent response plus the constraints to check.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProofRequest {
    pub response: String,
    pub constraints: Vec<Constraint>,
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
            Constraint::PatternBlock { name, patterns, specs } => {
                for (i, spec) in specs.iter().enumerate() {
                    if nfa_match(spec, &req.response) {
                        violations.push(Violation {
                            rule: name.clone(),
                            kind: "pattern_block".into(),
                            evidence: patterns.get(i).cloned().unwrap_or_default(),
                        });
                        break;
                    }
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
}

/// Private-mode input. `mask` are the char indices allowed to differ (hold
/// `*`); `redacted` is the candidate redaction to verify (optional).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrivateRequest {
    pub response: String,
    pub constraints: Vec<Constraint>,
    #[serde(default)]
    pub mask: Vec<u32>,
    #[serde(default)]
    pub redacted: Option<String>,
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

/// Judge a private request: compute the (shared) evaluation, but disclose only
/// rule/kind + evidence commitments, plus the response commitment and an
/// optional redaction proof.
pub fn evaluate_private(req: &PrivateRequest) -> PrivateOutput {
    let public = evaluate(&ProofRequest {
        response: req.response.clone(),
        constraints: req.constraints.clone(),
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
    let redaction = req.redacted.as_ref().map(|red| RedactionProof {
        redacted_commitment: sha256_hex(red),
        mask_count: req.mask.len() as u32,
        redaction_ok: redaction_ok(&req.response, red, &req.mask),
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
