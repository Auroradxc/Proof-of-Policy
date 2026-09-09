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

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// A compiled constraint from the ConstraintSpec.
///
/// Phase 1 covers `KeywordBlock` and `LengthBound`; more variants land in
/// later phases. Field values follow `policydsl/compile.py`:
/// - keyword lists are lower-cased + sorted,
/// - lengths are inclusive bounds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Constraint {
    /// Response must not contain any of `keywords` (case-insensitive, ASCII).
    KeywordBlock { name: String, keywords: Vec<String> },
    /// Response length (code points) must satisfy `min <= len <= max`.
    LengthBound { name: String, min: u32, max: u32 },
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
