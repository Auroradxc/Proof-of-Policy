//! SP1 program: judge whether a response satisfies constraints and commit
//! `ProofOutput` as public values.
//!
//! Phase 1 covers:
//! - `keyword_block`: response must not contain any listed keyword
//!   (ASCII case-insensitive substring; semantics mirror `policydsl.evaluate`)
//! - `length_bound`:   response length in code points within `[min, max]`
//!
//! Cross-validated against the Python golden by `scripts/cross_validate.py`.

#![no_main]

sp1_zkvm::entrypoint!(main);

use pop_types::{Constraint, ProofOutput, ProofRequest, Violation};
use sp1_zkvm::io;

/// ASCII-only lower-casing, to match the reference for ASCII responses.
/// (Non-ASCII letters are left unchanged — divergence documented for now.)
fn ascii_lower(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

fn evaluate(req: &ProofRequest) -> ProofOutput {
    let mut violations: Vec<Violation> = Vec::new();

    for c in &req.constraints {
        match c {
            Constraint::KeywordBlock { name, keywords } => {
                let text = ascii_lower(&req.response);
                if let Some(hit) = keywords.iter().find(|kw| text.contains(kw.as_str())) {
                    violations.push(Violation {
                        rule: name.clone(),
                        kind: "keyword_block".to_string(),
                        evidence: hit.clone(),
                    });
                }
            }
            Constraint::LengthBound { name, min, max } => {
                let n = req.response.chars().count();
                if n < *min as usize || n > *max as usize {
                    violations.push(Violation {
                        rule: name.clone(),
                        kind: "length_bound".to_string(),
                        evidence: format!("len={}", n),
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

pub fn main() {
    let req: ProofRequest = io::read();
    let out = evaluate(&req);
    io::commit(&out);
}
