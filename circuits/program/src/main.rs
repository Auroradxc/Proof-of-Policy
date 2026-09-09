//! SP1 program: read a ProofRequest, judge constraints (shared logic in
//! `pop-types::evaluate`), and commit the `ProofOutput` as public values.
//!
//! Rule kinds implemented in-circuit (Phase 1-2):
//!   - keyword_block : ASCII case-insensitive substring
//!   - length_bound  : code-point length within [min, max]
//!   - pattern_block : substring regex via the compiled NFA
//! Semantics mirror `policydsl.evaluate`; cross-validated by
//! `scripts/cross_validate.py`.

#![no_main]

sp1_zkvm::entrypoint!(main);

use pop_types::{evaluate, ProofOutput, ProofRequest};
use sp1_zkvm::io;

pub fn main() {
    let req: ProofRequest = io::read();
    let out: ProofOutput = evaluate(&req);
    io::commit(&out);
}
