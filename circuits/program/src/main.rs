//! SP1 program: read a Job (public or private mode), judge constraints via the
//! shared `pop-types` logic, and commit the Outcome as public values.
//!
//! Public mode  → `Outcome::Public(ProofOutput)`  (response is part of the request)
//! Private mode → `Outcome::Private(PrivateOutput)` (only the response commitment,
//!                per-violation evidence commitments, and an optional redaction
//!                proof are committed)
//!
//! Rule kinds implemented in-circuit (Phase 1-2): keyword_block, length_bound,
//! pattern_block. Semantics mirror `policydsl.evaluate`.

#![no_main]

sp1_zkvm::entrypoint!(main);

use pop_types::{run_job, Job, Outcome};
use sp1_zkvm::io;

pub fn main() {
    let job: Job = io::read();
    let out: Outcome = run_job(&job);
    io::commit(&out);
}
