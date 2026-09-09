//! SP1 zkVM program (Phase 0 placeholder).
//!
//! Reads a `u32` and commits it back. In Phase 1-3 this is replaced by the
//! real logic: read a serialized ProofRequest (response + ConstraintSpec),
//! evaluate the compiled constraints inside the zkVM, and commit
//! `passed` (+ optional violation evidence) as public output.

#![no_main]

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let n: u32 = sp1_zkvm::io::read();
    sp1_zkvm::io::commit(&n);
}
