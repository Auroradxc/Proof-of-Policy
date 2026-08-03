//! SP1 zkVM program (skeleton).
//!
//! W4 replaces this with the real logic: read a serialized ProofRequest
//! (response bytes + ConstraintSpec JSON), evaluate the compiled constraints
//! inside the zkVM, and commit `passed` (+ optional violation evidence) as
//! the public output.
//!
//! NOTE: not buildable yet — Rust/SP1 toolchain not installed on this machine.
//! See ../README.md for install steps and W4 tasks.

#![no_main]

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Placeholder: read a boolean and commit it back. In W4 this becomes
    // `passed: bool` computed by evaluating the ConstraintSpec over `response`.
    let passed: bool = sp1_zkvm::io::read();
    sp1_zkvm::io::commit(&passed);
}
