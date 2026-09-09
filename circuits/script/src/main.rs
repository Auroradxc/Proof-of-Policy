//! SP1 driver (Phase 0 placeholder): generate + verify a Proof-of-Policy proof.
//!
//! Reads `n` (optional arg, default 42) and produces a proof that the program
//! ran with that input. From Phase 1 the input becomes a ProofRequest and the
//! committed value becomes `(passed, evidence)`.

use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

/// The ELF for the SP1 program (pop-program).
const POP_ELF: Elf = include_elf!("pop-program");

fn main() {
    sp1_sdk::utils::setup_logger();

    let n: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(42);
    println!("placeholder input n = {n}");

    let client = ProverClient::from_env();

    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    let pk = client.setup(POP_ELF).expect("failed to setup elf");
    let proof = client
        .prove(&pk, stdin)
        .run()
        .expect("failed to generate proof");

    println!("Successfully generated proof!");

    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("failed to verify proof");
    println!("Successfully verified proof!");
}
