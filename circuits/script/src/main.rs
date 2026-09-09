//! SP1 driver: prove responses satisfy constraints (batch), or host-check.
//!
//! Modes:
//!   pop-script --check   --vectors vectors.json --out results.json
//!       Host-side check only (no proof): runs `pop-types::evaluate` directly.
//!       Used by cross-validation to test all vectors quickly.
//!   pop-script --vectors vectors.json --out results.json
//!       Generates + verifies an SP1 proof per vector and reads back the
//!       committed `ProofOutput`.
//!
//! vectors.json shape (serde externally-tagged Constraint):
//!   { "vectors": [ { "name": "...", "response": "...",
//!                     "constraints": [
//!                        {"KeywordBlock": {"name": "...", "keywords": [...]}},
//!                        {"LengthBound":  {"name": "...", "min": 0, "max": 100}},
//!                        {"PatternBlock": {"name": "...", "patterns": [...],
//!                                          "specs": [ <NfaSpec>, ... ]}}
//!                     ] } ] }
//!
//! Cross-validation harness: scripts/cross_validate.py.

use pop_types::{evaluate, Constraint, ProofOutput, ProofRequest};
use serde::Deserialize;
use serde_json::json;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};

const POP_ELF: Elf = include_elf!("pop-program");

#[derive(Deserialize)]
struct VectorIn {
    #[serde(default)]
    name: Option<String>,
    response: String,
    constraints: Vec<Constraint>,
}

#[derive(Deserialize)]
struct VectorsFile {
    #[serde(default)]
    vectors: Vec<VectorIn>,
}

fn result_entry(name: &Option<String>, out: &ProofOutput) -> serde_json::Value {
    json!({
        "name": name,
        "passed": out.passed,
        "violations": out.violations,
    })
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let mut vectors_path = "vectors.json".to_string();
    let mut out_path = "results.json".to_string();
    let mut check_mode = false;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--vectors" => {
                i += 1;
                vectors_path = args.get(i).cloned().unwrap_or_default();
            }
            "--out" => {
                i += 1;
                out_path = args.get(i).cloned().unwrap_or_default();
            }
            "--check" => check_mode = true,
            other => eprintln!("unknown arg: {other}"),
        }
        i += 1;
    }

    let text = std::fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("read {vectors_path}: {e}"));
    let data: VectorsFile = match serde_json::from_str(&text) {
        Ok(d) => d,
        Err(_) => {
            let v: Vec<VectorIn> =
                serde_json::from_str(&text).expect("vectors must be {\"vectors\":[...]} or [...]");
            VectorsFile { vectors: v }
        }
    };
    eprintln!("loaded {} vector(s) (mode={})", data.vectors.len(), if check_mode { "check" } else { "prove" });

    let mut results: Vec<serde_json::Value> = Vec::new();

    if check_mode {
        for (idx, v) in data.vectors.iter().enumerate() {
            let label = v.name.clone().unwrap_or_else(|| format!("#{idx}"));
            let req = ProofRequest {
                response: v.response.clone(),
                constraints: v.constraints.clone(),
            };
            let out = evaluate(&req);
            results.push(result_entry(&v.name, &out));
            eprintln!("[{label}] passed={} violations={}", out.passed, out.violations.len());
        }
    } else {
        let client = ProverClient::from_env();
        let pk = client.setup(POP_ELF).expect("setup elf");
        for (idx, v) in data.vectors.iter().enumerate() {
            let label = v.name.clone().unwrap_or_else(|| format!("#{idx}"));
            let req = ProofRequest {
                response: v.response.clone(),
                constraints: v.constraints.clone(),
            };

            let mut stdin = SP1Stdin::new();
            stdin.write(&req);

            eprintln!("[{label}] generating proof ...");
            let mut proof = client.prove(&pk, stdin).run().expect("generate proof");
            let out: ProofOutput = proof.public_values.read::<ProofOutput>();
            client
                .verify(&proof, pk.verifying_key(), None)
                .expect("verify proof");

            results.push(result_entry(&v.name, &out));
            eprintln!("[{label}] passed={} violations={}", out.passed, out.violations.len());
        }
    }

    std::fs::write(&out_path, serde_json::to_string_pretty(&results).unwrap())
        .unwrap_or_else(|e| panic!("write {out_path}: {e}"));
    eprintln!("wrote {} result(s) to {out_path}", results.len());
    println!("done");
}
