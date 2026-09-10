//! SP1 driver: prove jobs in batch (public or private mode), or host-check.
//!
//! Modes:
//!   pop-script --check --vectors vectors.json --out results.json
//!       Host-side check only (no proof): runs `pop-types::run_job` directly.
//!   pop-script --vectors vectors.json --out results.json
//!       Generates + verifies an SP1 proof per job and reads back the committed
//!       `Outcome`.
//!
//! vectors.json shape:
//!   { "vectors": [ { "name": "...", "response": "...", "constraints": [...],
//!                     "private": false,               // optional
//!                     "mask": [int, ...],             // optional (private)
//!                     "redacted": "..." } ] }         // optional (private)
//!
//! cross-validation harness: scripts/cross_validate.py (public),
//! scripts/private_demo.py (private).

use pop_types::{run_job, Constraint, Job, Outcome, PrivateRequest, ProofRequest};
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
    #[serde(default)]
    private: bool,
    #[serde(default)]
    mask: Vec<u32>,
    #[serde(default)]
    redacted: Option<String>,
    #[serde(default)]
    spans: Vec<(u32, u32)>,
}

#[derive(Deserialize)]
struct VectorsFile {
    #[serde(default)]
    vectors: Vec<VectorIn>,
}

impl VectorIn {
    fn to_job(&self) -> Job {
        if self.private {
            Job::Private(PrivateRequest {
                response: self.response.clone(),
                constraints: self.constraints.clone(),
                mask: self.mask.clone(),
                redacted: self.redacted.clone(),
                spans: self.spans.clone(),
            })
        } else {
            Job::Public(ProofRequest {
                response: self.response.clone(),
                constraints: self.constraints.clone(),
            })
        }
    }
}

fn outcome_json(name: &Option<String>, out: &Outcome) -> serde_json::Value {
    match out {
        Outcome::Public(o) => json!({
            "name": name,
            "mode": "public",
            "passed": o.passed,
            "violations": o.violations,
        }),
        Outcome::Private(o) => json!({
            "name": name,
            "mode": "private",
            "passed": o.passed,
            "response_commitment": o.response_commitment,
            "violations": o.violations,
            "redaction": o.redaction,
        }),
    }
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
    eprintln!(
        "loaded {} vector(s) (mode={})",
        data.vectors.len(),
        if check_mode { "check" } else { "prove" }
    );

    let mut results: Vec<serde_json::Value> = Vec::new();

    if check_mode {
        for (idx, v) in data.vectors.iter().enumerate() {
            let label = v.name.clone().unwrap_or_else(|| format!("#{idx}"));
            let out = run_job(&v.to_job());
            results.push(outcome_json(&v.name, &out));
            eprintln!("[{label}] done");
        }
    } else {
        let client = ProverClient::from_env();
        let pk = client.setup(POP_ELF).expect("setup elf");
        for (idx, v) in data.vectors.iter().enumerate() {
            let label = v.name.clone().unwrap_or_else(|| format!("#{idx}"));
            let mut stdin = SP1Stdin::new();
            stdin.write(&v.to_job());

            eprintln!("[{label}] generating proof ...");
            let mut proof = client.prove(&pk, stdin).run().expect("generate proof");
            let out: Outcome = proof.public_values.read::<Outcome>();
            client
                .verify(&proof, pk.verifying_key(), None)
                .expect("verify proof");

            results.push(outcome_json(&v.name, &out));
            eprintln!("[{label}] proved");
        }
    }

    std::fs::write(&out_path, serde_json::to_string_pretty(&results).unwrap())
        .unwrap_or_else(|e| panic!("write {out_path}: {e}"));
    eprintln!("wrote {} result(s) to {out_path}", results.len());
    println!("done");
}
