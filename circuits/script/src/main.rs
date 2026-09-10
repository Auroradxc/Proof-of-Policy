//! SP1 driver: prove jobs (public/private), host-check, or independently verify
//! a saved proof.
//!
//! Modes:
//!   pop-script --check  --vectors v.json --out r.json
//!   pop-script          --vectors v.json --out r.json [--proof-out proof.bin]
//!   pop-script --verify --proof proof.bin [--out r.json]
//!
//! `--proof-out` (single-vector prove) saves the proof and a sidecar
//! `<proof-out>.meta.json` carrying the program vkey hash (for certificates).
//! `--verify` loads a proof, re-derives the verifying key from the ELF, verifies
//! cryptographically, and prints the committed Outcome JSON (no secrets needed).

use pop_types::{run_job, Constraint, Job, Outcome, PrivateRequest, ProofRequest};
use serde::Deserialize;
use serde_json::json;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1ProofWithPublicValues, SP1Stdin,
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
            "name": name, "mode": "public",
            "passed": o.passed, "violations": o.violations,
        }),
        Outcome::Private(o) => json!({
            "name": name, "mode": "private",
            "passed": o.passed,
            "response_commitment": o.response_commitment,
            "violations": o.violations,
            "redaction": o.redaction,
        }),
    }
}

fn write_json(path: &str, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_string_pretty(value).unwrap())
        .unwrap_or_else(|e| panic!("write {path}: {e}"));
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let mut vectors_path = "vectors.json".to_string();
    let mut out_path = "results.json".to_string();
    let mut proof_out: Option<String> = None;
    let mut proof_path: Option<String> = None;
    let mut check_mode = false;
    let mut verify_mode = false;

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
            "--proof-out" => {
                i += 1;
                proof_out = args.get(i).cloned();
            }
            "--proof" => {
                i += 1;
                proof_path = args.get(i).cloned();
            }
            "--check" => check_mode = true,
            "--verify" => verify_mode = true,
            other => eprintln!("unknown arg: {other}"),
        }
        i += 1;
    }

    // ---- independent verification mode ----
    if verify_mode {
        let path = proof_path.expect("--verify requires --proof <file>");
        let mut proof = SP1ProofWithPublicValues::load(&path)
            .unwrap_or_else(|e| panic!("load proof {path}: {e}"));
        let client = ProverClient::from_env();
        let pk = client.setup(POP_ELF).expect("setup elf");
        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("verify proof");
        let out: Outcome = proof.public_values.read::<Outcome>();
        let value = json!({ "verified": true, "vkey_hash": pk.verifying_key().bytes32(),
                            "outcome": outcome_json(&None, &out) });
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
        write_json(&out_path, &value);
        return;
    }

    let text = std::fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("read {vectors_path}: {e}"));
    let data: VectorsFile = match serde_json::from_str(&text) {
        Ok(d) => d,
        Err(_) => VectorsFile {
            vectors: serde_json::from_str(&text)
                .expect("vectors must be {\"vectors\":[...]} or [...]"),
        },
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
        write_json(&out_path, &serde_json::Value::Array(results));
        eprintln!("wrote results to {out_path}");
        println!("done");
        return;
    }

    // ---- prove mode ----
    let client = ProverClient::from_env();
    let pk = client.setup(POP_ELF).expect("setup elf");
    if proof_out.is_some() && data.vectors.len() != 1 {
        panic!("--proof-out supports exactly one vector (got {})", data.vectors.len());
    }
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

        if let Some(path) = &proof_out {
            proof.save(path).unwrap_or_else(|e| panic!("save proof {path}: {e}"));
            let meta = json!({ "vkey_hash": pk.verifying_key().bytes32(), "proof_file": path });
            let meta_path = format!("{path}.meta.json");
            write_json(&meta_path, &meta);
            eprintln!("saved proof to {path} (+ {meta_path})");
        }
        results.push(outcome_json(&v.name, &out));
        eprintln!("[{label}] proved");
    }

    write_json(&out_path, &serde_json::Value::Array(results));
    eprintln!("wrote {} result(s) to {out_path}", data.vectors.len());
    println!("done");
}
