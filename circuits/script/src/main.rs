//! SP1 驱动：证明任务（公开/私有）、宿主校验，或独立验证已保存的证明。
//!
//! 模式：
//!   pop-script --check  --vectors v.json --out r.json
//!   pop-script          --vectors v.json --out r.json [--proof-out proof.bin]
//!   pop-script --verify --proof proof.bin [--out r.json]
//!
//! `--proof-out`（单向量证明）保存证明与一个边车 `<proof-out>.meta.json`，
//! 携带程序 vkey 哈希（供证书使用）。`--verify` 加载证明、从 ELF 重新推导
//! 验证密钥、做密码学验证，并打印承诺的 Outcome JSON（无需任何秘密）。

use pop_types::{run_job, Constraint, Job, Outcome, PrivateRequest, ProofRequest};
use serde::Deserialize;
use serde_json::json;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1ProofWithPublicValues, SP1Stdin,
};

// 内嵌 guest 程序 ELF（由 build.rs 编译生成）
const POP_ELF: Elf = include_elf!("pop-program");

/// 从 vectors.json 反序列化的单个输入向量。
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
    #[serde(default)]
    tool_calls: Vec<pop_types::ToolCall>,
    #[serde(default)]
    token_count: Option<u32>,
}

#[derive(Deserialize)]
struct VectorsFile {
    #[serde(default)]
    vectors: Vec<VectorIn>,
}

impl VectorIn {
    /// 根据 private 标志转成对应的 Job（公开/私有）。
    fn to_job(&self) -> Job {
        if self.private {
            Job::Private(PrivateRequest {
                response: self.response.clone(),
                constraints: self.constraints.clone(),
                mask: self.mask.clone(),
                redacted: self.redacted.clone(),
                spans: self.spans.clone(),
                tool_calls: self.tool_calls.clone(),
                token_count: self.token_count,
            })
        } else {
            Job::Public(ProofRequest {
                response: self.response.clone(),
                constraints: self.constraints.clone(),
                tool_calls: self.tool_calls.clone(),
                token_count: self.token_count,
            })
        }
    }
}

/// 把 Outcome 序列化为带 name/mode 的结果 JSON（公开/私有两种形态）。
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

/// 把 JSON 值美化写入文件。
fn write_json(path: &str, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_string_pretty(value).unwrap())
        .unwrap_or_else(|e| panic!("write {path}: {e}"));
}

/// 在证明旁写出 verifier-only 二进制（`pop-verify`）所需的文件：
///   <proof>.bytes  bincode(SP1Proof)  (compressed) | 链上字节 (groth16/plonk)
///   <proof>.pv     原始公开值
///   <proof>.vkh    bincode(vk.hash_koalabear())   (compressed)
///   <proof>.verify.json  描述上述文件的边车
fn write_verifier_sidecar(path: &str, proof: &SP1ProofWithPublicValues,
                          vk: &sp1_sdk::SP1VerifyingKey, mode: &str) {
    use sp1_sdk::SP1Proof;
    let proof_bytes = match mode {
        "compressed" => bincode::serialize(&proof.proof).expect("bincode(SP1Proof)"),
        "groth16" | "plonk" => match &proof.proof {
            SP1Proof::Groth16(_) | SP1Proof::Plonk(_) => proof.bytes(),
            _ => panic!("proof mode {mode} but proof is not groth16/plonk"),
        },
        _ => bincode::serialize(&proof.proof).expect("bincode(SP1Proof)"),
    };
    let pv = proof.public_values.as_slice().to_vec();
    let vkh = bincode::serialize(&vk.hash_koalabear()).expect("bincode(vkey hash)");
    let bytes_file = format!("{path}.bytes");
    let pv_file = format!("{path}.pv");
    let vkh_file = format!("{path}.vkh");
    std::fs::write(&bytes_file, &proof_bytes).expect("write proof bytes");
    std::fs::write(&pv_file, &pv).expect("write public values");
    std::fs::write(&vkh_file, &vkh).expect("write vkey hash");
    let sidecar = json!({
        "proof_mode": mode,
        "proof_bytes_file": bytes_file,
        "public_values_file": pv_file,
        "vkey_hash_file": vkh_file,
        "vkey_hash_str": vk.bytes32(),
    });
    write_json(&format!("{path}.verify.json"), &sidecar);
}

fn main() {
    sp1_sdk::utils::setup_logger();

    // 默认参数
    let mut vectors_path = "vectors.json".to_string();
    let mut out_path = "results.json".to_string();
    let mut proof_out: Option<String> = None;
    let mut proof_path: Option<String> = None;
    let mut check_mode = false;
    let mut execute_mode = false;
    let mut verify_mode = false;
    let mut verify_reps: u32 = 1;
    let mut proof_mode = "core".to_string();

    // 极简命令行解析
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
            "--proof-mode" => {
                i += 1;
                proof_mode = args.get(i).cloned().unwrap_or_else(|| "core".to_string());
            }
            "--verify-reps" => {
                i += 1;
                verify_reps = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(1);
            }
            "--check" => check_mode = true,
            "--execute" => execute_mode = true,
            "--verify" => verify_mode = true,
            other => eprintln!("unknown arg: {other}"),
        }
        i += 1;
    }

    // ---- 独立验证模式 ----
    if verify_mode {
        let path = proof_path.expect("--verify requires --proof <file>");
        let mut proof = SP1ProofWithPublicValues::load(&path)
            .unwrap_or_else(|e| panic!("load proof {path}: {e}"));
        let client = ProverClient::from_env();
        // 从 ELF 重新 setup 以推导验证密钥（vkey）
        let t_setup = std::time::Instant::now();
        let pk = client.setup(POP_ELF).expect("setup elf");
        let setup_secs = t_setup.elapsed().as_secs_f64();
        let vk = pk.verifying_key();
        // 重复验证以把 vkey 推导（setup）与 verify 分开计时
        let mut times: Vec<f64> = Vec::new();
        for _ in 0..verify_reps.max(1) {
            let t = std::time::Instant::now();
            client.verify(&proof, vk, None).expect("verify proof");
            times.push(t.elapsed().as_secs_f64());
        }
        let out: Outcome = proof.public_values.read::<Outcome>();
        let value = json!({ "verified": true, "vkey_hash": vk.bytes32(),
                            "setup_seconds": setup_secs, "verify_times_seconds": times,
                            "outcome": outcome_json(&None, &out) });
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
        write_json(&out_path, &value);
        return;
    }

    // 读取 vectors 文件（支持 {"vectors":[...]} 或裸 [...] 两种形态）
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

    // ---- 宿主校验模式：直接跑共享逻辑，不生成证明 ----
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

    // ---- 仅执行模式：在 zkVM 内跑并报告 cycle 数（不生成证明） ----
    if execute_mode {
        let client = ProverClient::from_env();
        for (idx, v) in data.vectors.iter().enumerate() {
            let label = v.name.clone().unwrap_or_else(|| format!("#{idx}"));
            let mut stdin = SP1Stdin::new();
            stdin.write(&v.to_job());
            let (pv, report) = client.execute(POP_ELF, stdin).run().expect("execute");
            let mut pv = pv;
            let out: Outcome = pv.read::<Outcome>();
            let mut entry = outcome_json(&v.name, &out);
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("cycles".to_string(), json!(report.total_instruction_count()));
            }
            eprintln!("[{label}] cycles={}", report.total_instruction_count());
            results.push(entry);
        }
        write_json(&out_path, &serde_json::Value::Array(results));
        eprintln!("wrote {} execute result(s) to {out_path}", data.vectors.len());
        println!("done");
        return;
    }

    // ---- 证明模式 ----
    let client = ProverClient::from_env();
    let pk = client.setup(POP_ELF).expect("setup elf");
    if proof_out.is_some() && data.vectors.len() != 1 {
        panic!("--proof-out supports exactly one vector (got {})", data.vectors.len());
    }
    for (idx, v) in data.vectors.iter().enumerate() {
        let label = v.name.clone().unwrap_or_else(|| format!("#{idx}"));
        let mut stdin = SP1Stdin::new();
        stdin.write(&v.to_job());

        eprintln!("[{label}] generating proof (mode={proof_mode}) ...");
        // 按 --proof-mode 选择 core/compressed/groth16/plonk
        let req = client.prove(&pk, stdin);
        let req = match proof_mode.as_str() {
            "compressed" => req.compressed(),
            "groth16" => req.groth16(),
            "plonk" => req.plonk(),
            _ => req.core(),
        };
        let mut proof = req.run().expect("generate proof");
        let out: Outcome = proof.public_values.read::<Outcome>();
        // 生成后立即做一次本地验证，确保证明有效
        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("verify proof");

        // 若指定 --proof-out：保存证明 + 边车 + 元信息
        if let Some(path) = &proof_out {
            proof.save(path).unwrap_or_else(|e| panic!("save proof {path}: {e}"));
            write_verifier_sidecar(path, &proof, pk.verifying_key(), &proof_mode);
            let meta = json!({ "vkey_hash": pk.verifying_key().bytes32(), "proof_file": path,
                               "proof_mode": proof_mode });
            let meta_path = format!("{path}.meta.json");
            write_json(&meta_path, &meta);
            eprintln!("saved proof to {path} (+ {meta_path}, verifier sidecar)");
        }
        results.push(outcome_json(&v.name, &out));
        eprintln!("[{label}] proved");
    }

    write_json(&out_path, &serde_json::Value::Array(results));
    eprintln!("wrote {} result(s) to {out_path}", data.vectors.len());
    println!("done");
}
