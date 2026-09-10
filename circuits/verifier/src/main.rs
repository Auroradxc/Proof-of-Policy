//! `pop-verify` —— Proof-of-Policy 的 verifier-only（仅验证器）二进制。
//!
//! 用 `sp1-verifier` 验证一份已保存的证明，**不构造任何证明器**
//! （无 sp1-sdk、无 ~10 GB 证明器状态、无 Gnark）。支持 `sp1-verifier` 暴露的
//! 证明模式：
//!   - `compressed`（STARK，仅验证器可验证；由 `pop-script --proof-mode compressed` 产出）
//!   - `groth16` / `plonk`（链上友好）
//!
//! Core 证明**不能**仅验证器验证；请用 `pop-script --verify`。
//!
//! 用法：
//!   pop-verify --meta <proof>.verify.json [--out result.json]

use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::exit;

/// 对字节求 SHA-256，返回小写十六进制。
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// 极简命令行解析：返回指定 flag 后面的值。
fn arg_value(args: &[String], flag: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let meta_path = arg_value(&args, "--meta").unwrap_or_else(|| {
        eprintln!("usage: pop-verify --meta <proof>.verify.json [--out result.json]");
        exit(2);
    });
    let out_path = arg_value(&args, "--out");

    // 读取边车（sidecar）元信息：含证明字节/公开值/vkey 哈希的文件路径
    let meta: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&meta_path).expect("read meta"),
    )
    .expect("parse meta json");
    let mode = meta["proof_mode"].as_str().unwrap_or("core").to_string();
    // 在触碰（可能缺失的）工件文件之前先校验模式，避免报出误导性错误
    if !matches!(mode.as_str(), "compressed" | "groth16" | "plonk") {
        eprintln!(
            "proof mode '{mode}' is not verifier-only verifiable \
             (core needs `pop-script --verify`; re-prove with --proof-mode compressed)"
        );
        exit(3);
    }
    // 闭包：按 key 从边车读文件字节
    let read = |key: &str| -> Vec<u8> {
        let p = meta[key].as_str().unwrap_or_else(|| panic!("meta missing {key}"));
        std::fs::read(Path::new(p)).unwrap_or_else(|e| panic!("read {p}: {e}"))
    };
    let proof = read("proof_bytes_file");
    let public_values = read("public_values_file");

    // 按模式选择对应的 sp1-verifier 校验器
    let verified = match mode.as_str() {
        "compressed" => {
            let vkey_hash = read("vkey_hash_file");
            match sp1_verifier::compressed::SP1CompressedVerifierRaw::verify_with_public_values(
                &proof, &public_values, &vkey_hash,
            ) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("compressed verification failed: {e}");
                    false
                }
            }
        }
        "groth16" => {
            let vkey_hash_str = meta["vkey_hash_str"].as_str().unwrap_or_default();
            match sp1_verifier::Groth16Verifier::verify(
                &proof, &public_values, vkey_hash_str, &sp1_verifier::GROTH16_VK_BYTES,
            ) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("groth16 verification failed: {e}");
                    false
                }
            }
        }
        "plonk" => {
            let vkey_hash_str = meta["vkey_hash_str"].as_str().unwrap_or_default();
            match sp1_verifier::PlonkVerifier::verify(
                &proof, &public_values, vkey_hash_str, &sp1_verifier::PLONK_VK_BYTES,
            ) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("plonk verification failed: {e}");
                    false
                }
            }
        }
        other => {
            eprintln!("unsupported proof mode '{other}'");
            exit(3);
        }
    };

    // 解码公开值 —— 这一步是策略绑定的关键，不能省。
    //
    // 只报 `public_values_sha256` 是不够的：那只能证明「证明的公开值是证书
    // 声称的那串字节」，而证书**另有一个** `outcome`/`policy_hash` 字段与之
    // 并列，二者之间没有任何可核对的联系。签发方（或被篡改的证书组装流程）
    // 完全可以声称 `policy_hash = π_real`，而证明的公开值其实来自空策略。
    //
    // 因此这里把公开值**解回 `Outcome` 并原样输出**，让验证方拿它与证书载荷
    // 逐字段比对（三方比对：证书声称的哈希、重编译策略包的哈希、证明承诺的
    // 哈希）。解码失败即视为验证失败：宁可 fail-closed，也不能让「解不出来」
    // 退化成「跳过检查」。
    let decoded: Result<pop_types::Outcome, _> =
        bincode::deserialize::<pop_types::Outcome>(&public_values);
    let (decoded_ok, outcome_json) = match decoded {
        Ok(out) => (true, pop_types::outcome_value(&out)),
        Err(e) => {
            eprintln!("public values do not decode as pop_types::Outcome: {e}");
            (false, serde_json::Value::Null)
        }
    };

    // 汇总验证结果，供第三方核验
    let result = serde_json::json!({
        "verified": verified && decoded_ok,
        "proof_mode": mode,
        "vkey_hash": meta["vkey_hash_str"],
        "public_values_sha256": sha256_hex(&public_values),
        "public_values_len": public_values.len(),
        "proof_bytes_len": proof.len(),
        "outcome": outcome_json,
    });
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    if let Some(p) = out_path {
        std::fs::write(&p, serde_json::to_string_pretty(&result).unwrap()).expect("write out");
    }
    exit(if verified { 0 } else { 1 });
}
