//! SP1 程序（**会话聚合域**，P2-10）：读取一个 `Job::Session`，在 zkVM 内对
//! **一组证书**判定三件事，并把 `Outcome::Session(SessionOutput)` 作为公开值承诺。
//!
//! 三条义务（都由 `pop_types::run_session` 在电路内断言，不满足就出不了证明）：
//!
//! 1. **同一策略** —— 整组证书的 `policy_hash` 全同；
//! 2. **无缝拼接** —— `streaming.chain = {index, prev}` 逐张连续，`prev` 指向
//!    上一张的载荷摘要（首张为 `genesis`），与 `verify_chain` 同一判据；
//! 3. **覆盖完整轨迹** —— 链尾那张证书携带网关签的会话末端承诺（`trace_seal`），
//!    其 `(count, trace_root)` 进公开值。
//!
//! 证明方之外的人怎么用它：验证方拿**手上的证书文件**重算每张的
//! `cert_digest` 与 Merkle 根，与本证明承诺的 `merkle_root` 逐字节比对。任何
//! 「换一张 / 挖掉一张 / 重排」都会改变根 ⟹ 对不上。于是「这组证书是同策略、
//! 无缺口、覆盖完整轨迹」就不再是验证方对着 JSON 的自述式核对，而是一次
//! 有密码学承诺的聚合结论。
//!
//! 本 guest **拒绝**其它三个域（策略合规 / 推理完整性 / 私有）：四个域各有各的
//! vkey，组合引理 L6 的键分离就落在这一行断言上。

#![no_main]

sp1_zkvm::entrypoint!(main);

use pop_types::{job_domain, run_job, Job, Outcome, DOMAIN_SESSION};
use sp1_zkvm::io;

pub fn main() {
    let job: Job = io::read();
    assert_eq!(
        job_domain(&job),
        DOMAIN_SESSION,
        "pop-session 只接受会话聚合任务（Session）；策略/推理任务请交给 pop-program / pop-infer"
    );
    let out: Outcome = run_job(&job);
    io::commit(&out);
}
