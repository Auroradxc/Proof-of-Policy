//! SP1 程序（**推理完整性域**，P1-6）：读取一个 `Job::Infer`，在 zkVM 内跑一遍
//! **确定性小模型前向**，并把 `Outcome::Infer(InferOutput)` 作为公开值承诺。
//!
//! 这是 P1-6「与 zkAgent 联合证明」的**代理**（stand-in）：zkAgent 是外部 C++
//! 系统、源码不可得（计划 D1），所以用一个结构同构的小模型（MLP，定点整数）
//! 替代，用来实测「组合成本 ≈ 两者之和」这一假设是否成立。真实替换时只需把
//! 本 guest 的 `run_job` 换成 zkAgent 的 prover —— 上下（`pop-types` 的公开值
//! 形状、`policydsl/compose.py` 的组合驱动）都不动。
//!
//! 本 guest **拒绝**策略合规任务（`Job::Public`/`Job::Private`）：两个域各有各的
//! vkey，组合引理 L6 的键分离就落在这一行断言上。

#![no_main]

sp1_zkvm::entrypoint!(main);

use pop_types::{job_domain, run_job, Job, Outcome, DOMAIN_INFER};
use sp1_zkvm::io;

pub fn main() {
    let job: Job = io::read();
    assert_eq!(
        job_domain(&job),
        DOMAIN_INFER,
        "pop-infer 只接受推理任务（Infer）；策略合规任务请交给 pop-program"
    );
    let out: Outcome = run_job(&job);
    io::commit(&out);
}
