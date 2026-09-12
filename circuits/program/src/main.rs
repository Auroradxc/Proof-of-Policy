//! SP1 程序（**策略合规域**）：读取一个 Job（公开或私有模式），经由共享的
//! `pop-types` 逻辑判定约束，并把 Outcome 作为公开值（public values）承诺。
//!
//! 公开模式  → `Outcome::Public(ProofOutput)`  （响应是请求的一部分）
//! 私有模式  → `Outcome::Private(PrivateOutput)`（仅承诺响应承诺、逐违规的
//!             证据承诺，以及可选的脱敏证明）
//!
//! 电路内实现的规则类型（阶段一至二）：keyword_block、length_bound、
//! pattern_block、format_check、tool_arg_guard、budget_bound。
//!
//! **本 guest 拒绝推理任务**（`Job::Infer`，P1-6）：推理完整性由**另一个**
//! guest（`pop-infer`）承载，两个 vkey 因此不同 —— 这是组合引理 L6 的键分离。
//! 少了这道断言，同一个 ELF 就能既出策略证明又出推理证明，验证方无法据 vkey
//! 判断手里这份证明属于哪一半。

#![no_main]

// 入口点宏：把 `main` 注册为 zkVM 程序入口。
sp1_zkvm::entrypoint!(main);

use pop_types::{job_domain, run_job, Job, Outcome, DOMAIN_POLICY};
use sp1_zkvm::io;

pub fn main() {
    // 从 zkVM 的私有输入里读入 Job（不进入公开值，即证明中不可见）
    let job: Job = io::read();
    assert_eq!(
        job_domain(&job),
        DOMAIN_POLICY,
        "pop-program 只接受策略合规任务（Public/Private）；推理任务请交给 pop-infer"
    );
    // 用共享逻辑判定（链下/链上同一实现，保证判定一致）
    let out: Outcome = run_job(&job);
    // 把 Outcome 提交为公开值（验证者可读取并据此核验）
    io::commit(&out);
}
