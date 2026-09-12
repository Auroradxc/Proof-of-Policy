// 构建脚本：把 guest 程序编译成 zkVM ELF，使宿主驱动能通过
// `include_elf!("pop-program")` / `include_elf!("pop-infer")` /
// `include_elf!("pop-session")` 内嵌它们。
//
// 三个 guest：`pop-program` 承载策略合规域，`pop-infer` 承载推理完整性域（P1-6），
// `pop-session` 承载会话聚合域（P2-10）。
// **三个 ELF ⇒ 三个 vkey**，组合引理 L6 的键分离就落在这一点上。
use sp1_build::build_program_with_args;

fn main() {
    build_program_with_args("../program", Default::default());
    build_program_with_args("../infer-program", Default::default());
    build_program_with_args("../session-program", Default::default());
}
