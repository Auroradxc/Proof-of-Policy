// 构建脚本：把 guest 程序编译成 zkVM ELF，使宿主驱动能通过
// `include_elf!("pop-program")` / `include_elf!("pop-infer")` 内嵌它们。
//
// 两个 guest（P1-6）：`pop-program` 承载策略合规域，`pop-infer` 承载推理完整性域。
// **两个 ELF ⇒ 两个 vkey**，组合引理 L6 的键分离就落在这一点上。
use sp1_build::build_program_with_args;

fn main() {
    build_program_with_args("../program", Default::default());
    build_program_with_args("../infer-program", Default::default());
}
