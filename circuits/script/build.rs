// 构建脚本：把 ../program（guest 程序）编译成 zkVM ELF，
// 使宿主驱动能通过 include_elf!("pop-program") 内嵌它。
use sp1_build::build_program_with_args;

fn main() {
    build_program_with_args("../program", Default::default())
}
