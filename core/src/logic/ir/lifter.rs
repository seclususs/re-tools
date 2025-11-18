//! Author: [Seclususs](https://github.com/seclususs)

use super::instruction::{
    MicroAtomicOp, MicroBinOp, MicroExpr, MicroInstruction, MicroOperand, MicroUnOp, SsaVariabel,
};
use crate::error::ReToolsError;
use crate::logic::static_analysis::disasm::{buat_instance_capstone_by_arch, ArsitekturDisasm};
use capstone::arch::{
    arm::{ArmInsnDetail, ArmOperand, ArmOperandType},
    arm64::{Arm64InsnDetail, Arm64OpMem, Arm64Operand, Arm64OperandType},
    mips::{MipsInsnDetail, MipsOpMem, MipsOperand},
    riscv::{RiscVInsnDetail, RiscVOpMem, RiscVOperand},
    x86::{X86InsnDetail, X86OpMem, X86Operand, X86OperandType},
    ArchDetail,
};
use capstone::prelude::*;

#[allow(non_snake_case)]
pub fn buatSsaVariabel(reg_name: String) -> SsaVariabel {
    SsaVariabel {
        nama_dasar: reg_name,
        versi: 0,
    }
}

#[allow(non_snake_case)]
pub fn buatSsaVariabelDariRegId(reg_id: RegId, cs: &Capstone) -> SsaVariabel {
    let reg_name = cs.reg_name(reg_id).unwrap_or("unknown_reg".to_string());
    buatSsaVariabel(reg_name)
}

#[allow(non_snake_case)]
pub fn petakanAlamatMemoriX86(mem_op: &X86OpMem, cs: &Capstone) -> MicroExpr {
    let mut expr_opt: Option<Box<MicroExpr>> = None;
    if mem_op.base().0 != 0 {
        let base_var = buatSsaVariabelDariRegId(mem_op.base(), cs);
        expr_opt = Some(Box::new(MicroExpr::Operand(MicroOperand::SsaVar(
            base_var,
        ))));
    }
    if mem_op.index().0 != 0 {
        let index_var = buatSsaVariabelDariRegId(mem_op.index(), cs);
        let index_expr = Box::new(MicroExpr::Operand(MicroOperand::SsaVar(index_var)));
        let scale_expr = Box::new(MicroExpr::Operand(MicroOperand::Konstanta(
            mem_op.scale() as u64,
        )));
        let scaled_index = Box::new(MicroExpr::OperasiBiner(
            MicroBinOp::Mul,
            index_expr,
            scale_expr,
        ));
        if let Some(base_expr) = expr_opt {
            expr_opt = Some(Box::new(MicroExpr::OperasiBiner(
                MicroBinOp::Add,
                base_expr,
                scaled_index,
            )));
        } else {
            expr_opt = Some(scaled_index);
        }
    }
    if mem_op.disp() != 0 {
        let disp_expr = Box::new(MicroExpr::Operand(MicroOperand::Konstanta(
            mem_op.disp() as u64,
        )));
        if let Some(base_expr) = expr_opt {
            expr_opt = Some(Box::new(MicroExpr::OperasiBiner(
                MicroBinOp::Add,
                base_expr,
                disp_expr,
            )));
        } else {
            expr_opt = Some(disp_expr);
        }
    }
    *expr_opt.unwrap_or(Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))))
}

#[allow(non_snake_case)]
pub fn petakanOperandKeEkspresiSsaX86(op: &X86Operand, cs: &Capstone) -> MicroExpr {
    match op.op_type {
        X86OperandType::Reg(reg_id) => {
            let var = buatSsaVariabelDariRegId(reg_id, cs);
            MicroExpr::Operand(MicroOperand::SsaVar(var))
        }
        X86OperandType::Imm(imm_val) => {
            MicroExpr::Operand(MicroOperand::Konstanta(imm_val as u64))
        }
        X86OperandType::Mem(mem_op) => {
            let addr_expr = petakanAlamatMemoriX86(&mem_op, cs);
            MicroExpr::MuatMemori(Box::new(addr_expr))
        }
        _ => MicroExpr::Operand(MicroOperand::Konstanta(0)),
    }
}

#[allow(non_snake_case)]
fn petakanOperandKeMicroOperandX86(op: &X86Operand, cs: &Capstone) -> MicroOperand {
    match op.op_type {
        X86OperandType::Reg(reg_id) => {
            let var = buatSsaVariabelDariRegId(reg_id, cs);
            MicroOperand::SsaVar(var)
        }
        X86OperandType::Imm(val) => MicroOperand::Konstanta(val as u64),
        _ => MicroOperand::Konstanta(0),
    }
}

fn generate_eflags_update(
    instrs: &mut Vec<MicroInstruction>,
    res_expr: MicroExpr,
    op1_expr: MicroExpr,
    op2_expr: MicroExpr,
    is_sub: bool,
) {
    let res_boxed = Box::new(res_expr.clone());
    let op1_boxed = Box::new(op1_expr);
    let op2_boxed = Box::new(op2_expr);
    instrs.push(MicroInstruction::UpdateFlag(
        "ZF".to_string(),
        MicroExpr::OperasiUnary(MicroUnOp::ExtractZeroFlag, res_boxed.clone()),
    ));
    instrs.push(MicroInstruction::UpdateFlag(
        "SF".to_string(),
        MicroExpr::OperasiUnary(MicroUnOp::ExtractSignFlag, res_boxed.clone()),
    ));
    let overflow_op = if is_sub {
        MicroExpr::OperasiBiner(MicroBinOp::Sub, op1_boxed.clone(), op2_boxed.clone()) 
    } else {
        MicroExpr::OperasiBiner(MicroBinOp::Add, op1_boxed.clone(), op2_boxed.clone())
    };
    instrs.push(MicroInstruction::UpdateFlag(
        "OF".to_string(),
        MicroExpr::OperasiUnary(MicroUnOp::ExtractOverflowFlag, Box::new(overflow_op)),
    ));
    let carry_expr = if is_sub {
        MicroExpr::Bandingkan(op1_boxed, op2_boxed)
    } else {
        *res_boxed
    };
     instrs.push(MicroInstruction::UpdateFlag(
        "CF".to_string(),
        MicroExpr::OperasiUnary(MicroUnOp::ExtractCarryFlag, Box::new(carry_expr)),
    ));
}

#[allow(non_snake_case)]
pub fn angkatSsaX86(
    insn: &capstone::Insn,
    detail: &X86InsnDetail,
    cs: &Capstone,
    arch: ArsitekturDisasm,
) -> Vec<MicroInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<X86Operand> = detail.operands().collect();
    let has_lock_prefix = detail.prefix().contains(&0xF0);
    macro_rules! angkatOperasiBiner {
        ($op:expr, $is_sub:expr) => {{
            let mut instrs = Vec::new();
            if operands.len() == 2 {
                let dest_op = &operands[0];
                let src_expr = petakanOperandKeEkspresiSsaX86(&operands[1], cs);
                
                if has_lock_prefix {
                     match dest_op.op_type {
                         X86OperandType::Mem(mem_op) => {
                             let addr_expr = petakanAlamatMemoriX86(&mem_op, cs);
                             let atomic_op = match $op {
                                 MicroBinOp::Add => MicroAtomicOp::Add,
                                 MicroBinOp::Sub => MicroAtomicOp::Sub,
                                 MicroBinOp::And => MicroAtomicOp::And,
                                 MicroBinOp::Or => MicroAtomicOp::Or,
                                 MicroBinOp::Xor => MicroAtomicOp::Xor,
                                 _ => MicroAtomicOp::Add,
                             };
                             instrs.push(MicroInstruction::AtomicRMW {
                                 op: atomic_op,
                                 alamat: addr_expr,
                                 nilai: src_expr,
                                 tujuan_lama: None,
                             });
                         },
                         _ => instrs.push(MicroInstruction::TidakTerdefinisi),
                     }
                } else {
                    match dest_op.op_type {
                        X86OperandType::Reg(reg_id) => {
                            let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                            let dest_expr = MicroExpr::Operand(MicroOperand::SsaVar(dest_var.clone()));
                            let res_expr = MicroExpr::OperasiBiner($op, Box::new(dest_expr.clone()), Box::new(src_expr.clone()));
                            instrs.push(MicroInstruction::Assign(dest_var.clone(), res_expr.clone()));
                            generate_eflags_update(&mut instrs, res_expr, dest_expr, src_expr, $is_sub);
                        }
                        X86OperandType::Mem(mem_op) => {
                            let addr_expr = petakanAlamatMemoriX86(&mem_op, cs);
                            let dest_expr = MicroExpr::MuatMemori(Box::new(addr_expr.clone()));
                            let res_expr = MicroExpr::OperasiBiner($op, Box::new(dest_expr.clone()), Box::new(src_expr.clone()));
                            instrs.push(MicroInstruction::SimpanMemori(addr_expr, res_expr.clone()));
                            generate_eflags_update(&mut instrs, res_expr, dest_expr, src_expr, $is_sub);
                        }
                        _ => instrs.push(MicroInstruction::TidakTerdefinisi),
                    }
                }
            } else {
                instrs.push(MicroInstruction::TidakTerdefinisi);
            }
            instrs
        }};
    }
    match mnem {
        "mov" | "movsx" | "movzx" | "movabs" => {
            if operands.len() == 2 {
                let dest_op = &operands[0];
                let src_expr = petakanOperandKeEkspresiSsaX86(&operands[1], cs);
                match dest_op.op_type {
                    X86OperandType::Reg(reg_id) => {
                        let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                        vec![MicroInstruction::Assign(dest_var, src_expr)]
                    }
                    X86OperandType::Mem(mem_op) => {
                        let addr_expr = petakanAlamatMemoriX86(&mem_op, cs);
                        vec![MicroInstruction::SimpanMemori(addr_expr, src_expr)]
                    }
                    _ => vec![MicroInstruction::TidakTerdefinisi],
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "xchg" => {
             if operands.len() == 2 {
                 if has_lock_prefix {
                      let dest_op = &operands[0];
                      let src_expr = petakanOperandKeEkspresiSsaX86(&operands[1], cs);
                      match dest_op.op_type {
                          X86OperandType::Mem(mem_op) => {
                               let addr_expr = petakanAlamatMemoriX86(&mem_op, cs);
                               vec![MicroInstruction::AtomicRMW {
                                   op: MicroAtomicOp::Xchg,
                                   alamat: addr_expr,
                                   nilai: src_expr,
                                   tujuan_lama: None,
                               }]
                          },
                          _ => vec![MicroInstruction::TidakTerdefinisi] 
                      }
                 } else {
                     let op1 = petakanOperandKeEkspresiSsaX86(&operands[0], cs);
                     let op2 = petakanOperandKeEkspresiSsaX86(&operands[1], cs);
                     let mut instrs = Vec::new();
                     if let X86OperandType::Reg(r1) = operands[0].op_type {
                         instrs.push(MicroInstruction::Assign(buatSsaVariabelDariRegId(r1, cs), op2));
                     }
                     if let X86OperandType::Reg(r2) = operands[1].op_type {
                          instrs.push(MicroInstruction::Assign(buatSsaVariabelDariRegId(r2, cs), op1));
                     }
                     instrs
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        }
        "lea" => {
            if operands.len() == 2 {
                let dest_op = &operands[0];
                let src_op = &operands[1];
                if let X86OperandType::Reg(reg_id) = dest_op.op_type {
                    if let X86OperandType::Mem(mem_op) = src_op.op_type {
                        let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                        let addr_expr = petakanAlamatMemoriX86(&mem_op, cs);
                        vec![MicroInstruction::Assign(dest_var, addr_expr)]
                    } else {
                        vec![MicroInstruction::TidakTerdefinisi]
                    }
                } else {
                    vec![MicroInstruction::TidakTerdefinisi]
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "push" => {
            if operands.len() == 1 {
                let (reg_sp_name, op_size) = match arch {
                    ArsitekturDisasm::ARCH_X86_64 => ("rsp".to_string(), 8u64),
                    _ => ("esp".to_string(), 4u64),
                };
                let reg_sp = buatSsaVariabel(reg_sp_name);
                let src_expr = petakanOperandKeEkspresiSsaX86(&operands[0], cs);
                let t1 = buatSsaVariabel("t_stack_push".to_string());
                let expr_sub = MicroExpr::OperasiBiner(
                    MicroBinOp::Sub,
                    Box::new(MicroExpr::Operand(MicroOperand::SsaVar(reg_sp.clone()))),
                    Box::new(MicroExpr::Operand(MicroOperand::Konstanta(op_size))),
                );
                let instr1 = MicroInstruction::Assign(t1.clone(), expr_sub);
                let instr2 = MicroInstruction::SimpanMemori(
                    MicroExpr::Operand(MicroOperand::SsaVar(t1.clone())),
                    src_expr,
                );
                let instr3 = MicroInstruction::Assign(
                    reg_sp,
                    MicroExpr::Operand(MicroOperand::SsaVar(t1)),
                );
                vec![instr1, instr2, instr3]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "pop" => {
            if operands.len() == 1 {
                if let X86OperandType::Reg(reg_id) = operands[0].op_type {
                    let (reg_sp_name, op_size) = match arch {
                        ArsitekturDisasm::ARCH_X86_64 => ("rsp".to_string(), 8u64),
                        _ => ("esp".to_string(), 4u64),
                    };
                    let reg_sp = buatSsaVariabel(reg_sp_name);
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let t1 = buatSsaVariabel("t_stack_pop".to_string());
                    let expr_load = MicroExpr::MuatMemori(Box::new(MicroExpr::Operand(
                        MicroOperand::SsaVar(reg_sp.clone()),
                    )));
                    let instr1 = MicroInstruction::Assign(t1.clone(), expr_load);
                    let instr2 = MicroInstruction::Assign(
                        dest_var,
                        MicroExpr::Operand(MicroOperand::SsaVar(t1)),
                    );
                    let t2 = buatSsaVariabel("t_stack_adj".to_string());
                    let expr_add = MicroExpr::OperasiBiner(
                        MicroBinOp::Add,
                        Box::new(MicroExpr::Operand(MicroOperand::SsaVar(reg_sp.clone()))),
                        Box::new(MicroExpr::Operand(MicroOperand::Konstanta(op_size))),
                    );
                    let instr3 = MicroInstruction::Assign(t2.clone(), expr_add);
                    let instr4 = MicroInstruction::Assign(
                        reg_sp,
                        MicroExpr::Operand(MicroOperand::SsaVar(t2)),
                    );
                    vec![instr1, instr2, instr3, instr4]
                } else {
                    vec![MicroInstruction::TidakTerdefinisi]
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "add" => angkatOperasiBiner!(MicroBinOp::Add, false),
        "sub" => angkatOperasiBiner!(MicroBinOp::Sub, true),
        "and" => angkatOperasiBiner!(MicroBinOp::And, false),
        "or" => angkatOperasiBiner!(MicroBinOp::Or, false),
        "xor" => angkatOperasiBiner!(MicroBinOp::Xor, false),
        "paddb" | "paddw" | "paddd" | "paddq" | "vpaddb" | "vpaddw" | "vpaddd" | "vpaddq" => {
            if operands.len() >= 2 {
                let op1_vec = operands.iter().map(|op| petakanOperandKeMicroOperandX86(op, cs)).collect();
                let op2_vec = Vec::new(); 
                if let X86OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let op_type = match mnem.chars().last().unwrap() {
                        'b' => MicroBinOp::VecAddI8,
                        'w' => MicroBinOp::VecAddI16,
                        'd' => MicroBinOp::VecAddI32,
                        'q' => MicroBinOp::VecAddI64,
                        _ => MicroBinOp::VecAddI32,
                    };
                    vec![MicroInstruction::InstruksiVektor {
                        op: op_type,
                        tujuan: dest_var,
                        elemen_size: 0, 
                        operand_1: op1_vec,
                        operand_2: op2_vec,
                    }]
                } else {
                    vec![MicroInstruction::TidakTerdefinisi]
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "pxor" | "vpxor" => {
             if let X86OperandType::Reg(reg_id) = operands[0].op_type {
                 let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                 let op1_vec = operands.iter().map(|op| petakanOperandKeMicroOperandX86(op, cs)).collect();
                 vec![MicroInstruction::InstruksiVektor {
                        op: MicroBinOp::VecXor,
                        tujuan: dest_var,
                        elemen_size: 128,
                        operand_1: op1_vec,
                        operand_2: Vec::new(),
                 }]
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        }
        "cmp" => {
            if operands.len() == 2 {
                let op1 = petakanOperandKeEkspresiSsaX86(&operands[0], cs);
                let op2 = petakanOperandKeEkspresiSsaX86(&operands[1], cs);
                let res_expr = MicroExpr::OperasiBiner(MicroBinOp::Sub, Box::new(op1.clone()), Box::new(op2.clone()));
                let mut instrs = Vec::new();
                generate_eflags_update(&mut instrs, res_expr, op1, op2, true);
                instrs
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "test" => {
             if operands.len() == 2 {
                let op1 = petakanOperandKeEkspresiSsaX86(&operands[0], cs);
                let op2 = petakanOperandKeEkspresiSsaX86(&operands[1], cs);
                let res_expr = MicroExpr::OperasiBiner(MicroBinOp::And, Box::new(op1.clone()), Box::new(op2.clone()));
                let mut instrs = Vec::new();
                instrs.push(MicroInstruction::UpdateFlag(
                    "ZF".to_string(),
                    MicroExpr::OperasiUnary(MicroUnOp::ExtractZeroFlag, Box::new(res_expr.clone())),
                ));
                instrs.push(MicroInstruction::UpdateFlag(
                    "SF".to_string(),
                    MicroExpr::OperasiUnary(MicroUnOp::ExtractSignFlag, Box::new(res_expr.clone())),
                ));
                instrs.push(MicroInstruction::UpdateFlag("CF".to_string(), MicroExpr::Operand(MicroOperand::Konstanta(0))));
                instrs.push(MicroInstruction::UpdateFlag("OF".to_string(), MicroExpr::Operand(MicroOperand::Konstanta(0))));
                instrs
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "jmp" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Lompat(petakanOperandKeEkspresiSsaX86(
                    &operands[0],
                    cs,
                ))]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "je" | "jz" => {
             let cond = MicroExpr::Operand(MicroOperand::Flag("ZF".to_string()));
             let target = petakanOperandKeEkspresiSsaX86(&operands[0], cs);
             vec![MicroInstruction::LompatKondisi(cond, target)]
        }
        "jne" | "jnz" => {
             let cond = MicroExpr::OperasiUnary(MicroUnOp::Not, Box::new(MicroExpr::Operand(MicroOperand::Flag("ZF".to_string()))));
             let target = petakanOperandKeEkspresiSsaX86(&operands[0], cs);
             vec![MicroInstruction::LompatKondisi(cond, target)]
        }
        "call" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Panggil(petakanOperandKeEkspresiSsaX86(
                    &operands[0],
                    cs,
                ))]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "ret" | "retn" => vec![MicroInstruction::Kembali],
        "nop" | "pause" => vec![MicroInstruction::Nop],
        "syscall" | "sysenter" | "int" => vec![MicroInstruction::Syscall],
        "mfence" | "lfence" | "sfence" => vec![MicroInstruction::MemoryFence],
        _ => vec![MicroInstruction::TidakTerdefinisi],
    }
}

#[allow(non_snake_case)]
pub fn petakanOperandKeEkspresiSsaArm(op: &ArmOperand, cs: &Capstone) -> MicroExpr {
    match op.op_type {
        ArmOperandType::Reg(reg_id) => {
            let var = buatSsaVariabelDariRegId(reg_id, cs);
            MicroExpr::Operand(MicroOperand::SsaVar(var))
        }
        ArmOperandType::Imm(imm_val) => {
            MicroExpr::Operand(MicroOperand::Konstanta(imm_val as u64))
        }
        _ => MicroExpr::Operand(MicroOperand::Konstanta(0)),
    }
}

#[allow(non_snake_case)]
pub fn angkatSsaArm(
    _insn: &capstone::Insn,
    _detail: &ArmInsnDetail,
    _cs: &Capstone,
) -> Vec<MicroInstruction> {
    vec![MicroInstruction::TidakTerdefinisi]
}

#[allow(non_snake_case)]
pub fn petakanAlamatMemoriAarch64(mem_op: &Arm64OpMem, cs: &Capstone) -> MicroExpr {
    let mut expr_opt: Option<Box<MicroExpr>> = None;
    if mem_op.base().0 != 0 {
        let base_var = buatSsaVariabelDariRegId(mem_op.base(), cs);
        expr_opt = Some(Box::new(MicroExpr::Operand(MicroOperand::SsaVar(
            base_var,
        ))));
    }
    if mem_op.index().0 != 0 {
        let index_var = buatSsaVariabelDariRegId(mem_op.index(), cs);
        let index_expr = Box::new(MicroExpr::Operand(MicroOperand::SsaVar(index_var)));
        if let Some(base_expr) = expr_opt {
            expr_opt = Some(Box::new(MicroExpr::OperasiBiner(
                MicroBinOp::Add,
                base_expr,
                index_expr,
            )));
        } else {
            expr_opt = Some(index_expr);
        }
    }
    if mem_op.disp() != 0 {
        let disp_expr = Box::new(MicroExpr::Operand(MicroOperand::Konstanta(
            mem_op.disp() as u64,
        )));
        if let Some(base_expr) = expr_opt {
            expr_opt = Some(Box::new(MicroExpr::OperasiBiner(
                MicroBinOp::Add,
                base_expr,
                disp_expr,
            )));
        } else {
            expr_opt = Some(disp_expr);
        }
    }
    *expr_opt.unwrap_or(Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))))
}

#[allow(non_snake_case)]
pub fn petakanOperandKeEkspresiSsaAarch64(
    op: &Arm64Operand,
    cs: &Capstone,
) -> MicroExpr {
    match op.op_type {
        Arm64OperandType::Reg(reg_id) => {
            let var = buatSsaVariabelDariRegId(reg_id, cs);
            MicroExpr::Operand(MicroOperand::SsaVar(var))
        }
        Arm64OperandType::Imm(imm_val) => {
            MicroExpr::Operand(MicroOperand::Konstanta(imm_val as u64))
        }
        Arm64OperandType::Mem(mem_op) => {
            let addr_expr = petakanAlamatMemoriAarch64(&mem_op, cs);
            MicroExpr::MuatMemori(Box::new(addr_expr))
        }
        _ => MicroExpr::Operand(MicroOperand::Konstanta(0)),
    }
}

#[allow(non_snake_case)]
fn petakanOperandKeMicroOperandAarch64(op: &Arm64Operand, cs: &Capstone) -> MicroOperand {
     match op.op_type {
        Arm64OperandType::Reg(reg_id) => {
             let var = buatSsaVariabelDariRegId(reg_id, cs);
             MicroOperand::SsaVar(var)
        },
        Arm64OperandType::Imm(val) => MicroOperand::Konstanta(val as u64),
        _ => MicroOperand::Konstanta(0),
    }
}

#[allow(non_snake_case)]
pub fn angkatSsaAarch64(
    insn: &capstone::Insn,
    detail: &Arm64InsnDetail,
    cs: &Capstone,
) -> Vec<MicroInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<Arm64Operand> = detail.operands().collect();
    match mnem {
        "mov" | "fmov" => {
            if operands.len() == 2 {
                if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                    vec![MicroInstruction::Assign(dest_var, src_expr)]
                } else {
                    vec![MicroInstruction::TidakTerdefinisi]
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "add" | "fadd" => {
            if operands.len() == 3 {
                if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                    let src2_expr = petakanOperandKeEkspresiSsaAarch64(&operands[2], cs);
                    let op = if mnem == "fadd" { MicroBinOp::TambahFloat } else { MicroBinOp::Add };
                    vec![MicroInstruction::Assign(
                        dest_var,
                        MicroExpr::OperasiBiner(
                            op,
                            Box::new(src1_expr),
                            Box::new(src2_expr),
                        ),
                    )]
                } else {
                     if operands.len() == 3 {
                        let mut op_vec = Vec::new();
                        for op in &operands {
                            op_vec.push(petakanOperandKeMicroOperandAarch64(op, cs));
                        }
                         if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                             let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                             vec![MicroInstruction::InstruksiVektor {
                                op: MicroBinOp::VecAddI64,
                                tujuan: dest_var,
                                elemen_size: 64,
                                operand_1: op_vec,
                                operand_2: Vec::new()
                             }]
                         } else {
                             vec![MicroInstruction::TidakTerdefinisi]
                         }
                     } else {
                         vec![MicroInstruction::TidakTerdefinisi]
                     }
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "ldxr" => {
             if operands.len() == 2 {
                 if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                     let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                     let addr_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                     vec![
                         MicroInstruction::MemoryFence,
                         MicroInstruction::Assign(dest_var, MicroExpr::MuatMemori(Box::new(addr_expr)))
                     ]
                 } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "stxr" => {
             if operands.len() == 3 {
                 let addr_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                 let val_expr = petakanOperandKeEkspresiSsaAarch64(&operands[0], cs);
                 if let Arm64OperandType::Reg(status_reg) = operands[2].op_type {
                     let status_var = buatSsaVariabelDariRegId(status_reg, cs);
                     vec![
                         MicroInstruction::AtomicRMW {
                             op: MicroAtomicOp::Xchg,
                             alamat: addr_expr,
                             nilai: val_expr,
                             tujuan_lama: Some(status_var)
                         },
                         MicroInstruction::MemoryFence
                     ]
                 } else {
                      vec![MicroInstruction::TidakTerdefinisi]
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        }
        "dmb" | "dsb" | "isb" => vec![MicroInstruction::MemoryFence],
        "ret" => vec![MicroInstruction::Kembali],
        _ => vec![MicroInstruction::TidakTerdefinisi],
    }
}

#[allow(non_snake_case)]
pub fn petakanAlamatMemoriMips(mem_op: &MipsOpMem, cs: &Capstone) -> MicroExpr {
    let mut expr_opt: Option<Box<MicroExpr>> = None;
    if mem_op.base().0 != 0 {
        let base_var = buatSsaVariabelDariRegId(mem_op.base(), cs);
        expr_opt = Some(Box::new(MicroExpr::Operand(MicroOperand::SsaVar(base_var))));
    }
    if mem_op.disp() != 0 {
        let disp_expr = Box::new(MicroExpr::Operand(MicroOperand::Konstanta(mem_op.disp() as u64)));
        if let Some(base_expr) = expr_opt {
             expr_opt = Some(Box::new(MicroExpr::OperasiBiner(
                MicroBinOp::Add,
                base_expr,
                disp_expr,
            )));
        } else {
            expr_opt = Some(disp_expr);
        }
    }
    *expr_opt.unwrap_or(Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))))
}

#[allow(non_snake_case)]
pub fn petakanOperandKeEkspresiSsaMips(op: &MipsOperand, cs: &Capstone) -> MicroExpr {
    match op {
        MipsOperand::Reg(reg_id) => {
            let var = buatSsaVariabelDariRegId(*reg_id, cs);
            MicroExpr::Operand(MicroOperand::SsaVar(var))
        }
        MipsOperand::Imm(val) => {
            MicroExpr::Operand(MicroOperand::Konstanta(*val as u64))
        }
        MipsOperand::Mem(mem) => {
             let addr_expr = petakanAlamatMemoriMips(mem, cs);
             MicroExpr::MuatMemori(Box::new(addr_expr))
        }
        _ => MicroExpr::Operand(MicroOperand::Konstanta(0))
    }
}

#[allow(non_snake_case)]
pub fn angkatSsaMips(
    insn: &capstone::Insn,
    detail: &MipsInsnDetail,
    cs: &Capstone
) -> Vec<MicroInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<MipsOperand> = detail.operands().collect();
    match mnem {
        "lw" | "lb" | "lbu" | "lh" | "lhu" | "ld" => {
            if operands.len() == 2 {
                 if let MipsOperand::Reg(reg_id) = operands[0] {
                     let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                     let src_expr = petakanOperandKeEkspresiSsaMips(&operands[1], cs);
                     vec![MicroInstruction::Assign(dest_var, src_expr)]
                 } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                 }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        },
        "sw" | "sb" | "sh" | "sd" => {
             if operands.len() == 2 {
                 let src_expr = petakanOperandKeEkspresiSsaMips(&operands[0], cs);
                 if let MipsOperand::Mem(mem) = &operands[1] {
                      let addr_expr = petakanAlamatMemoriMips(mem, cs);
                      vec![MicroInstruction::SimpanMemori(addr_expr, src_expr)]
                 } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "move" | "li" | "la" => {
             if operands.len() == 2 {
                 if let MipsOperand::Reg(reg_id) = operands[0] {
                     let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                     let src_expr = petakanOperandKeEkspresiSsaMips(&operands[1], cs);
                     vec![MicroInstruction::Assign(dest_var, src_expr)]
                 } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "add" | "addu" | "dadd" | "daddu" | "addi" | "addiu" => {
             if operands.len() == 3 {
                if let MipsOperand::Reg(reg_id) = operands[0] {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1 = petakanOperandKeEkspresiSsaMips(&operands[1], cs);
                    let src2 = petakanOperandKeEkspresiSsaMips(&operands[2], cs);
                    vec![MicroInstruction::Assign(
                        dest_var,
                        MicroExpr::OperasiBiner(MicroBinOp::Add, Box::new(src1), Box::new(src2))
                    )]
                } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "sub" | "subu" | "dsub" | "dsubu" => {
             if operands.len() == 3 {
                if let MipsOperand::Reg(reg_id) = operands[0] {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1 = petakanOperandKeEkspresiSsaMips(&operands[1], cs);
                    let src2 = petakanOperandKeEkspresiSsaMips(&operands[2], cs);
                    vec![MicroInstruction::Assign(
                        dest_var,
                        MicroExpr::OperasiBiner(MicroBinOp::Sub, Box::new(src1), Box::new(src2))
                    )]
                } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "j" | "b" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Lompat(petakanOperandKeEkspresiSsaMips(&operands[0], cs))]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        },
        "jal" | "jalr" => {
            if operands.len() >= 1 {
                 let target = if operands.len() == 2 { &operands[1] } else { &operands[0] };
                 vec![MicroInstruction::Panggil(petakanOperandKeEkspresiSsaMips(target, cs))]
            } else {
                 vec![MicroInstruction::TidakTerdefinisi]
            }
        },
        "jr" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Kembali]
            } else {
                 vec![MicroInstruction::Lompat(petakanOperandKeEkspresiSsaMips(&operands[0], cs))]
            }
        },
        "syscall" => vec![MicroInstruction::Syscall],
        "nop" => vec![MicroInstruction::Nop],
        "sync" => vec![MicroInstruction::MemoryFence],
        _ => vec![MicroInstruction::TidakTerdefinisi],
    }
}

#[allow(non_snake_case)]
pub fn petakanAlamatMemoriRiscv(mem_op: &RiscVOpMem, cs: &Capstone) -> MicroExpr {
     let mut expr_opt: Option<Box<MicroExpr>> = None;
    if mem_op.base().0 != 0 {
        let base_var = buatSsaVariabelDariRegId(mem_op.base(), cs);
        expr_opt = Some(Box::new(MicroExpr::Operand(MicroOperand::SsaVar(base_var))));
    }
    if mem_op.disp() != 0 {
        let disp_expr = Box::new(MicroExpr::Operand(MicroOperand::Konstanta(mem_op.disp() as u64)));
        if let Some(base_expr) = expr_opt {
             expr_opt = Some(Box::new(MicroExpr::OperasiBiner(
                MicroBinOp::Add,
                base_expr,
                disp_expr,
            )));
        } else {
            expr_opt = Some(disp_expr);
        }
    }
    *expr_opt.unwrap_or(Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))))
}

#[allow(non_snake_case)]
pub fn petakanOperandKeEkspresiSsaRiscv(op: &RiscVOperand, cs: &Capstone) -> MicroExpr {
    match op {
        RiscVOperand::Reg(reg_id) => {
             let var = buatSsaVariabelDariRegId(*reg_id, cs);
             MicroExpr::Operand(MicroOperand::SsaVar(var))
        },
        RiscVOperand::Imm(val) => {
             MicroExpr::Operand(MicroOperand::Konstanta(*val as u64))
        },
        RiscVOperand::Mem(mem) => {
             let addr = petakanAlamatMemoriRiscv(mem, cs);
             MicroExpr::MuatMemori(Box::new(addr))
        },
        _ => MicroExpr::Operand(MicroOperand::Konstanta(0))
    }
}

#[allow(non_snake_case)]
pub fn angkatSsaRiscv(
    insn: &capstone::Insn,
    detail: &RiscVInsnDetail,
    cs: &Capstone
) -> Vec<MicroInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<RiscVOperand> = detail.operands().collect();
    match mnem {
        "lb" | "lh" | "lw" | "ld" | "lbu" | "lhu" | "lwu" => {
            if operands.len() == 2 {
                if let RiscVOperand::Reg(reg_id) = operands[0] {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src_expr = petakanOperandKeEkspresiSsaRiscv(&operands[1], cs);
                    vec![MicroInstruction::Assign(dest_var, src_expr)]
                } else {
                    vec![MicroInstruction::TidakTerdefinisi]
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        },
        "sb" | "sh" | "sw" | "sd" => {
             if operands.len() == 2 {
                 let src_expr = petakanOperandKeEkspresiSsaRiscv(&operands[0], cs);
                 if let RiscVOperand::Mem(mem) = &operands[1] {
                     let addr = petakanAlamatMemoriRiscv(mem, cs);
                     vec![MicroInstruction::SimpanMemori(addr, src_expr)]
                 } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "add" | "addw" | "addi" | "addiw" => {
             if operands.len() == 3 {
                 if let RiscVOperand::Reg(reg_id) = operands[0] {
                     let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                     let src1 = petakanOperandKeEkspresiSsaRiscv(&operands[1], cs);
                     let src2 = petakanOperandKeEkspresiSsaRiscv(&operands[2], cs);
                     vec![MicroInstruction::Assign(dest_var, MicroExpr::OperasiBiner(MicroBinOp::Add, Box::new(src1), Box::new(src2)))]
                 } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "fence" | "fence.i" => vec![MicroInstruction::MemoryFence],
        "jal" => {
            if operands.len() >= 1 {
                let target = operands.last().unwrap();
                vec![MicroInstruction::Panggil(petakanOperandKeEkspresiSsaRiscv(target, cs))]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        },
        "ecall" | "ebreak" => vec![MicroInstruction::Syscall],
        "ret" => vec![MicroInstruction::Kembali],
        _ => vec![MicroInstruction::TidakTerdefinisi],
    }
}

pub fn angkat_blok_instruksi(
    bytes: &[u8],
    va: u64,
    arch: ArsitekturDisasm,
) -> Result<(usize, Vec<MicroInstruction>), ReToolsError> {
    let cs = buat_instance_capstone_by_arch(arch)?;
    let insns = cs
        .disasm_count(bytes, va, 1)
        .map_err(ReToolsError::from)?;
    let insn = insns
        .first()
        .ok_or(ReToolsError::Generic("Disasm failed".to_string()))?;
    let insn_detail = cs.insn_detail(insn)?;
    let detail = insn_detail.arch_detail();
    let ir_instrs = angkat_dari_detail(insn, &detail, &cs, arch);
    Ok((insn.bytes().len(), ir_instrs))
}

pub fn angkat_dari_detail(
    insn: &capstone::Insn,
    detail: &ArchDetail,
    cs: &Capstone,
    arch: ArsitekturDisasm,
) -> Vec<MicroInstruction> {
    match arch {
        ArsitekturDisasm::ARCH_X86_64 | ArsitekturDisasm::ARCH_X86_32 => {
            angkatSsaX86(insn, detail.x86().unwrap(), cs, arch)
        }
        ArsitekturDisasm::ARCH_ARM_32 => angkatSsaArm(insn, detail.arm().unwrap(), cs),
        ArsitekturDisasm::ARCH_ARM_64 => angkatSsaAarch64(insn, detail.arm64().unwrap(), cs),
        ArsitekturDisasm::ARCH_RISCV_32 | ArsitekturDisasm::ARCH_RISCV_64 => {
             if let Some(riscv_detail) = detail.riscv() {
                angkatSsaRiscv(insn, riscv_detail, cs)
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        }
        ArsitekturDisasm::ARCH_MIPS_32 | ArsitekturDisasm::ARCH_MIPS_64 => {
             if let Some(mips_detail) = detail.mips() {
                 angkatSsaMips(insn, mips_detail, cs)
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        }
        _ => vec![MicroInstruction::TidakTerdefinisi],
    }
}