//! Author: [Seclususs](https://github.com/seclususs)

use super::instruction::{
    MicroAtomicOp, MicroBinOp, MicroExpr, MicroInstruction, MicroOperand, MicroUnOp, SsaVariabel,
};
use crate::error::ReToolsError;
use crate::logic::static_analysis::disasm::{create_instance_capstone_by_arch, ArsitekturDisasm};
use capstone::arch::{
    arm::{ArmInsnDetail, ArmOperand, ArmOperandType},
    arm64::{Arm64InsnDetail, Arm64OpMem, Arm64Operand, Arm64OperandType},
    mips::{MipsInsnDetail, MipsOpMem, MipsOperand},
    riscv::{RiscVInsnDetail, RiscVOpMem, RiscVOperand},
    x86::{X86InsnDetail, X86OpMem, X86Operand, X86OperandType},
    ArchDetail,
};
use capstone::prelude::*;

pub fn create_var_ssa(nama_reg: String) -> SsaVariabel {
    SsaVariabel {
        id_reg: nama_reg,
        versi: 0,
    }
}

pub fn create_var_ssa_from_reg(id_reg: RegId, cs: &Capstone) -> SsaVariabel {
    let nama_reg = cs.reg_name(id_reg).unwrap_or("unknown_reg".to_string());
    create_var_ssa(nama_reg)
}

pub fn map_addr_mem_x86(op_mem: &X86OpMem, cs: &Capstone) -> MicroExpr {
    let mut opt_expr: Option<Box<MicroExpr>> = None;
    if op_mem.base().0 != 0 {
        let var_basis = create_var_ssa_from_reg(op_mem.base(), cs);
        opt_expr = Some(Box::new(MicroExpr::Operand(MicroOperand::SsaVar(
            var_basis,
        ))));
    }
    if op_mem.index().0 != 0 {
        let var_indeks = create_var_ssa_from_reg(op_mem.index(), cs);
        let expr_indeks = Box::new(MicroExpr::Operand(MicroOperand::SsaVar(var_indeks)));
        let expr_skala = Box::new(MicroExpr::Operand(MicroOperand::Konstanta(
            op_mem.scale() as u64,
        )));
        let indeks_skala = Box::new(MicroExpr::BinaryOp(
            MicroBinOp::Mul,
            expr_indeks,
            expr_skala,
        ));
        if let Some(expr_basis) = opt_expr {
            opt_expr = Some(Box::new(MicroExpr::BinaryOp(
                MicroBinOp::Add,
                expr_basis,
                indeks_skala,
            )));
        } else {
            opt_expr = Some(indeks_skala);
        }
    }
    if op_mem.disp() != 0 {
        let expr_disp = Box::new(MicroExpr::Operand(MicroOperand::Konstanta(
            op_mem.disp() as u64,
        )));
        if let Some(expr_basis) = opt_expr {
            opt_expr = Some(Box::new(MicroExpr::BinaryOp(
                MicroBinOp::Add,
                expr_basis,
                expr_disp,
            )));
        } else {
            opt_expr = Some(expr_disp);
        }
    }
    *opt_expr.unwrap_or(Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))))
}

pub fn map_op_to_expr_ssa_x86(op: &X86Operand, cs: &Capstone) -> MicroExpr {
    match op.op_type {
        X86OperandType::Reg(id_reg) => {
            let var = create_var_ssa_from_reg(id_reg, cs);
            MicroExpr::Operand(MicroOperand::SsaVar(var))
        }
        X86OperandType::Imm(val_imm) => {
            MicroExpr::Operand(MicroOperand::Konstanta(val_imm as u64))
        }
        X86OperandType::Mem(op_mem) => {
            let expr_addr = map_addr_mem_x86(&op_mem, cs);
            MicroExpr::LoadMemori(Box::new(expr_addr))
        }
        _ => MicroExpr::Operand(MicroOperand::Konstanta(0)),
    }
}

fn map_op_to_micro_op_x86(op: &X86Operand, cs: &Capstone) -> MicroOperand {
    match op.op_type {
        X86OperandType::Reg(id_reg) => {
            let var = create_var_ssa_from_reg(id_reg, cs);
            MicroOperand::SsaVar(var)
        }
        X86OperandType::Imm(val) => MicroOperand::Konstanta(val as u64),
        _ => MicroOperand::Konstanta(0),
    }
}

fn generate_eflags_update(
    list_instr: &mut Vec<MicroInstruction>,
    expr_hasil: MicroExpr,
    expr_op1: MicroExpr,
    expr_op2: MicroExpr,
    is_sub: bool,
) {
    let box_hasil = Box::new(expr_hasil.clone());
    let box_op1 = Box::new(expr_op1);
    let box_op2 = Box::new(expr_op2);
    list_instr.push(MicroInstruction::UpdateFlag(
        "ZF".to_string(),
        MicroExpr::UnaryOp(MicroUnOp::ExtractZeroFlag, box_hasil.clone()),
    ));
    list_instr.push(MicroInstruction::UpdateFlag(
        "SF".to_string(),
        MicroExpr::UnaryOp(MicroUnOp::ExtractSignFlag, box_hasil.clone()),
    ));
    let overflow_op = if is_sub {
        MicroExpr::BinaryOp(MicroBinOp::Sub, box_op1.clone(), box_op2.clone()) 
    } else {
        MicroExpr::BinaryOp(MicroBinOp::Add, box_op1.clone(), box_op2.clone())
    };
    list_instr.push(MicroInstruction::UpdateFlag(
        "OF".to_string(),
        MicroExpr::UnaryOp(MicroUnOp::ExtractOverflowFlag, Box::new(overflow_op)),
    ));
    let expr_carry = if is_sub {
        MicroExpr::Compare(box_op1, box_op2)
    } else {
        *box_hasil
    };
     list_instr.push(MicroInstruction::UpdateFlag(
        "CF".to_string(),
        MicroExpr::UnaryOp(MicroUnOp::ExtractCarryFlag, Box::new(expr_carry)),
    ));
}

pub fn lift_ssa_x86(
    insn: &capstone::Insn,
    detail: &X86InsnDetail,
    cs: &Capstone,
    arch: ArsitekturDisasm,
) -> Vec<MicroInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<X86Operand> = detail.operands().collect();
    let has_lock_prefix = detail.prefix().contains(&0xF0);
    macro_rules! lift_op_biner {
        ($op:expr, $is_sub:expr) => {{
            let mut list_instr = Vec::new();
            if operands.len() == 2 {
                let op_tujuan = &operands[0];
                let expr_sumber = map_op_to_expr_ssa_x86(&operands[1], cs);
                if has_lock_prefix {
                     match op_tujuan.op_type {
                         X86OperandType::Mem(op_mem) => {
                             let expr_addr = map_addr_mem_x86(&op_mem, cs);
                             let atomic_op = match $op {
                                 MicroBinOp::Add => MicroAtomicOp::Add,
                                 MicroBinOp::Sub => MicroAtomicOp::Sub,
                                 MicroBinOp::And => MicroAtomicOp::And,
                                 MicroBinOp::Or => MicroAtomicOp::Or,
                                 MicroBinOp::Xor => MicroAtomicOp::Xor,
                                 _ => MicroAtomicOp::Add,
                             };
                             list_instr.push(MicroInstruction::AtomicRMW {
                                 op: atomic_op,
                                 addr_mem: expr_addr,
                                 nilai: expr_sumber,
                                 tujuan_lama: None,
                             });
                         },
                         _ => list_instr.push(MicroInstruction::Undefined),
                     }
                } else {
                    match op_tujuan.op_type {
                        X86OperandType::Reg(id_reg) => {
                            let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                            let expr_tujuan = MicroExpr::Operand(MicroOperand::SsaVar(var_tujuan.clone()));
                            let expr_hasil = MicroExpr::BinaryOp($op, Box::new(expr_tujuan.clone()), Box::new(expr_sumber.clone()));
                            list_instr.push(MicroInstruction::Assign(var_tujuan.clone(), expr_hasil.clone()));
                            generate_eflags_update(&mut list_instr, expr_hasil, expr_tujuan, expr_sumber, $is_sub);
                        }
                        X86OperandType::Mem(op_mem) => {
                            let expr_addr = map_addr_mem_x86(&op_mem, cs);
                            let expr_tujuan = MicroExpr::LoadMemori(Box::new(expr_addr.clone()));
                            let expr_hasil = MicroExpr::BinaryOp($op, Box::new(expr_tujuan.clone()), Box::new(expr_sumber.clone()));
                            list_instr.push(MicroInstruction::StoreMemori(expr_addr, expr_hasil.clone()));
                            generate_eflags_update(&mut list_instr, expr_hasil, expr_tujuan, expr_sumber, $is_sub);
                        }
                        _ => list_instr.push(MicroInstruction::Undefined),
                    }
                }
            } else {
                list_instr.push(MicroInstruction::Undefined);
            }
            list_instr
        }};
    }
    match mnem {
        "mov" | "movsx" | "movzx" | "movabs" | "movaps" | "movups" | "movdqa" | "movdqu" => {
            if operands.len() == 2 {
                let op_tujuan = &operands[0];
                let expr_sumber = map_op_to_expr_ssa_x86(&operands[1], cs);
                match op_tujuan.op_type {
                    X86OperandType::Reg(id_reg) => {
                        let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                        vec![MicroInstruction::Assign(var_tujuan, expr_sumber)]
                    }
                    X86OperandType::Mem(op_mem) => {
                        let expr_addr = map_addr_mem_x86(&op_mem, cs);
                        vec![MicroInstruction::StoreMemori(expr_addr, expr_sumber)]
                    }
                    _ => vec![MicroInstruction::Undefined],
                }
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        "xchg" => {
             if operands.len() == 2 {
                 if has_lock_prefix {
                      let op_tujuan = &operands[0];
                      let expr_sumber = map_op_to_expr_ssa_x86(&operands[1], cs);
                      match op_tujuan.op_type {
                          X86OperandType::Mem(op_mem) => {
                               let expr_addr = map_addr_mem_x86(&op_mem, cs);
                               vec![MicroInstruction::AtomicRMW {
                                   op: MicroAtomicOp::Xchg,
                                   addr_mem: expr_addr,
                                   nilai: expr_sumber,
                                   tujuan_lama: None,
                               }]
                          },
                          _ => vec![MicroInstruction::Undefined] 
                      }
                 } else {
                     let op1 = map_op_to_expr_ssa_x86(&operands[0], cs);
                     let op2 = map_op_to_expr_ssa_x86(&operands[1], cs);
                     let mut list_instr = Vec::new();
                     if let X86OperandType::Reg(r1) = operands[0].op_type {
                         list_instr.push(MicroInstruction::Assign(create_var_ssa_from_reg(r1, cs), op2));
                     }
                     if let X86OperandType::Reg(r2) = operands[1].op_type {
                          list_instr.push(MicroInstruction::Assign(create_var_ssa_from_reg(r2, cs), op1));
                     }
                     list_instr
                 }
             } else {
                 vec![MicroInstruction::Undefined]
             }
        }
        "lea" => {
            if operands.len() == 2 {
                let op_tujuan = &operands[0];
                let op_sumber = &operands[1];
                if let X86OperandType::Reg(id_reg) = op_tujuan.op_type {
                    if let X86OperandType::Mem(op_mem) = op_sumber.op_type {
                        let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                        let expr_addr = map_addr_mem_x86(&op_mem, cs);
                        vec![MicroInstruction::Assign(var_tujuan, expr_addr)]
                    } else {
                        vec![MicroInstruction::Undefined]
                    }
                } else {
                    vec![MicroInstruction::Undefined]
                }
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        "push" => {
            if operands.len() == 1 {
                let (nama_reg_sp, sz_op) = match arch {
                    ArsitekturDisasm::ARCH_X86_64 => ("rsp".to_string(), 8u64),
                    _ => ("esp".to_string(), 4u64),
                };
                let reg_sp = create_var_ssa(nama_reg_sp);
                let expr_sumber = map_op_to_expr_ssa_x86(&operands[0], cs);
                let tmp1 = create_var_ssa("t_stack_push".to_string());
                let expr_sub = MicroExpr::BinaryOp(
                    MicroBinOp::Sub,
                    Box::new(MicroExpr::Operand(MicroOperand::SsaVar(reg_sp.clone()))),
                    Box::new(MicroExpr::Operand(MicroOperand::Konstanta(sz_op))),
                );
                let instr1 = MicroInstruction::Assign(tmp1.clone(), expr_sub);
                let instr2 = MicroInstruction::StoreMemori(
                    MicroExpr::Operand(MicroOperand::SsaVar(tmp1.clone())),
                    expr_sumber,
                );
                let instr3 = MicroInstruction::Assign(
                    reg_sp,
                    MicroExpr::Operand(MicroOperand::SsaVar(tmp1)),
                );
                vec![instr1, instr2, instr3]
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        "pop" => {
            if operands.len() == 1 {
                if let X86OperandType::Reg(id_reg) = operands[0].op_type {
                    let (nama_reg_sp, sz_op) = match arch {
                        ArsitekturDisasm::ARCH_X86_64 => ("rsp".to_string(), 8u64),
                        _ => ("esp".to_string(), 4u64),
                    };
                    let reg_sp = create_var_ssa(nama_reg_sp);
                    let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                    let tmp1 = create_var_ssa("t_stack_pop".to_string());
                    let expr_load = MicroExpr::LoadMemori(Box::new(MicroExpr::Operand(
                        MicroOperand::SsaVar(reg_sp.clone()),
                    )));
                    let instr1 = MicroInstruction::Assign(tmp1.clone(), expr_load);
                    let instr2 = MicroInstruction::Assign(
                        var_tujuan,
                        MicroExpr::Operand(MicroOperand::SsaVar(tmp1)),
                    );
                    let tmp2 = create_var_ssa("t_stack_adj".to_string());
                    let expr_add = MicroExpr::BinaryOp(
                        MicroBinOp::Add,
                        Box::new(MicroExpr::Operand(MicroOperand::SsaVar(reg_sp.clone()))),
                        Box::new(MicroExpr::Operand(MicroOperand::Konstanta(sz_op))),
                    );
                    let instr3 = MicroInstruction::Assign(tmp2.clone(), expr_add);
                    let instr4 = MicroInstruction::Assign(
                        reg_sp,
                        MicroExpr::Operand(MicroOperand::SsaVar(tmp2)),
                    );
                    vec![instr1, instr2, instr3, instr4]
                } else {
                    vec![MicroInstruction::Undefined]
                }
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        "add" => lift_op_biner!(MicroBinOp::Add, false),
        "sub" => lift_op_biner!(MicroBinOp::Sub, true),
        "and" => lift_op_biner!(MicroBinOp::And, false),
        "or" => lift_op_biner!(MicroBinOp::Or, false),
        "xor" => lift_op_biner!(MicroBinOp::Xor, false),
        "addps" | "addpd" | "paddb" | "paddw" | "paddd" | "paddq" | "vpaddb" | "vpaddw" | "vpaddd" | "vpaddq" => {
            if operands.len() >= 2 {
                let vec_op1 = operands.iter().map(|op| map_op_to_micro_op_x86(op, cs)).collect();
                let vec_op2 = Vec::new(); 
                if let X86OperandType::Reg(id_reg) = operands[0].op_type {
                    let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                    let tipe_op = if mnem.contains("ps") || mnem.contains("pd") {
                         MicroBinOp::TambahFloat
                    } else {
                         match mnem.chars().last().unwrap_or('d') {
                             'b' => MicroBinOp::VecAddI8,
                             'w' => MicroBinOp::VecAddI16,
                             'd' => MicroBinOp::VecAddI32,
                             'q' => MicroBinOp::VecAddI64,
                             _ => MicroBinOp::VecAddI32,
                         }
                    };
                    vec![MicroInstruction::VectorOp {
                        op: tipe_op,
                        tujuan: var_tujuan,
                        sz_elemen: 0, 
                        op_1: vec_op1,
                        op_2: vec_op2,
                    }]
                } else {
                    vec![MicroInstruction::Undefined]
                }
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        "pxor" | "vpxor" | "xorps" | "xorpd" => {
             if let X86OperandType::Reg(id_reg) = operands[0].op_type {
                 let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                 let vec_op1 = operands.iter().map(|op| map_op_to_micro_op_x86(op, cs)).collect();
                 vec![MicroInstruction::VectorOp {
                        op: MicroBinOp::VecXor,
                        tujuan: var_tujuan,
                        sz_elemen: 128,
                        op_1: vec_op1,
                        op_2: Vec::new(),
                 }]
             } else {
                 vec![MicroInstruction::Undefined]
             }
        }
        "cmp" => {
            if operands.len() == 2 {
                let op1 = map_op_to_expr_ssa_x86(&operands[0], cs);
                let op2 = map_op_to_expr_ssa_x86(&operands[1], cs);
                let expr_hasil = MicroExpr::BinaryOp(MicroBinOp::Sub, Box::new(op1.clone()), Box::new(op2.clone()));
                let mut list_instr = Vec::new();
                generate_eflags_update(&mut list_instr, expr_hasil, op1, op2, true);
                list_instr
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        "test" => {
             if operands.len() == 2 {
                let op1 = map_op_to_expr_ssa_x86(&operands[0], cs);
                let op2 = map_op_to_expr_ssa_x86(&operands[1], cs);
                let expr_hasil = MicroExpr::BinaryOp(MicroBinOp::And, Box::new(op1.clone()), Box::new(op2.clone()));
                let mut list_instr = Vec::new();
                list_instr.push(MicroInstruction::UpdateFlag(
                    "ZF".to_string(),
                    MicroExpr::UnaryOp(MicroUnOp::ExtractZeroFlag, Box::new(expr_hasil.clone())),
                ));
                list_instr.push(MicroInstruction::UpdateFlag(
                    "SF".to_string(),
                    MicroExpr::UnaryOp(MicroUnOp::ExtractSignFlag, Box::new(expr_hasil.clone())),
                ));
                list_instr.push(MicroInstruction::UpdateFlag("CF".to_string(), MicroExpr::Operand(MicroOperand::Konstanta(0))));
                list_instr.push(MicroInstruction::UpdateFlag("OF".to_string(), MicroExpr::Operand(MicroOperand::Konstanta(0))));
                list_instr
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        "jmp" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Jump(map_op_to_expr_ssa_x86(
                    &operands[0],
                    cs,
                ))]
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        "je" | "jz" => {
             let cond = MicroExpr::Operand(MicroOperand::Flag("ZF".to_string()));
             let target = map_op_to_expr_ssa_x86(&operands[0], cs);
             vec![MicroInstruction::JumpKondisi(cond, target)]
        }
        "jne" | "jnz" => {
             let cond = MicroExpr::UnaryOp(MicroUnOp::Not, Box::new(MicroExpr::Operand(MicroOperand::Flag("ZF".to_string()))));
             let target = map_op_to_expr_ssa_x86(&operands[0], cs);
             vec![MicroInstruction::JumpKondisi(cond, target)]
        }
        "call" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Call(map_op_to_expr_ssa_x86(
                    &operands[0],
                    cs,
                ))]
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        "ret" | "retn" => vec![MicroInstruction::Return],
        "nop" | "pause" => vec![MicroInstruction::Nop],
        "syscall" | "sysenter" | "int" => vec![MicroInstruction::Syscall],
        "mfence" | "lfence" | "sfence" => vec![MicroInstruction::MemoryFence],
        _ => vec![MicroInstruction::Undefined],
    }
}

pub fn map_op_to_expr_ssa_arm(op: &ArmOperand, cs: &Capstone) -> MicroExpr {
    match op.op_type {
        ArmOperandType::Reg(id_reg) => {
            let var = create_var_ssa_from_reg(id_reg, cs);
            MicroExpr::Operand(MicroOperand::SsaVar(var))
        }
        ArmOperandType::Imm(val_imm) => {
            MicroExpr::Operand(MicroOperand::Konstanta(val_imm as u64))
        }
        _ => MicroExpr::Operand(MicroOperand::Konstanta(0)),
    }
}

pub fn lift_ssa_arm(
    _insn: &capstone::Insn,
    _detail: &ArmInsnDetail,
    _cs: &Capstone,
) -> Vec<MicroInstruction> {
    vec![MicroInstruction::Undefined]
}

pub fn map_addr_mem_aarch64(op_mem: &Arm64OpMem, cs: &Capstone) -> MicroExpr {
    let mut opt_expr: Option<Box<MicroExpr>> = None;
    if op_mem.base().0 != 0 {
        let var_basis = create_var_ssa_from_reg(op_mem.base(), cs);
        opt_expr = Some(Box::new(MicroExpr::Operand(MicroOperand::SsaVar(
            var_basis,
        ))));
    }
    if op_mem.index().0 != 0 {
        let var_indeks = create_var_ssa_from_reg(op_mem.index(), cs);
        let expr_indeks = Box::new(MicroExpr::Operand(MicroOperand::SsaVar(var_indeks)));
        if let Some(expr_basis) = opt_expr {
            opt_expr = Some(Box::new(MicroExpr::BinaryOp(
                MicroBinOp::Add,
                expr_basis,
                expr_indeks,
            )));
        } else {
            opt_expr = Some(expr_indeks);
        }
    }
    if op_mem.disp() != 0 {
        let expr_disp = Box::new(MicroExpr::Operand(MicroOperand::Konstanta(
            op_mem.disp() as u64,
        )));
        if let Some(expr_basis) = opt_expr {
            opt_expr = Some(Box::new(MicroExpr::BinaryOp(
                MicroBinOp::Add,
                expr_basis,
                expr_disp,
            )));
        } else {
            opt_expr = Some(expr_disp);
        }
    }
    *opt_expr.unwrap_or(Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))))
}

pub fn map_op_to_expr_ssa_aarch64(
    op: &Arm64Operand,
    cs: &Capstone,
) -> MicroExpr {
    match op.op_type {
        Arm64OperandType::Reg(id_reg) => {
            let var = create_var_ssa_from_reg(id_reg, cs);
            MicroExpr::Operand(MicroOperand::SsaVar(var))
        }
        Arm64OperandType::Imm(val_imm) => {
            MicroExpr::Operand(MicroOperand::Konstanta(val_imm as u64))
        }
        Arm64OperandType::Mem(op_mem) => {
            let expr_addr = map_addr_mem_aarch64(&op_mem, cs);
            MicroExpr::LoadMemori(Box::new(expr_addr))
        }
        _ => MicroExpr::Operand(MicroOperand::Konstanta(0)),
    }
}

fn map_op_to_micro_op_aarch64(op: &Arm64Operand, cs: &Capstone) -> MicroOperand {
     match op.op_type {
        Arm64OperandType::Reg(id_reg) => {
             let var = create_var_ssa_from_reg(id_reg, cs);
             MicroOperand::SsaVar(var)
        },
        Arm64OperandType::Imm(val) => MicroOperand::Konstanta(val as u64),
        _ => MicroOperand::Konstanta(0),
    }
}

pub fn lift_ssa_aarch64(
    insn: &capstone::Insn,
    detail: &Arm64InsnDetail,
    cs: &Capstone,
) -> Vec<MicroInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<Arm64Operand> = detail.operands().collect();
    match mnem {
        "mov" | "fmov" | "ldr" | "ldur" => {
            if operands.len() >= 2 {
                if let Arm64OperandType::Reg(id_reg) = operands[0].op_type {
                    let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                    let expr_sumber = map_op_to_expr_ssa_aarch64(&operands[1], cs);
                    vec![MicroInstruction::Assign(var_tujuan, expr_sumber)]
                } else {
                    vec![MicroInstruction::Undefined]
                }
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        "str" | "stur" => {
             if operands.len() == 2 {
                let expr_sumber = map_op_to_expr_ssa_aarch64(&operands[0], cs);
                if let Arm64OperandType::Mem(op_mem) = operands[1].op_type {
                    let expr_addr = map_addr_mem_aarch64(&op_mem, cs);
                    vec![MicroInstruction::StoreMemori(expr_addr, expr_sumber)]
                } else {
                    vec![MicroInstruction::Undefined]
                }
             } else {
                 vec![MicroInstruction::Undefined]
             }
        }
        "add" | "sub" | "fadd" | "fsub" | "fmul" | "fdiv" => {
            if operands.len() >= 2 {
                if let Arm64OperandType::Reg(id_reg) = operands[0].op_type {
                    let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                    let src1_expr = if operands.len() == 2 {
                         MicroExpr::Operand(MicroOperand::SsaVar(var_tujuan.clone()))
                    } else {
                        map_op_to_expr_ssa_aarch64(&operands[1], cs)
                    };
                    let src2_expr = if operands.len() == 2 {
                        map_op_to_expr_ssa_aarch64(&operands[1], cs)
                    } else {
                        map_op_to_expr_ssa_aarch64(&operands[2], cs)
                    };
                    let op = match mnem {
                        "fadd" => MicroBinOp::TambahFloat,
                        "fsub" => MicroBinOp::KurangFloat,
                        "fmul" => MicroBinOp::KaliFloat,
                        "fdiv" => MicroBinOp::BagiFloat,
                        "sub" => MicroBinOp::Sub,
                        _ => MicroBinOp::Add,
                    };
                    vec![MicroInstruction::Assign(
                        var_tujuan,
                        MicroExpr::BinaryOp(
                            op,
                            Box::new(src1_expr),
                            Box::new(src2_expr),
                        ),
                    )]
                } else {
                     if operands.len() == 3 {
                        let mut vec_op = Vec::new();
                        for op in &operands {
                            vec_op.push(map_op_to_micro_op_aarch64(op, cs));
                        }
                         if let Arm64OperandType::Reg(id_reg) = operands[0].op_type {
                             let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                             vec![MicroInstruction::VectorOp {
                                op: MicroBinOp::VecAddI64,
                                tujuan: var_tujuan,
                                sz_elemen: 64,
                                op_1: vec_op,
                                op_2: Vec::new()
                             }]
                         } else {
                             vec![MicroInstruction::Undefined]
                         }
                     } else {
                         vec![MicroInstruction::Undefined]
                     }
                }
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        "and" | "orr" | "eor" | "bic" => {
            if operands.len() >= 2 {
                if let Arm64OperandType::Reg(id_reg) = operands[0].op_type {
                    let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                    let src1_expr = if operands.len() == 2 {
                        MicroExpr::Operand(MicroOperand::SsaVar(var_tujuan.clone()))
                    } else {
                        map_op_to_expr_ssa_aarch64(&operands[1], cs)
                    };
                    let src2_expr = if operands.len() == 2 {
                        map_op_to_expr_ssa_aarch64(&operands[1], cs)
                    } else {
                        map_op_to_expr_ssa_aarch64(&operands[2], cs)
                    };
                    let op = match mnem {
                        "and" => MicroBinOp::And,
                        "orr" => MicroBinOp::Or,
                        "eor" => MicroBinOp::Xor,
                        "bic" => MicroBinOp::And, 
                        _ => MicroBinOp::And,
                    };
                    vec![MicroInstruction::Assign(
                         var_tujuan,
                         MicroExpr::BinaryOp(op, Box::new(src1_expr), Box::new(src2_expr))
                    )]
                } else {
                     vec![MicroInstruction::Undefined]
                }
            } else {
                 vec![MicroInstruction::Undefined]
            }
        }
        "cmp" | "fcmp" => {
             if operands.len() == 2 {
                let op1 = map_op_to_expr_ssa_aarch64(&operands[0], cs);
                let op2 = map_op_to_expr_ssa_aarch64(&operands[1], cs);
                let expr_hasil = MicroExpr::BinaryOp(MicroBinOp::Sub, Box::new(op1.clone()), Box::new(op2.clone()));
                let mut list_instr = Vec::new();
                list_instr.push(MicroInstruction::UpdateFlag("ZF".to_string(), MicroExpr::UnaryOp(MicroUnOp::ExtractZeroFlag, Box::new(expr_hasil.clone()))));
                list_instr.push(MicroInstruction::UpdateFlag("NF".to_string(), MicroExpr::UnaryOp(MicroUnOp::ExtractSignFlag, Box::new(expr_hasil.clone()))));
                list_instr
             } else {
                 vec![MicroInstruction::Undefined]
             }
        }
        "b" => {
             if operands.len() == 1 {
                 vec![MicroInstruction::Jump(map_op_to_expr_ssa_aarch64(&operands[0], cs))]
             } else {
                 vec![MicroInstruction::Undefined]
             }
        }
        "b.eq" | "b.ne" | "b.lt" | "b.le" | "b.gt" | "b.ge" => {
             let cond_flag = match mnem {
                 "b.eq" => MicroExpr::Operand(MicroOperand::Flag("ZF".to_string())),
                 "b.ne" => MicroExpr::UnaryOp(MicroUnOp::Not, Box::new(MicroExpr::Operand(MicroOperand::Flag("ZF".to_string())))),
                 _ => MicroExpr::Operand(MicroOperand::Konstanta(1)), 
             };
             if operands.len() == 1 {
                  let target = map_op_to_expr_ssa_aarch64(&operands[0], cs);
                  vec![MicroInstruction::JumpKondisi(cond_flag, target)]
             } else {
                 vec![MicroInstruction::Undefined]
             }
        }
        "bl" => {
             if operands.len() == 1 {
                 vec![MicroInstruction::Call(map_op_to_expr_ssa_aarch64(&operands[0], cs))]
             } else {
                 vec![MicroInstruction::Undefined]
             }
        }
        "br" | "blr" => {
             if operands.len() == 1 {
                 let target = map_op_to_expr_ssa_aarch64(&operands[0], cs);
                 if mnem == "blr" {
                      vec![MicroInstruction::Call(target)]
                 } else {
                      vec![MicroInstruction::Jump(target)]
                 }
             } else {
                 vec![MicroInstruction::Undefined]
             }
        }
        "ldxr" => {
             if operands.len() == 2 {
                 if let Arm64OperandType::Reg(id_reg) = operands[0].op_type {
                     let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                     let expr_addr = map_op_to_expr_ssa_aarch64(&operands[1], cs);
                     vec![
                         MicroInstruction::MemoryFence,
                         MicroInstruction::Assign(var_tujuan, MicroExpr::LoadMemori(Box::new(expr_addr)))
                     ]
                 } else {
                     vec![MicroInstruction::Undefined]
                 }
             } else {
                 vec![MicroInstruction::Undefined]
             }
        },
        "stxr" => {
             if operands.len() == 3 {
                 let expr_addr = map_op_to_expr_ssa_aarch64(&operands[1], cs);
                 let expr_nilai = map_op_to_expr_ssa_aarch64(&operands[0], cs);
                 if let Arm64OperandType::Reg(status_reg) = operands[2].op_type {
                     let status_var = create_var_ssa_from_reg(status_reg, cs);
                     vec![
                         MicroInstruction::AtomicRMW {
                             op: MicroAtomicOp::Xchg,
                             addr_mem: expr_addr,
                             nilai: expr_nilai,
                             tujuan_lama: Some(status_var)
                         },
                         MicroInstruction::MemoryFence
                     ]
                 } else {
                      vec![MicroInstruction::Undefined]
                 }
             } else {
                 vec![MicroInstruction::Undefined]
             }
        }
        "dmb" | "dsb" | "isb" => vec![MicroInstruction::MemoryFence],
        "ret" => vec![MicroInstruction::Return],
        _ => vec![MicroInstruction::Undefined],
    }
}

pub fn map_addr_mem_mips(op_mem: &MipsOpMem, cs: &Capstone) -> MicroExpr {
    let mut opt_expr: Option<Box<MicroExpr>> = None;
    if op_mem.base().0 != 0 {
        let var_basis = create_var_ssa_from_reg(op_mem.base(), cs);
        opt_expr = Some(Box::new(MicroExpr::Operand(MicroOperand::SsaVar(var_basis))));
    }
    if op_mem.disp() != 0 {
        let expr_disp = Box::new(MicroExpr::Operand(MicroOperand::Konstanta(op_mem.disp() as u64)));
        if let Some(expr_basis) = opt_expr {
             opt_expr = Some(Box::new(MicroExpr::BinaryOp(
                MicroBinOp::Add,
                expr_basis,
                expr_disp,
            )));
        } else {
            opt_expr = Some(expr_disp);
        }
    }
    *opt_expr.unwrap_or(Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))))
}

pub fn map_op_to_expr_ssa_mips(op: &MipsOperand, cs: &Capstone) -> MicroExpr {
    match op {
        MipsOperand::Reg(id_reg) => {
            let var = create_var_ssa_from_reg(*id_reg, cs);
            MicroExpr::Operand(MicroOperand::SsaVar(var))
        }
        MipsOperand::Imm(val) => {
            MicroExpr::Operand(MicroOperand::Konstanta(*val as u64))
        }
        MipsOperand::Mem(mem) => {
             let expr_addr = map_addr_mem_mips(mem, cs);
             MicroExpr::LoadMemori(Box::new(expr_addr))
        }
        _ => MicroExpr::Operand(MicroOperand::Konstanta(0))
    }
}

pub fn lift_ssa_mips(
    insn: &capstone::Insn,
    detail: &MipsInsnDetail,
    cs: &Capstone
) -> Vec<MicroInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<MipsOperand> = detail.operands().collect();
    match mnem {
        "lw" | "lb" | "lbu" | "lh" | "lhu" | "ld" => {
            if operands.len() == 2 {
                 if let MipsOperand::Reg(id_reg) = operands[0] {
                     let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                     let expr_sumber = map_op_to_expr_ssa_mips(&operands[1], cs);
                     vec![MicroInstruction::Assign(var_tujuan, expr_sumber)]
                 } else {
                     vec![MicroInstruction::Undefined]
                 }
            } else {
                vec![MicroInstruction::Undefined]
            }
        },
        "sw" | "sb" | "sh" | "sd" => {
             if operands.len() == 2 {
                 let expr_sumber = map_op_to_expr_ssa_mips(&operands[0], cs);
                 if let MipsOperand::Mem(mem) = &operands[1] {
                      let expr_addr = map_addr_mem_mips(mem, cs);
                      vec![MicroInstruction::StoreMemori(expr_addr, expr_sumber)]
                 } else {
                     vec![MicroInstruction::Undefined]
                 }
             } else {
                 vec![MicroInstruction::Undefined]
             }
        },
        "move" | "li" | "la" => {
             if operands.len() == 2 {
                 if let MipsOperand::Reg(id_reg) = operands[0] {
                     let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                     let expr_sumber = map_op_to_expr_ssa_mips(&operands[1], cs);
                     vec![MicroInstruction::Assign(var_tujuan, expr_sumber)]
                 } else {
                     vec![MicroInstruction::Undefined]
                 }
             } else {
                 vec![MicroInstruction::Undefined]
             }
        },
        "add" | "addu" | "dadd" | "daddu" | "addi" | "addiu" => {
             if operands.len() == 3 {
                if let MipsOperand::Reg(id_reg) = operands[0] {
                    let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                    let src1 = map_op_to_expr_ssa_mips(&operands[1], cs);
                    let src2 = map_op_to_expr_ssa_mips(&operands[2], cs);
                    vec![MicroInstruction::Assign(
                        var_tujuan,
                        MicroExpr::BinaryOp(MicroBinOp::Add, Box::new(src1), Box::new(src2))
                    )]
                } else {
                     vec![MicroInstruction::Undefined]
                }
             } else {
                 vec![MicroInstruction::Undefined]
             }
        },
        "sub" | "subu" | "dsub" | "dsubu" => {
             if operands.len() == 3 {
                if let MipsOperand::Reg(id_reg) = operands[0] {
                    let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                    let src1 = map_op_to_expr_ssa_mips(&operands[1], cs);
                    let src2 = map_op_to_expr_ssa_mips(&operands[2], cs);
                    vec![MicroInstruction::Assign(
                        var_tujuan,
                        MicroExpr::BinaryOp(MicroBinOp::Sub, Box::new(src1), Box::new(src2))
                    )]
                } else {
                     vec![MicroInstruction::Undefined]
                }
             } else {
                 vec![MicroInstruction::Undefined]
             }
        },
        "j" | "b" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Jump(map_op_to_expr_ssa_mips(&operands[0], cs))]
            } else {
                vec![MicroInstruction::Undefined]
            }
        },
        "jal" | "jalr" => {
            if !operands.is_empty() {
                 let target = if operands.len() == 2 { &operands[1] } else { &operands[0] };
                 vec![MicroInstruction::Call(map_op_to_expr_ssa_mips(target, cs))]
            } else {
                 vec![MicroInstruction::Undefined]
            }
        },
        "jr" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Return]
            } else {
                if !operands.is_empty() {
                    vec![MicroInstruction::Jump(map_op_to_expr_ssa_mips(&operands[0], cs))]
                } else {
                    vec![MicroInstruction::Undefined]
                }
            }
        },
        "syscall" => vec![MicroInstruction::Syscall],
        "nop" => vec![MicroInstruction::Nop],
        "sync" => vec![MicroInstruction::MemoryFence],
        _ => vec![MicroInstruction::Undefined],
    }
}

pub fn map_addr_mem_riscv(op_mem: &RiscVOpMem, cs: &Capstone) -> MicroExpr {
     let mut opt_expr: Option<Box<MicroExpr>> = None;
    if op_mem.base().0 != 0 {
        let var_basis = create_var_ssa_from_reg(op_mem.base(), cs);
        opt_expr = Some(Box::new(MicroExpr::Operand(MicroOperand::SsaVar(var_basis))));
    }
    if op_mem.disp() != 0 {
        let expr_disp = Box::new(MicroExpr::Operand(MicroOperand::Konstanta(op_mem.disp() as u64)));
        if let Some(expr_basis) = opt_expr {
             opt_expr = Some(Box::new(MicroExpr::BinaryOp(
                MicroBinOp::Add,
                expr_basis,
                expr_disp,
            )));
        } else {
            opt_expr = Some(expr_disp);
        }
    }
    *opt_expr.unwrap_or(Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))))
}

pub fn map_op_to_expr_ssa_riscv(op: &RiscVOperand, cs: &Capstone) -> MicroExpr {
    match op {
        RiscVOperand::Reg(id_reg) => {
             let var = create_var_ssa_from_reg(*id_reg, cs);
             MicroExpr::Operand(MicroOperand::SsaVar(var))
        },
        RiscVOperand::Imm(val) => {
             MicroExpr::Operand(MicroOperand::Konstanta(*val as u64))
        },
        RiscVOperand::Mem(mem) => {
             let addr = map_addr_mem_riscv(mem, cs);
             MicroExpr::LoadMemori(Box::new(addr))
        },
        _ => MicroExpr::Operand(MicroOperand::Konstanta(0))
    }
}

pub fn lift_ssa_riscv(
    insn: &capstone::Insn,
    detail: &RiscVInsnDetail,
    cs: &Capstone
) -> Vec<MicroInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<RiscVOperand> = detail.operands().collect();
    match mnem {
        "lb" | "lh" | "lw" | "ld" | "lbu" | "lhu" | "lwu" => {
            if operands.len() == 2 {
                if let RiscVOperand::Reg(id_reg) = operands[0] {
                    let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                    let expr_sumber = map_op_to_expr_ssa_riscv(&operands[1], cs);
                    vec![MicroInstruction::Assign(var_tujuan, expr_sumber)]
                } else {
                    vec![MicroInstruction::Undefined]
                }
            } else {
                vec![MicroInstruction::Undefined]
            }
        },
        "sb" | "sh" | "sw" | "sd" => {
             if operands.len() == 2 {
                 let expr_sumber = map_op_to_expr_ssa_riscv(&operands[0], cs);
                 if let RiscVOperand::Mem(mem) = &operands[1] {
                     let addr = map_addr_mem_riscv(mem, cs);
                     vec![MicroInstruction::StoreMemori(addr, expr_sumber)]
                 } else {
                     vec![MicroInstruction::Undefined]
                 }
             } else {
                 vec![MicroInstruction::Undefined]
             }
        },
        "add" | "addw" | "addi" | "addiw" => {
             if operands.len() == 3 {
                 if let RiscVOperand::Reg(id_reg) = operands[0] {
                     let var_tujuan = create_var_ssa_from_reg(id_reg, cs);
                     let src1 = map_op_to_expr_ssa_riscv(&operands[1], cs);
                     let src2 = map_op_to_expr_ssa_riscv(&operands[2], cs);
                     vec![MicroInstruction::Assign(var_tujuan, MicroExpr::BinaryOp(MicroBinOp::Add, Box::new(src1), Box::new(src2)))]
                 } else {
                     vec![MicroInstruction::Undefined]
                 }
             } else {
                 vec![MicroInstruction::Undefined]
             }
        },
        "fence" | "fence.i" => vec![MicroInstruction::MemoryFence],
        "jal" => {
            if !operands.is_empty() {
                let target = operands.last().unwrap(); 
                vec![MicroInstruction::Call(map_op_to_expr_ssa_riscv(target, cs))]
            } else {
                vec![MicroInstruction::Undefined]
            }
        },
        "ecall" | "ebreak" => vec![MicroInstruction::Syscall],
        "ret" => vec![MicroInstruction::Return],
        _ => vec![MicroInstruction::Undefined],
    }
}

pub fn lift_blok_instr(
    ptr_kode: &[u8],
    va_base_instr: u64,
    arch: ArsitekturDisasm,
) -> Result<(usize, Vec<MicroInstruction>), ReToolsError> {
    let cs = create_instance_capstone_by_arch(arch)?;
    let insns = cs
        .disasm_count(ptr_kode, va_base_instr, 1)
        .map_err(ReToolsError::from)?;
    let insn = insns
        .first()
        .ok_or(ReToolsError::Generic("Disasm failed".to_string()))?;
    let insn_detail = cs.insn_detail(insn)?;
    let detail = insn_detail.arch_detail();
    let ir_instrs = lift_from_detail(insn, &detail, &cs, arch);
    Ok((insn.bytes().len(), ir_instrs))
}

pub fn lift_from_detail(
    insn: &capstone::Insn,
    detail: &ArchDetail,
    cs: &Capstone,
    arch: ArsitekturDisasm,
) -> Vec<MicroInstruction> {
    match arch {
        ArsitekturDisasm::ARCH_X86_64 | ArsitekturDisasm::ARCH_X86_32 => {
            if let Some(x86_det) = detail.x86() {
                lift_ssa_x86(insn, x86_det, cs, arch)
            } else {
                vec![MicroInstruction::Undefined]
            }
        }
        ArsitekturDisasm::ARCH_ARM_32 => {
            if let Some(arm_det) = detail.arm() {
                lift_ssa_arm(insn, arm_det, cs)
            } else {
                vec![MicroInstruction::Undefined]
            }
        },
        ArsitekturDisasm::ARCH_ARM_64 => {
             if let Some(arm64_det) = detail.arm64() {
                 lift_ssa_aarch64(insn, arm64_det, cs)
             } else {
                 vec![MicroInstruction::Undefined]
             }
        },
        ArsitekturDisasm::ARCH_RISCV_32 | ArsitekturDisasm::ARCH_RISCV_64 => {
             if let Some(riscv_detail) = detail.riscv() {
                lift_ssa_riscv(insn, riscv_detail, cs)
             } else {
                 vec![MicroInstruction::Undefined]
             }
        }
        ArsitekturDisasm::ARCH_MIPS_32 | ArsitekturDisasm::ARCH_MIPS_64 => {
             if let Some(mips_detail) = detail.mips() {
                 lift_ssa_mips(insn, mips_detail, cs)
             } else {
                 vec![MicroInstruction::Undefined]
             }
        }
        _ => vec![MicroInstruction::Undefined],
    }
}