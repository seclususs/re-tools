use super::instruction::{IrBinOp, IrExpression, IrInstruction, IrOperand, IrUnOp};
use crate::error::ReToolsError;
use crate::logic::static_analysis::disasm::{ArsitekturDisasm, buat_instance_capstone_by_arch};
use capstone::prelude::*;
use capstone::arch::{
    arm::{ArmInsnDetail, ArmOperand, ArmOperandType},
    arm64::{Arm64InsnDetail, Arm64OpMem, Arm64Operand, Arm64OperandType},
    x86::{X86InsnDetail, X86Operand, X86OperandType},
    ArchDetail,
};


pub fn angkat_blok_instruksi(
    bytes: &[u8],
    va: u64,
    arch: ArsitekturDisasm,
) -> Result<(usize, Vec<IrInstruction>), ReToolsError> {
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
) -> Vec<IrInstruction> {
    match arch {
        ArsitekturDisasm::ARCH_X86_64 | ArsitekturDisasm::ARCH_X86_32 => {
            angkat_x86(insn, detail.x86().unwrap(), cs)
        }
        ArsitekturDisasm::ARCH_ARM_32 => angkat_arm(insn, detail.arm().unwrap(), cs),
        ArsitekturDisasm::ARCH_ARM_64 => angkat_aarch64(insn, detail.arm64().unwrap(), cs),
        ArsitekturDisasm::ARCH_RISCV_32 | ArsitekturDisasm::ARCH_RISCV_64 => vec![IrInstruction::Undefined],
        ArsitekturDisasm::ARCH_MIPS_32 | ArsitekturDisasm::ARCH_MIPS_64 => vec![IrInstruction::Undefined],
        _ => vec![IrInstruction::Undefined],
    }
}

pub fn petakan_operand_x86(op: &X86Operand, cs: &Capstone) -> IrOperand {
    match op.op_type {
        X86OperandType::Reg(reg_id) => {
            let reg_name = cs.reg_name(reg_id).unwrap_or("unknown_reg".to_string());
            IrOperand::Register(reg_name)
        }
        X86OperandType::Imm(imm_val) => IrOperand::Immediate(imm_val as u64),
        X86OperandType::Mem(mem_op) => {
            let mut expr_opt: Option<Box<IrExpression>> = None;
            if mem_op.base().0 != 0 {
                let base_reg_name = cs
                    .reg_name(mem_op.base())
                    .unwrap_or("unknown_reg".to_string());
                expr_opt = Some(Box::new(IrExpression::Operand(IrOperand::Register(
                    base_reg_name,
                ))));
            }
            if mem_op.index().0 != 0 {
                let index_reg_name = cs
                    .reg_name(mem_op.index())
                    .unwrap_or("unknown_reg".to_string());
                let index_expr = Box::new(IrExpression::Operand(IrOperand::Register(
                    index_reg_name,
                )));
                let scale_expr = Box::new(IrExpression::Operand(IrOperand::Immediate(
                    mem_op.scale() as u64,
                )));
                let scaled_index =
                    Box::new(IrExpression::BinaryOp(IrBinOp::Mul, index_expr, scale_expr));
                if let Some(base_expr) = expr_opt {
                    expr_opt = Some(Box::new(IrExpression::BinaryOp(
                        IrBinOp::Add,
                        base_expr,
                        scaled_index,
                    )));
                } else {
                    expr_opt = Some(scaled_index);
                }
            }
            if mem_op.disp() != 0 {
                let disp_expr = Box::new(IrExpression::Operand(IrOperand::Immediate(
                    mem_op.disp() as u64,
                )));
                if let Some(base_expr) = expr_opt {
                    expr_opt = Some(Box::new(IrExpression::BinaryOp(
                        IrBinOp::Add,
                        base_expr,
                        disp_expr,
                    )));
                } else {
                    expr_opt = Some(disp_expr);
                }
            }
            IrOperand::Memory(
                expr_opt.unwrap_or(Box::new(IrExpression::Operand(IrOperand::Immediate(0)))),
            )
        }
        _ => IrOperand::Immediate(0),
    }
}

pub fn angkat_x86(insn: &capstone::Insn, detail: &X86InsnDetail, cs: &Capstone) -> Vec<IrInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<X86Operand> = detail.operands().collect();
    match mnem {
        "mov" | "movsx" | "movzx" | "movaps" => {
            if operands.len() == 2 {
                let dest = petakan_operand_x86(&operands[0], cs);
                let src = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::Set(dest, IrExpression::Operand(src))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "movsd" => {
             if operands.len() == 2 {
                let dest = petakan_operand_x86(&operands[0], cs);
                let src = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::Set(dest, IrExpression::Operand(src))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "lea" => {
            if operands.len() == 2 {
                let dest = petakan_operand_x86(&operands[0], cs);
                let src_op = petakan_operand_x86(&operands[1], cs);
                if let IrOperand::Memory(expr) = src_op {
                    vec![IrInstruction::Set(dest, *expr)]
                } else {
                    vec![IrInstruction::Undefined]
                }
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "push" => {
            if operands.len() == 1 {
                vec![IrInstruction::Push(IrExpression::Operand(
                    petakan_operand_x86(&operands[0], cs),
                ))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "pop" => {
            if operands.len() == 1 {
                vec![IrInstruction::Pop(petakan_operand_x86(&operands[0], cs))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "add" => {
            if operands.len() == 2 {
                let dest = petakan_operand_x86(&operands[0], cs);
                let src = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::Set(
                    dest.clone(),
                    IrExpression::BinaryOp(
                        IrBinOp::Add,
                        Box::new(IrExpression::Operand(dest)),
                        Box::new(IrExpression::Operand(src)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
         "addsd" => {
            if operands.len() == 2 {
                let dest = petakan_operand_x86(&operands[0], cs);
                let src = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::Set(
                    dest.clone(),
                    IrExpression::BinaryOp(
                        IrBinOp::TambahFloat,
                        Box::new(IrExpression::Operand(dest)),
                        Box::new(IrExpression::Operand(src)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "sub" => {
            if operands.len() == 2 {
                let dest = petakan_operand_x86(&operands[0], cs);
                let src = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::Set(
                    dest.clone(),
                    IrExpression::BinaryOp(
                        IrBinOp::Sub,
                        Box::new(IrExpression::Operand(dest)),
                        Box::new(IrExpression::Operand(src)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "subsd" => {
            if operands.len() == 2 {
                let dest = petakan_operand_x86(&operands[0], cs);
                let src = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::Set(
                    dest.clone(),
                    IrExpression::BinaryOp(
                        IrBinOp::KurangFloat,
                        Box::new(IrExpression::Operand(dest)),
                        Box::new(IrExpression::Operand(src)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "and" => {
            if operands.len() == 2 {
                let dest = petakan_operand_x86(&operands[0], cs);
                let src = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::Set(
                    dest.clone(),
                    IrExpression::BinaryOp(
                        IrBinOp::And,
                        Box::new(IrExpression::Operand(dest)),
                        Box::new(IrExpression::Operand(src)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "or" => {
            if operands.len() == 2 {
                let dest = petakan_operand_x86(&operands[0], cs);
                let src = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::Set(
                    dest.clone(),
                    IrExpression::BinaryOp(
                        IrBinOp::Or,
                        Box::new(IrExpression::Operand(dest)),
                        Box::new(IrExpression::Operand(src)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "xor" => {
            if operands.len() == 2 {
                let dest = petakan_operand_x86(&operands[0], cs);
                let src = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::Set(
                    dest.clone(),
                    IrExpression::BinaryOp(
                        IrBinOp::Xor,
                        Box::new(IrExpression::Operand(dest)),
                        Box::new(IrExpression::Operand(src)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "pxor" => {
            if operands.len() == 2 {
                let dest = petakan_operand_x86(&operands[0], cs);
                let src = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::InstruksiVektor(
                    "pxor".to_string(),
                    vec![dest, src]
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "not" => {
            if operands.len() == 1 {
                let dest = petakan_operand_x86(&operands[0], cs);
                vec![IrInstruction::Set(
                    dest.clone(),
                    IrExpression::UnaryOp(IrUnOp::Not, Box::new(IrExpression::Operand(dest))),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "cmp" => {
            if operands.len() == 2 {
                let op1 = petakan_operand_x86(&operands[0], cs);
                let op2 = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::Set(
                    IrOperand::Register("FLAGS".to_string()),
                    IrExpression::Cmp(
                        Box::new(IrExpression::Operand(op1)),
                        Box::new(IrExpression::Operand(op2)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "test" => {
            if operands.len() == 2 {
                let op1 = petakan_operand_x86(&operands[0], cs);
                let op2 = petakan_operand_x86(&operands[1], cs);
                vec![IrInstruction::Set(
                    IrOperand::Register("FLAGS".to_string()),
                    IrExpression::Test(
                        Box::new(IrExpression::Operand(op1)),
                        Box::new(IrExpression::Operand(op2)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "jmp" => {
            if operands.len() == 1 {
                vec![IrInstruction::Jmp(IrExpression::Operand(
                    petakan_operand_x86(&operands[0], cs),
                ))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "je" | "jz" | "jne" | "jnz" | "jg" | "jl" | "jge" | "jle" | "ja" | "jb" | "jc" | "jnc"
        | "jo" | "jno" | "jp" | "jnp" | "js" | "jns" => {
            if operands.len() == 1 {
                vec![IrInstruction::JmpCond(
                    IrExpression::Operand(IrOperand::Register("FLAGS".to_string())),
                    IrExpression::Operand(petakan_operand_x86(&operands[0], cs)),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "call" => {
            if operands.len() == 1 {
                vec![IrInstruction::Call(IrExpression::Operand(
                    petakan_operand_x86(&operands[0], cs),
                ))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "ret" => vec![IrInstruction::Ret],
        "nop" => vec![IrInstruction::Nop],
        "syscall" => vec![IrInstruction::Syscall],
        _ => vec![IrInstruction::Undefined],
    }
}

pub fn petakan_operand_arm(op: &ArmOperand, cs: &Capstone) -> IrOperand {
    match op.op_type {
        ArmOperandType::Reg(reg_id) => {
            IrOperand::Register(cs.reg_name(reg_id).unwrap_or("unknown_reg".to_string()))
        }
        ArmOperandType::Imm(imm_val) => IrOperand::Immediate(imm_val as u64),
        _ => IrOperand::Immediate(0),
    }
}

pub fn angkat_arm(
    insn: &capstone::Insn,
    detail: &ArmInsnDetail,
    cs: &Capstone,
) -> Vec<IrInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<ArmOperand> = detail.operands().collect();
    match mnem {
        "mov" => {
            if operands.len() == 2 {
                let dest = petakan_operand_arm(&operands[0], cs);
                let src = petakan_operand_arm(&operands[1], cs);
                vec![IrInstruction::Set(dest, IrExpression::Operand(src))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "add" => {
            if operands.len() == 3 {
                let dest = petakan_operand_arm(&operands[0], cs);
                let src1 = petakan_operand_arm(&operands[1], cs);
                let src2 = petakan_operand_arm(&operands[2], cs);
                vec![IrInstruction::Set(
                    dest,
                    IrExpression::BinaryOp(
                        IrBinOp::Add,
                        Box::new(IrExpression::Operand(src1)),
                        Box::new(IrExpression::Operand(src2)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "sub" => {
            if operands.len() == 3 {
                let dest = petakan_operand_arm(&operands[0], cs);
                let src1 = petakan_operand_arm(&operands[1], cs);
                let src2 = petakan_operand_arm(&operands[2], cs);
                vec![IrInstruction::Set(
                    dest,
                    IrExpression::BinaryOp(
                        IrBinOp::Sub,
                        Box::new(IrExpression::Operand(src1)),
                        Box::new(IrExpression::Operand(src2)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "cmp" => {
            if operands.len() == 2 {
                let op1 = petakan_operand_arm(&operands[0], cs);
                let op2 = petakan_operand_arm(&operands[1], cs);
                vec![IrInstruction::Set(
                    IrOperand::Register("cpsr".to_string()),
                    IrExpression::Cmp(
                        Box::new(IrExpression::Operand(op1)),
                        Box::new(IrExpression::Operand(op2)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "b" => {
            if operands.len() == 1 {
                vec![IrInstruction::Jmp(IrExpression::Operand(
                    petakan_operand_arm(&operands[0], cs),
                ))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "bl" => {
            if operands.len() == 1 {
                vec![IrInstruction::Call(IrExpression::Operand(
                    petakan_operand_arm(&operands[0], cs),
                ))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "bx" => {
            if operands.len() == 1 {
                vec![IrInstruction::Ret]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "pop" => {
            if operands.len() >= 1 {
                vec![IrInstruction::Pop(petakan_operand_arm(&operands[0], cs))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "push" => {
            if operands.len() >= 1 {
                vec![IrInstruction::Push(IrExpression::Operand(petakan_operand_arm(
                    &operands[0],
                    cs,
                )))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        _ => vec![IrInstruction::Undefined],
    }
}

pub fn petakan_mem_op_aarch64(mem_op: &Arm64OpMem, cs: &Capstone) -> IrOperand {
    let mut expr_opt: Option<Box<IrExpression>> = None;
    if mem_op.base().0 != 0 {
        let base_reg_name = cs
            .reg_name(mem_op.base())
            .unwrap_or("unknown_reg".to_string());
        expr_opt = Some(Box::new(IrExpression::Operand(IrOperand::Register(
            base_reg_name,
        ))));
    }
    if mem_op.index().0 != 0 {
        let index_reg_name = cs
            .reg_name(mem_op.index())
            .unwrap_or("unknown_reg".to_string());
        let index_expr = Box::new(IrExpression::Operand(IrOperand::Register(
            index_reg_name,
        )));
        if let Some(base_expr) = expr_opt {
            expr_opt = Some(Box::new(IrExpression::BinaryOp(
                IrBinOp::Add,
                base_expr,
                index_expr,
            )));
        } else {
            expr_opt = Some(index_expr);
        }
    }
    if mem_op.disp() != 0 {
        let disp_expr = Box::new(IrExpression::Operand(IrOperand::Immediate(
            mem_op.disp() as u64,
        )));
        if let Some(base_expr) = expr_opt {
            expr_opt = Some(Box::new(IrExpression::BinaryOp(
                IrBinOp::Add,
                base_expr,
                disp_expr,
            )));
        } else {
            expr_opt = Some(disp_expr);
        }
    }
    IrOperand::Memory(expr_opt.unwrap_or(Box::new(IrExpression::Operand(IrOperand::Immediate(0)))))
}

pub fn petakan_operand_aarch64(op: &Arm64Operand, cs: &Capstone) -> IrOperand {
    match op.op_type {
        Arm64OperandType::Reg(reg_id) => {
            IrOperand::Register(cs.reg_name(reg_id).unwrap_or("unknown_reg".to_string()))
        }
        Arm64OperandType::Imm(imm_val) => IrOperand::Immediate(imm_val as u64),
        Arm64OperandType::Mem(mem_op) => petakan_mem_op_aarch64(&mem_op, cs),
        _ => IrOperand::Immediate(0),
    }
}

pub fn angkat_aarch64(
    insn: &capstone::Insn,
    detail: &Arm64InsnDetail,
    cs: &Capstone,
) -> Vec<IrInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<Arm64Operand> = detail.operands().collect();
    match mnem {
        "mov" => {
            if operands.len() == 2 {
                let dest = petakan_operand_aarch64(&operands[0], cs);
                let src = petakan_operand_aarch64(&operands[1], cs);
                vec![IrInstruction::Set(dest, IrExpression::Operand(src))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "add" => {
            if operands.len() == 3 {
                let dest = petakan_operand_aarch64(&operands[0], cs);
                let src1 = petakan_operand_aarch64(&operands[1], cs);
                let src2 = petakan_operand_aarch64(&operands[2], cs);
                vec![IrInstruction::Set(
                    dest,
                    IrExpression::BinaryOp(
                        IrBinOp::Add,
                        Box::new(IrExpression::Operand(src1)),
                        Box::new(IrExpression::Operand(src2)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "sub" => {
            if operands.len() == 3 {
                let dest = petakan_operand_aarch64(&operands[0], cs);
                let src1 = petakan_operand_aarch64(&operands[1], cs);
                let src2 = petakan_operand_aarch64(&operands[2], cs);
                vec![IrInstruction::Set(
                    dest,
                    IrExpression::BinaryOp(
                        IrBinOp::Sub,
                        Box::new(IrExpression::Operand(src1)),
                        Box::new(IrExpression::Operand(src2)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "cmp" => {
            if operands.len() == 2 {
                let op1 = petakan_operand_aarch64(&operands[0], cs);
                let op2 = petakan_operand_aarch64(&operands[1], cs);
                vec![IrInstruction::Set(
                    IrOperand::Register("pstate".to_string()),
                    IrExpression::Cmp(
                        Box::new(IrExpression::Operand(op1)),
                        Box::new(IrExpression::Operand(op2)),
                    ),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "b" => {
            if operands.len() == 1 {
                vec![IrInstruction::Jmp(IrExpression::Operand(
                    petakan_operand_aarch64(&operands[0], cs),
                ))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "bl" => {
            if operands.len() == 1 {
                vec![IrInstruction::Call(IrExpression::Operand(
                    petakan_operand_aarch64(&operands[0], cs),
                ))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "ret" => vec![IrInstruction::Ret],
        "ldr" => {
            if operands.len() == 2 {
                let dest = petakan_operand_aarch64(&operands[0], cs);
                let src = petakan_operand_aarch64(&operands[1], cs);
                vec![IrInstruction::Set(dest, IrExpression::Operand(src))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "str" => {
            if operands.len() == 2 {
                let src = petakan_operand_aarch64(&operands[0], cs);
                let dest = petakan_operand_aarch64(&operands[1], cs);
                vec![IrInstruction::Set(dest, IrExpression::Operand(src))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        _ => vec![IrInstruction::Undefined],
    }
}