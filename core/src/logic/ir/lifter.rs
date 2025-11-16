use super::instruction::{IrBinOp, IrExpression, IrInstruction, IrOperand};
use crate::error::ReToolsError;
use crate::logic::static_analysis::disasm::ArsitekturDisasm;
use capstone::prelude::*;
use capstone::arch::{
    x86::{X86InsnDetail, X86Operand, X86OperandType}, 
    ArchDetail,
};


fn get_capstone_instance(arch: ArsitekturDisasm) -> Result<Capstone, ReToolsError> {
    let cs_result = match arch {
        ArsitekturDisasm::ARCH_X86_32 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .detail(true)
            .build(),
        ArsitekturDisasm::ARCH_X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build(),
        ArsitekturDisasm::ARCH_ARM_32 => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(true)
            .build(),
        ArsitekturDisasm::ARCH_ARM_64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build(),
        _ => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build(),
    };
    cs_result.map_err(ReToolsError::from)
}

pub fn angkat_blok_instruksi(
    bytes: &[u8],
    va: u64,
    arch: ArsitekturDisasm,
) -> Result<(usize, Vec<IrInstruction>), ReToolsError> {
    let cs = get_capstone_instance(arch)?;
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

fn angkat_dari_detail(
    insn: &capstone::Insn,
    detail: &ArchDetail,
    cs: &Capstone,
    arch: ArsitekturDisasm,
) -> Vec<IrInstruction> {
    match arch {
        ArsitekturDisasm::ARCH_X86_64 | ArsitekturDisasm::ARCH_X86_32 => {
            lift_x86(insn, detail.x86().unwrap(), cs)
        }
        _ => vec![IrInstruction::Undefined],
    }
}

fn map_x86_operand(op: &X86Operand, cs: &Capstone) -> IrOperand {
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

fn lift_x86(insn: &capstone::Insn, detail: &X86InsnDetail, cs: &Capstone) -> Vec<IrInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<X86Operand> = detail.operands().collect();
    match mnem {
        "mov" | "movsx" | "movzx" => {
            if operands.len() == 2 {
                let dest = map_x86_operand(&operands[0], cs);
                let src = map_x86_operand(&operands[1], cs);
                vec![IrInstruction::Set(dest, IrExpression::Operand(src))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "push" => {
            if operands.len() == 1 {
                vec![IrInstruction::Push(IrExpression::Operand(
                    map_x86_operand(&operands[0], cs),
                ))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "pop" => {
            if operands.len() == 1 {
                vec![IrInstruction::Pop(map_x86_operand(&operands[0], cs))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "add" => {
            if operands.len() == 2 {
                let dest = map_x86_operand(&operands[0], cs);
                let src = map_x86_operand(&operands[1], cs);
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
        "sub" => {
            if operands.len() == 2 {
                let dest = map_x86_operand(&operands[0], cs);
                let src = map_x86_operand(&operands[1], cs);
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
        "jmp" => {
            if operands.len() == 1 {
                vec![IrInstruction::Jmp(IrExpression::Operand(
                    map_x86_operand(&operands[0], cs),
                ))]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "je" | "jz" | "jne" | "jnz" | "jg" | "jl" | "jge" | "jle" | "ja" | "jb" | "jc" | "jnc"
        | "jo" | "jno" | "jp" | "jnp" | "js" | "jns" => {
            if operands.len() == 1 {
                vec![IrInstruction::JmpCond(
                    IrExpression::Operand(IrOperand::Register("eflags".to_string())),
                    IrExpression::Operand(map_x86_operand(&operands[0], cs)),
                )]
            } else {
                vec![IrInstruction::Undefined]
            }
        }
        "call" => {
            if operands.len() == 1 {
                vec![IrInstruction::Call(IrExpression::Operand(
                    map_x86_operand(&operands[0], cs),
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