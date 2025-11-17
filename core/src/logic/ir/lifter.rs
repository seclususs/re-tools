use super::instruction::{
    IrBinOp, IrExpressionSsa, IrInstructionSsa, IrOperandSsa, IrUnOp, SsaVariabel,
};
use crate::error::ReToolsError;
use crate::logic::static_analysis::disasm::{ArsitekturDisasm, buat_instance_capstone_by_arch};
use capstone::prelude::*;
use capstone::arch::{
    arm::{ArmInsnDetail, ArmOperand, ArmOperandType},
    arm64::{Arm64InsnDetail, Arm64OpMem, Arm64Operand, Arm64OperandType},
    x86::{X86InsnDetail, X86OpMem, X86Operand, X86OperandType},
    ArchDetail,
};

#[allow(non_snake_case)]
fn buatSsaVariabel(reg_name: String) -> SsaVariabel {
    SsaVariabel {
        nama_dasar: reg_name,
        versi: 0,
    }
}
#[allow(non_snake_case)]
fn buatSsaVariabelDariRegId(reg_id: RegId, cs: &Capstone) -> SsaVariabel {
    let reg_name = cs.reg_name(reg_id).unwrap_or("unknown_reg".to_string());
    buatSsaVariabel(reg_name)
}

#[allow(non_snake_case)]
fn petakanAlamatMemoriX86(mem_op: &X86OpMem, cs: &Capstone) -> IrExpressionSsa {
    let mut expr_opt: Option<Box<IrExpressionSsa>> = None;
    if mem_op.base().0 != 0 {
        let base_var = buatSsaVariabelDariRegId(mem_op.base(), cs);
        expr_opt = Some(Box::new(IrExpressionSsa::Operand(IrOperandSsa::SsaVar(
            base_var,
        ))));
    }
    if mem_op.index().0 != 0 {
        let index_var = buatSsaVariabelDariRegId(mem_op.index(), cs);
        let index_expr = Box::new(IrExpressionSsa::Operand(IrOperandSsa::SsaVar(index_var)));
        let scale_expr = Box::new(IrExpressionSsa::Operand(IrOperandSsa::Konstanta(
            mem_op.scale() as u64,
        )));
        let scaled_index = Box::new(IrExpressionSsa::OperasiBiner(
            IrBinOp::Mul,
            index_expr,
            scale_expr,
        ));
        if let Some(base_expr) = expr_opt {
            expr_opt = Some(Box::new(IrExpressionSsa::OperasiBiner(
                IrBinOp::Add,
                base_expr,
                scaled_index,
            )));
        } else {
            expr_opt = Some(scaled_index);
        }
    }
    if mem_op.disp() != 0 {
        let disp_expr = Box::new(IrExpressionSsa::Operand(IrOperandSsa::Konstanta(
            mem_op.disp() as u64,
        )));
        if let Some(base_expr) = expr_opt {
            expr_opt = Some(Box::new(IrExpressionSsa::OperasiBiner(
                IrBinOp::Add,
                base_expr,
                disp_expr,
            )));
        } else {
            expr_opt = Some(disp_expr);
        }
    }
    *expr_opt.unwrap_or(Box::new(IrExpressionSsa::Operand(IrOperandSsa::Konstanta(0))))
}

#[allow(non_snake_case)]
fn petakanOperandKeEkspresiSsa(op: &X86Operand, cs: &Capstone) -> IrExpressionSsa {
    match op.op_type {
        X86OperandType::Reg(reg_id) => {
            let var = buatSsaVariabelDariRegId(reg_id, cs);
            IrExpressionSsa::Operand(IrOperandSsa::SsaVar(var))
        }
        X86OperandType::Imm(imm_val) => {
            IrExpressionSsa::Operand(IrOperandSsa::Konstanta(imm_val as u64))
        }
        X86OperandType::Mem(mem_op) => {
            let addr_expr = petakanAlamatMemoriX86(&mem_op, cs);
            IrExpressionSsa::MuatMemori(Box::new(addr_expr))
        }
        _ => IrExpressionSsa::Operand(IrOperandSsa::Konstanta(0)),
    }
}

#[allow(non_snake_case)]
pub fn angkatSsaX86(
    insn: &capstone::Insn,
    detail: &X86InsnDetail,
    cs: &Capstone,
) -> Vec<IrInstructionSsa> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<X86Operand> = detail.operands().collect();
    macro_rules! angkatOperasiBiner {
        ($op:expr) => {
            if operands.len() == 2 {
                let dest_op = &operands[0];
                let src_expr = petakanOperandKeEkspresiSsa(&operands[1], cs);
                match dest_op.op_type {
                    X86OperandType::Reg(reg_id) => {
                        let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                        let dest_expr =
                            IrExpressionSsa::Operand(IrOperandSsa::SsaVar(dest_var.clone()));
                        vec![IrInstructionSsa::Assign(
                            dest_var,
                            IrExpressionSsa::OperasiBiner($op, Box::new(dest_expr), Box::new(src_expr)),
                        )]
                    }
                    X86OperandType::Mem(mem_op) => {
                        let addr_expr = petakanAlamatMemoriX86(&mem_op, cs);
                        let dest_expr =
                            IrExpressionSsa::MuatMemori(Box::new(addr_expr.clone()));
                        vec![IrInstructionSsa::SimpanMemori(
                            addr_expr,
                            IrExpressionSsa::OperasiBiner(
                                $op,
                                Box::new(dest_expr),
                                Box::new(src_expr),
                            ),
                        )]
                    }
                    _ => vec![IrInstructionSsa::TidakTerdefinisi],
                }
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        };
    }
    match mnem {
        "mov" | "movsx" | "movzx" | "movaps" | "movsd" => {
            if operands.len() == 2 {
                let dest_op = &operands[0];
                let src_expr = petakanOperandKeEkspresiSsa(&operands[1], cs);
                match dest_op.op_type {
                    X86OperandType::Reg(reg_id) => {
                        let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                        vec![IrInstructionSsa::Assign(dest_var, src_expr)]
                    }
                    X86OperandType::Mem(mem_op) => {
                        let addr_expr = petakanAlamatMemoriX86(&mem_op, cs);
                        vec![IrInstructionSsa::SimpanMemori(
                            addr_expr,
                            src_expr,
                        )]
                    }
                    _ => vec![IrInstructionSsa::TidakTerdefinisi],
                }
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
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
                        vec![IrInstructionSsa::Assign(dest_var, addr_expr)]
                    } else {
                        vec![IrInstructionSsa::TidakTerdefinisi]
                    }
                } else {
                    vec![IrInstructionSsa::TidakTerdefinisi]
                }
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "push" => {
            if operands.len() == 1 {
                vec![IrInstructionSsa::Dorong(petakanOperandKeEkspresiSsa(
                    &operands[0],
                    cs,
                ))]
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "pop" => {
            if operands.len() == 1 {
                if let X86OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    vec![IrInstructionSsa::Ambil(dest_var)]
                } else {
                    vec![IrInstructionSsa::TidakTerdefinisi]
                }
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "add" => angkatOperasiBiner!(IrBinOp::Add),
        "addsd" => angkatOperasiBiner!(IrBinOp::TambahFloat),
        "sub" => angkatOperasiBiner!(IrBinOp::Sub),
        "subsd" => angkatOperasiBiner!(IrBinOp::KurangFloat),
        "and" => angkatOperasiBiner!(IrBinOp::And),
        "or" => angkatOperasiBiner!(IrBinOp::Or),
        "xor" => angkatOperasiBiner!(IrBinOp::Xor),
        "pxor" => {
            if operands.len() == 2 {
                if let (X86OperandType::Reg(reg1), X86OperandType::Reg(reg2)) =
                    (operands[0].op_type.clone(), operands[1].op_type.clone())
                {
                    let var1 = buatSsaVariabelDariRegId(reg1, cs);
                    let var2 = buatSsaVariabelDariRegId(reg2, cs);
                    vec![IrInstructionSsa::InstruksiVektor(
                        "pxor".to_string(),
                        vec![IrOperandSsa::SsaVar(var1), IrOperandSsa::SsaVar(var2)],
                    )]
                } else {
                    vec![IrInstructionSsa::TidakTerdefinisi]
                }
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "not" => {
            if operands.len() == 1 {
                let dest_op = &operands[0];
                match dest_op.op_type {
                    X86OperandType::Reg(reg_id) => {
                        let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                        let dest_expr =
                            IrExpressionSsa::Operand(IrOperandSsa::SsaVar(dest_var.clone()));
                        vec![IrInstructionSsa::Assign(
                            dest_var,
                            IrExpressionSsa::OperasiUnary(IrUnOp::Not, Box::new(dest_expr)),
                        )]
                    }
                    _ => vec![IrInstructionSsa::TidakTerdefinisi],
                }
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "cmp" => {
            if operands.len() == 2 {
                let op1 = petakanOperandKeEkspresiSsa(&operands[0], cs);
                let op2 = petakanOperandKeEkspresiSsa(&operands[1], cs);
                let flags_var = buatSsaVariabel("FLAGS".to_string());
                vec![IrInstructionSsa::Assign(
                    flags_var,
                    IrExpressionSsa::Bandingkan(Box::new(op1), Box::new(op2)),
                )]
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "test" => {
            if operands.len() == 2 {
                let op1 = petakanOperandKeEkspresiSsa(&operands[0], cs);
                let op2 = petakanOperandKeEkspresiSsa(&operands[1], cs);
                let flags_var = buatSsaVariabel("FLAGS".to_string());
                vec![IrInstructionSsa::Assign(
                    flags_var,
                    IrExpressionSsa::UjiBit(Box::new(op1), Box::new(op2)),
                )]
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "jmp" => {
            if operands.len() == 1 {
                vec![IrInstructionSsa::Lompat(petakanOperandKeEkspresiSsa(
                    &operands[0],
                    cs,
                ))]
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "je" | "jz" | "jne" | "jnz" | "jg" | "jl" | "jge" | "jle" | "ja" | "jb" | "jc" | "jnc"
        | "jo" | "jno" | "jp" | "jnp" | "js" | "jns" => {
            if operands.len() == 1 {
                let flags_var = buatSsaVariabel("FLAGS".to_string());
                let cond_expr = IrExpressionSsa::Operand(IrOperandSsa::SsaVar(flags_var));
                let target_expr = petakanOperandKeEkspresiSsa(&operands[0], cs);
                vec![IrInstructionSsa::LompatKondisi(cond_expr, target_expr)]
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "call" => {
            if operands.len() == 1 {
                vec![IrInstructionSsa::Panggil(petakanOperandKeEkspresiSsa(
                    &operands[0],
                    cs,
                ))]
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "ret" => vec![IrInstructionSsa::Kembali],
        "nop" => vec![IrInstructionSsa::Nop],
        "syscall" => vec![IrInstructionSsa::Syscall],
        _ => vec![IrInstructionSsa::TidakTerdefinisi],
    }
}

#[allow(non_snake_case)]
pub fn petakanOperandKeEkspresiSsaArm(op: &ArmOperand, cs: &Capstone) -> IrExpressionSsa {
    match op.op_type {
        ArmOperandType::Reg(reg_id) => {
            let var = buatSsaVariabelDariRegId(reg_id, cs);
            IrExpressionSsa::Operand(IrOperandSsa::SsaVar(var))
        }
        ArmOperandType::Imm(imm_val) => {
            IrExpressionSsa::Operand(IrOperandSsa::Konstanta(imm_val as u64))
        }
        _ => IrExpressionSsa::Operand(IrOperandSsa::Konstanta(0)),
    }
}

#[allow(non_snake_case)]
pub fn angkatSsaArm(
    _insn: &capstone::Insn,
    _detail: &ArmInsnDetail,
    _cs: &Capstone,
) -> Vec<IrInstructionSsa> {
    vec![IrInstructionSsa::TidakTerdefinisi]
}

#[allow(non_snake_case)]
pub fn petakanAlamatMemoriAarch64(mem_op: &Arm64OpMem, cs: &Capstone) -> IrExpressionSsa {
    let mut expr_opt: Option<Box<IrExpressionSsa>> = None;
    if mem_op.base().0 != 0 {
        let base_var = buatSsaVariabelDariRegId(mem_op.base(), cs);
        expr_opt = Some(Box::new(IrExpressionSsa::Operand(IrOperandSsa::SsaVar(
            base_var,
        ))));
    }
    if mem_op.index().0 != 0 {
        let index_var = buatSsaVariabelDariRegId(mem_op.index(), cs);
        let index_expr = Box::new(IrExpressionSsa::Operand(IrOperandSsa::SsaVar(index_var)));
        if let Some(base_expr) = expr_opt {
            expr_opt = Some(Box::new(IrExpressionSsa::OperasiBiner(
                IrBinOp::Add,
                base_expr,
                index_expr,
            )));
        } else {
            expr_opt = Some(index_expr);
        }
    }
    if mem_op.disp() != 0 {
        let disp_expr = Box::new(IrExpressionSsa::Operand(IrOperandSsa::Konstanta(
            mem_op.disp() as u64,
        )));
        if let Some(base_expr) = expr_opt {
            expr_opt = Some(Box::new(IrExpressionSsa::OperasiBiner(
                IrBinOp::Add,
                base_expr,
                disp_expr,
            )));
        } else {
            expr_opt = Some(disp_expr);
        }
    }
    *expr_opt.unwrap_or(Box::new(IrExpressionSsa::Operand(IrOperandSsa::Konstanta(0))))
}

#[allow(non_snake_case)]
pub fn petakanOperandKeEkspresiSsaAarch64(
    op: &Arm64Operand,
    cs: &Capstone,
) -> IrExpressionSsa {
    match op.op_type {
        Arm64OperandType::Reg(reg_id) => {
            let var = buatSsaVariabelDariRegId(reg_id, cs);
            IrExpressionSsa::Operand(IrOperandSsa::SsaVar(var))
        }
        Arm64OperandType::Imm(imm_val) => {
            IrExpressionSsa::Operand(IrOperandSsa::Konstanta(imm_val as u64))
        }
        Arm64OperandType::Mem(mem_op) => {
            let addr_expr = petakanAlamatMemoriAarch64(&mem_op, cs);
            IrExpressionSsa::MuatMemori(Box::new(addr_expr))
        }
        _ => IrExpressionSsa::Operand(IrOperandSsa::Konstanta(0)),
    }
}

#[allow(non_snake_case)]
pub fn angkatSsaAarch64(
    insn: &capstone::Insn,
    detail: &Arm64InsnDetail,
    cs: &Capstone,
) -> Vec<IrInstructionSsa> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<Arm64Operand> = detail.operands().collect();
    match mnem {
        "mov" => {
            if operands.len() == 2 {
                if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                    vec![IrInstructionSsa::Assign(dest_var, src_expr)]
                } else {
                    vec![IrInstructionSsa::TidakTerdefinisi]
                }
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "add" => {
            if operands.len() == 3 {
                if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                    let src2_expr = petakanOperandKeEkspresiSsaAarch64(&operands[2], cs);
                    vec![IrInstructionSsa::Assign(
                        dest_var,
                        IrExpressionSsa::OperasiBiner(
                            IrBinOp::Add,
                            Box::new(src1_expr),
                            Box::new(src2_expr),
                        ),
                    )]
                } else {
                    vec![IrInstructionSsa::TidakTerdefinisi]
                }
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "sub" => {
            if operands.len() == 3 {
                if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                    let src2_expr = petakanOperandKeEkspresiSsaAarch64(&operands[2], cs);
                    vec![IrInstructionSsa::Assign(
                        dest_var,
                        IrExpressionSsa::OperasiBiner(
                            IrBinOp::Sub,
                            Box::new(src1_expr),
                            Box::new(src2_expr),
                        ),
                    )]
                } else {
                    vec![IrInstructionSsa::TidakTerdefinisi]
                }
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "cmp" => {
            if operands.len() == 2 {
                let op1 = petakanOperandKeEkspresiSsaAarch64(&operands[0], cs);
                let op2 = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                let flags_var = buatSsaVariabel("pstate".to_string());
                vec![IrInstructionSsa::Assign(
                    flags_var,
                    IrExpressionSsa::Bandingkan(Box::new(op1), Box::new(op2)),
                )]
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "b" => {
            if operands.len() == 1 {
                vec![IrInstructionSsa::Lompat(
                    petakanOperandKeEkspresiSsaAarch64(&operands[0], cs),
                )]
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "bl" => {
            if operands.len() == 1 {
                vec![IrInstructionSsa::Panggil(
                    petakanOperandKeEkspresiSsaAarch64(&operands[0], cs),
                )]
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "ret" => vec![IrInstructionSsa::Kembali],
        "ldr" => {
            if operands.len() == 2 {
                if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                    vec![IrInstructionSsa::Assign(dest_var, src_expr)]
                } else {
                    vec![IrInstructionSsa::TidakTerdefinisi]
                }
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        "str" => {
            if operands.len() == 2 {
                let src_expr = petakanOperandKeEkspresiSsaAarch64(&operands[0], cs);
                if let Arm64OperandType::Mem(mem_op) = operands[1].op_type {
                    let addr_expr = petakanAlamatMemoriAarch64(&mem_op, cs);
                    vec![IrInstructionSsa::SimpanMemori(
                        addr_expr,
                        src_expr,
                    )]
                } else {
                    vec![IrInstructionSsa::TidakTerdefinisi]
                }
            } else {
                vec![IrInstructionSsa::TidakTerdefinisi]
            }
        }
        _ => vec![IrInstructionSsa::TidakTerdefinisi],
    }
}

pub fn angkat_blok_instruksi(
    bytes: &[u8],
    va: u64,
    arch: ArsitekturDisasm,
) -> Result<(usize, Vec<IrInstructionSsa>), ReToolsError> {
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
) -> Vec<IrInstructionSsa> {
    match arch {
        ArsitekturDisasm::ARCH_X86_64 | ArsitekturDisasm::ARCH_X86_32 => {
            angkatSsaX86(insn, detail.x86().unwrap(), cs)
        }
        ArsitekturDisasm::ARCH_ARM_32 => angkatSsaArm(insn, detail.arm().unwrap(), cs),
        ArsitekturDisasm::ARCH_ARM_64 => angkatSsaAarch64(insn, detail.arm64().unwrap(), cs),
        ArsitekturDisasm::ARCH_RISCV_32 | ArsitekturDisasm::ARCH_RISCV_64 => {
            vec![IrInstructionSsa::TidakTerdefinisi]
        }
        ArsitekturDisasm::ARCH_MIPS_32 | ArsitekturDisasm::ARCH_MIPS_64 => {
            vec![IrInstructionSsa::TidakTerdefinisi]
        }
        _ => vec![IrInstructionSsa::TidakTerdefinisi],
    }
}