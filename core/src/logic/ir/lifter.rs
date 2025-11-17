//! Author: [Seclususs](https://github.com/seclususs)

use super::instruction::{
    MicroBinOp, MicroExpr, MicroInstruction, MicroOperand, MicroUnOp, SsaVariabel,
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
fn petakanAlamatMemoriX86(mem_op: &X86OpMem, cs: &Capstone) -> MicroExpr {
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
fn petakanOperandKeEkspresiSsa(op: &X86Operand, cs: &Capstone) -> MicroExpr {
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
pub fn angkatSsaX86(
    insn: &capstone::Insn,
    detail: &X86InsnDetail,
    cs: &Capstone,
    arch: ArsitekturDisasm,
) -> Vec<MicroInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<X86Operand> = detail.operands().collect();
    macro_rules! angkatOperasiBiner {
        ($op:expr, $arch:expr) => {{
            let mut instrs = Vec::new();
            let mut dest_var_opt: Option<SsaVariabel> = None;
            if operands.len() == 2 {
                let dest_op = &operands[0];
                let src_expr = petakanOperandKeEkspresiSsa(&operands[1], cs);
                match dest_op.op_type {
                    X86OperandType::Reg(reg_id) => {
                        let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                        let dest_expr =
                            MicroExpr::Operand(MicroOperand::SsaVar(dest_var.clone()));
                        instrs.push(MicroInstruction::Assign(
                            dest_var.clone(),
                            MicroExpr::OperasiBiner($op, Box::new(dest_expr), Box::new(src_expr)),
                        ));
                        dest_var_opt = Some(dest_var);
                    }
                    X86OperandType::Mem(mem_op) => {
                        let addr_expr = petakanAlamatMemoriX86(&mem_op, cs);
                        let dest_expr =
                            MicroExpr::MuatMemori(Box::new(addr_expr.clone()));
                        instrs.push(MicroInstruction::SimpanMemori(
                            addr_expr,
                            MicroExpr::OperasiBiner(
                                $op,
                                Box::new(dest_expr),
                                Box::new(src_expr),
                            ),
                        ));
                    }
                    _ => instrs.push(MicroInstruction::TidakTerdefinisi),
                }
            } else {
                instrs.push(MicroInstruction::TidakTerdefinisi);
            }
            (instrs, dest_var_opt)
        }};
    }
    match mnem {
        "mov" | "movsx" | "movzx" | "movaps" | "movsd" => {
            if operands.len() == 2 {
                let dest_op = &operands[0];
                let src_expr = petakanOperandKeEkspresiSsa(&operands[1], cs);
                match dest_op.op_type {
                    X86OperandType::Reg(reg_id) => {
                        let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                        vec![MicroInstruction::Assign(dest_var, src_expr)]
                    }
                    X86OperandType::Mem(mem_op) => {
                        let addr_expr = petakanAlamatMemoriX86(&mem_op, cs);
                        vec![MicroInstruction::SimpanMemori(
                            addr_expr,
                            src_expr,
                        )]
                    }
                    _ => vec![MicroInstruction::TidakTerdefinisi],
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
                let src_expr = petakanOperandKeEkspresiSsa(&operands[0], cs);
                let t1 = buatSsaVariabel("t1".to_string());
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
                    let t1 = buatSsaVariabel("t1".to_string());
                    let expr_load = MicroExpr::MuatMemori(Box::new(MicroExpr::Operand(
                        MicroOperand::SsaVar(reg_sp.clone()),
                    )));
                    let instr1 = MicroInstruction::Assign(t1.clone(), expr_load);
                    let instr2 =
                        MicroInstruction::Assign(dest_var, MicroExpr::Operand(MicroOperand::SsaVar(t1)));
                    let t2 = buatSsaVariabel("t2".to_string());
                    let expr_add = MicroExpr::OperasiBiner(
                        MicroBinOp::Add,
                        Box::new(MicroExpr::Operand(MicroOperand::SsaVar(reg_sp.clone()))),
                        Box::new(MicroExpr::Operand(MicroOperand::Konstanta(op_size))),
                    );
                    let instr3 = MicroInstruction::Assign(t2.clone(), expr_add);
                    let instr4 =
                        MicroInstruction::Assign(reg_sp, MicroExpr::Operand(MicroOperand::SsaVar(t2)));
                    vec![instr1, instr2, instr3, instr4]
                } else {
                    vec![MicroInstruction::TidakTerdefinisi]
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "add" | "addsd" => {
            let (mut base_instrs, dest_var_opt) = angkatOperasiBiner!(MicroBinOp::Add, arch);
            if let Some(dest_var) = dest_var_opt {
                let flags_var = buatSsaVariabel("FLAGS".to_string());
                let flags_expr = MicroExpr::Bandingkan(
                    Box::new(MicroExpr::Operand(MicroOperand::SsaVar(dest_var))),
                    Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))),
                );
                base_instrs.push(MicroInstruction::Assign(flags_var, flags_expr));
            }
            base_instrs
        }
        "sub" | "subsd" => {
            let (mut base_instrs, dest_var_opt) = angkatOperasiBiner!(MicroBinOp::Sub, arch);
            if let Some(dest_var) = dest_var_opt {
                let flags_var = buatSsaVariabel("FLAGS".to_string());
                let flags_expr = MicroExpr::Bandingkan(
                    Box::new(MicroExpr::Operand(MicroOperand::SsaVar(dest_var))),
                    Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))),
                );
                base_instrs.push(MicroInstruction::Assign(flags_var, flags_expr));
            }
            base_instrs
        }
        "and" => {
            let (mut base_instrs, dest_var_opt) = angkatOperasiBiner!(MicroBinOp::And, arch);
            if let Some(dest_var) = dest_var_opt {
                let flags_var = buatSsaVariabel("FLAGS".to_string());
                let flags_expr = MicroExpr::Bandingkan(
                    Box::new(MicroExpr::Operand(MicroOperand::SsaVar(dest_var))),
                    Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))),
                );
                base_instrs.push(MicroInstruction::Assign(flags_var, flags_expr));
            }
            base_instrs
        }
        "or" => {
            let (mut base_instrs, dest_var_opt) = angkatOperasiBiner!(MicroBinOp::Or, arch);
            if let Some(dest_var) = dest_var_opt {
                let flags_var = buatSsaVariabel("FLAGS".to_string());
                let flags_expr = MicroExpr::Bandingkan(
                    Box::new(MicroExpr::Operand(MicroOperand::SsaVar(dest_var))),
                    Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))),
                );
                base_instrs.push(MicroInstruction::Assign(flags_var, flags_expr));
            }
            base_instrs
        }
        "xor" => {
            let (mut base_instrs, dest_var_opt) = angkatOperasiBiner!(MicroBinOp::Xor, arch);
            if let Some(dest_var) = dest_var_opt {
                let flags_var = buatSsaVariabel("FLAGS".to_string());
                let flags_expr = MicroExpr::Bandingkan(
                    Box::new(MicroExpr::Operand(MicroOperand::SsaVar(dest_var))),
                    Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))),
                );
                base_instrs.push(MicroInstruction::Assign(flags_var, flags_expr));
            }
            base_instrs
        }
        "pxor" => {
            if operands.len() == 2 {
                if let (X86OperandType::Reg(reg1), X86OperandType::Reg(reg2)) =
                    (operands[0].op_type.clone(), operands[1].op_type.clone())
                {
                    let var1 = buatSsaVariabelDariRegId(reg1, cs);
                    let var2 = buatSsaVariabelDariRegId(reg2, cs);
                    vec![MicroInstruction::InstruksiVektor(
                        "pxor".to_string(),
                        vec![MicroOperand::SsaVar(var1), MicroOperand::SsaVar(var2)],
                    )]
                } else {
                    vec![MicroInstruction::TidakTerdefinisi]
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "not" => {
            if operands.len() == 1 {
                let dest_op = &operands[0];
                match dest_op.op_type {
                    X86OperandType::Reg(reg_id) => {
                        let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                        let dest_expr =
                            MicroExpr::Operand(MicroOperand::SsaVar(dest_var.clone()));
                        vec![MicroInstruction::Assign(
                            dest_var,
                            MicroExpr::OperasiUnary(MicroUnOp::Not, Box::new(dest_expr)),
                        )]
                    }
                    _ => vec![MicroInstruction::TidakTerdefinisi],
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "cmp" => {
            if operands.len() == 2 {
                let op1 = petakanOperandKeEkspresiSsa(&operands[0], cs);
                let op2 = petakanOperandKeEkspresiSsa(&operands[1], cs);
                let flags_var = buatSsaVariabel("FLAGS".to_string());
                vec![MicroInstruction::Assign(
                    flags_var,
                    MicroExpr::Bandingkan(Box::new(op1), Box::new(op2)),
                )]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "test" => {
            if operands.len() == 2 {
                let op1 = petakanOperandKeEkspresiSsa(&operands[0], cs);
                let op2 = petakanOperandKeEkspresiSsa(&operands[1], cs);
                let flags_var = buatSsaVariabel("FLAGS".to_string());
                vec![MicroInstruction::Assign(
                    flags_var,
                    MicroExpr::UjiBit(Box::new(op1), Box::new(op2)),
                )]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "jmp" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Lompat(petakanOperandKeEkspresiSsa(
                    &operands[0],
                    cs,
                ))]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "je" | "jz" | "jne" | "jnz" | "jg" | "jl" | "jge" | "jle" | "ja" | "jb" | "jc" | "jnc"
        | "jo" | "jno" | "jp" | "jnp" | "js" | "jns" => {
            if operands.len() == 1 {
                let flags_var = buatSsaVariabel("FLAGS".to_string());
                let cond_expr = MicroExpr::Operand(MicroOperand::SsaVar(flags_var));
                let target_expr = petakanOperandKeEkspresiSsa(&operands[0], cs);
                vec![MicroInstruction::LompatKondisi(cond_expr, target_expr)]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "call" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Panggil(petakanOperandKeEkspresiSsa(
                    &operands[0],
                    cs,
                ))]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "ret" => vec![MicroInstruction::Kembali],
        "nop" => vec![MicroInstruction::Nop],
        "syscall" => vec![MicroInstruction::Syscall],
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
pub fn angkatSsaAarch64(
    insn: &capstone::Insn,
    detail: &Arm64InsnDetail,
    cs: &Capstone,
) -> Vec<MicroInstruction> {
    let mnem = insn.mnemonic().unwrap_or("");
    let operands: Vec<Arm64Operand> = detail.operands().collect();
    match mnem {
        "mov" => {
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
        "add" => {
            if operands.len() == 3 {
                if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                    let src2_expr = petakanOperandKeEkspresiSsaAarch64(&operands[2], cs);
                    vec![MicroInstruction::Assign(
                        dest_var,
                        MicroExpr::OperasiBiner(
                            MicroBinOp::Add,
                            Box::new(src1_expr),
                            Box::new(src2_expr),
                        ),
                    )]
                } else {
                    vec![MicroInstruction::TidakTerdefinisi]
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "sub" => {
            if operands.len() == 3 {
                if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                    let src2_expr = petakanOperandKeEkspresiSsaAarch64(&operands[2], cs);
                    vec![MicroInstruction::Assign(
                        dest_var,
                        MicroExpr::OperasiBiner(
                            MicroBinOp::Sub,
                            Box::new(src1_expr),
                            Box::new(src2_expr),
                        ),
                    )]
                } else {
                    vec![MicroInstruction::TidakTerdefinisi]
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "cmp" => {
            if operands.len() == 2 {
                let op1 = petakanOperandKeEkspresiSsaAarch64(&operands[0], cs);
                let op2 = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                let flags_var = buatSsaVariabel("pstate".to_string());
                vec![MicroInstruction::Assign(
                    flags_var,
                    MicroExpr::Bandingkan(Box::new(op1), Box::new(op2)),
                )]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "b" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Lompat(
                    petakanOperandKeEkspresiSsaAarch64(&operands[0], cs),
                )]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "bl" => {
            if operands.len() == 1 {
                vec![MicroInstruction::Panggil(
                    petakanOperandKeEkspresiSsaAarch64(&operands[0], cs),
                )]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "ret" => vec![MicroInstruction::Kembali],
        "ldr" => {
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
        "str" => {
            if operands.len() == 2 {
                let src_expr = petakanOperandKeEkspresiSsaAarch64(&operands[0], cs);
                if let Arm64OperandType::Mem(mem_op) = operands[1].op_type {
                    let addr_expr = petakanAlamatMemoriAarch64(&mem_op, cs);
                    vec![MicroInstruction::SimpanMemori(
                        addr_expr,
                        src_expr,
                    )]
                } else {
                    vec![MicroInstruction::TidakTerdefinisi]
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
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
            vec![MicroInstruction::TidakTerdefinisi]
        }
        ArsitekturDisasm::ARCH_MIPS_32 | ArsitekturDisasm::ARCH_MIPS_64 => {
            vec![MicroInstruction::TidakTerdefinisi]
        }
        _ => vec![MicroInstruction::TidakTerdefinisi],
    }
}