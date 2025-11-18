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
    mips::{MipsInsnDetail, MipsOpMem, MipsOperand},
    riscv::{RiscVInsnDetail, RiscVOpMem, RiscVOperand},
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
fn petakanOperandKeEkspresiSsaX86(op: &X86Operand, cs: &Capstone) -> MicroExpr {
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
        },
        X86OperandType::Imm(val) => MicroOperand::Konstanta(val as u64),
        _ => MicroOperand::Konstanta(0),
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
        ($op:expr) => {{
            let mut instrs = Vec::new();
            let mut dest_var_opt: Option<SsaVariabel> = None;
            if operands.len() == 2 {
                let dest_op = &operands[0];
                let src_expr = petakanOperandKeEkspresiSsaX86(&operands[1], cs);
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
        "mov" | "movsx" | "movzx" | "movaps" | "movsd" | "movss" | "movdqa" | "movdqu" => {
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
                    let instr2 =
                        MicroInstruction::Assign(dest_var, MicroExpr::Operand(MicroOperand::SsaVar(t1)));
                    let t2 = buatSsaVariabel("t_stack_adj".to_string());
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
        "add" => {
            let (mut base_instrs, dest_var_opt) = angkatOperasiBiner!(MicroBinOp::Add);
            if let Some(dest_var) = dest_var_opt {
                let flags_var = buatSsaVariabel("EFLAGS".to_string());
                let flags_expr = MicroExpr::Bandingkan(
                    Box::new(MicroExpr::Operand(MicroOperand::SsaVar(dest_var))),
                    Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))),
                );
                base_instrs.push(MicroInstruction::Assign(flags_var, flags_expr));
            }
            base_instrs
        }
        "sub" => {
            let (mut base_instrs, dest_var_opt) = angkatOperasiBiner!(MicroBinOp::Sub);
            if let Some(dest_var) = dest_var_opt {
                let flags_var = buatSsaVariabel("EFLAGS".to_string());
                let flags_expr = MicroExpr::Bandingkan(
                    Box::new(MicroExpr::Operand(MicroOperand::SsaVar(dest_var))),
                    Box::new(MicroExpr::Operand(MicroOperand::Konstanta(0))),
                );
                base_instrs.push(MicroInstruction::Assign(flags_var, flags_expr));
            }
            base_instrs
        }
        "fadd" | "addss" | "addsd" => {
             let (base_instrs, _) = angkatOperasiBiner!(MicroBinOp::TambahFloat);
             base_instrs
        }
        "fsub" | "subss" | "subsd" => {
             let (base_instrs, _) = angkatOperasiBiner!(MicroBinOp::KurangFloat);
             base_instrs
        }
        "fmul" | "mulss" | "mulsd" => {
             let (base_instrs, _) = angkatOperasiBiner!(MicroBinOp::KaliFloat);
             base_instrs
        }
        "fdiv" | "divss" | "divsd" => {
             let (base_instrs, _) = angkatOperasiBiner!(MicroBinOp::BagiFloat);
             base_instrs
        }
        "and" => angkatOperasiBiner!(MicroBinOp::And).0,
        "or" => angkatOperasiBiner!(MicroBinOp::Or).0,
        "xor" => angkatOperasiBiner!(MicroBinOp::Xor).0,
        "pxor" | "xorps" | "xorpd" | "vpxor" => {
            let mut op_vec = Vec::new();
            for op in &operands {
                op_vec.push(petakanOperandKeMicroOperandX86(op, cs));
            }
            vec![MicroInstruction::InstruksiVektor("pxor".to_string(), op_vec)]
        }
        "paddb" | "paddw" | "paddd" | "paddq" | "vaddps" | "vaddpd" | "addps" | "addpd" => {
             let mut op_vec = Vec::new();
            for op in &operands {
                op_vec.push(petakanOperandKeMicroOperandX86(op, cs));
            }
            vec![MicroInstruction::InstruksiVektor("vector_add".to_string(), op_vec)]
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
        "cmp" | "ucomiss" | "ucomisd" => {
            if operands.len() == 2 {
                let op1 = petakanOperandKeEkspresiSsaX86(&operands[0], cs);
                let op2 = petakanOperandKeEkspresiSsaX86(&operands[1], cs);
                let flags_var = buatSsaVariabel("EFLAGS".to_string());
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
                let op1 = petakanOperandKeEkspresiSsaX86(&operands[0], cs);
                let op2 = petakanOperandKeEkspresiSsaX86(&operands[1], cs);
                let flags_var = buatSsaVariabel("EFLAGS".to_string());
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
                vec![MicroInstruction::Lompat(petakanOperandKeEkspresiSsaX86(
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
                let flags_var = buatSsaVariabel("EFLAGS".to_string());
                let cond_expr = MicroExpr::Operand(MicroOperand::SsaVar(flags_var));
                let target_expr = petakanOperandKeEkspresiSsaX86(&operands[0], cs);
                vec![MicroInstruction::LompatKondisi(cond_expr, target_expr)]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
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
        "rdtsc" => {
            let eax = buatSsaVariabel("eax".to_string());
            let edx = buatSsaVariabel("edx".to_string());
            let tsc = buatSsaVariabel("TSC".to_string()); 
            vec![
                MicroInstruction::Assign(eax, MicroExpr::Operand(MicroOperand::SsaVar(tsc.clone()))),
                MicroInstruction::Assign(edx, MicroExpr::Operand(MicroOperand::SsaVar(tsc))),
            ]
        },
        "cpuid" => {
             let eax = buatSsaVariabel("eax".to_string());
             let ebx = buatSsaVariabel("ebx".to_string());
             let ecx = buatSsaVariabel("ecx".to_string());
             let edx = buatSsaVariabel("edx".to_string());
             let cpuid_src = buatSsaVariabel("CPUID_RESULT".to_string());
             vec![
                 MicroInstruction::Assign(eax, MicroExpr::Operand(MicroOperand::SsaVar(cpuid_src.clone()))),
                 MicroInstruction::Assign(ebx, MicroExpr::Operand(MicroOperand::SsaVar(cpuid_src.clone()))),
                 MicroInstruction::Assign(ecx, MicroExpr::Operand(MicroOperand::SsaVar(cpuid_src.clone()))),
                 MicroInstruction::Assign(edx, MicroExpr::Operand(MicroOperand::SsaVar(cpuid_src))),
             ]
        },
        "cli" | "sti" | "cld" | "std" => vec![MicroInstruction::Nop], 
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
                        vec![MicroInstruction::InstruksiVektor("vector_add".to_string(), op_vec)]
                     } else {
                         vec![MicroInstruction::TidakTerdefinisi]
                     }
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "sub" | "fsub" => {
            if operands.len() == 3 {
                if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                    let src2_expr = petakanOperandKeEkspresiSsaAarch64(&operands[2], cs);
                    let op = if mnem == "fsub" { MicroBinOp::KurangFloat } else { MicroBinOp::Sub };
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
                        vec![MicroInstruction::InstruksiVektor("vector_sub".to_string(), op_vec)]
                     } else {
                        vec![MicroInstruction::TidakTerdefinisi]
                     }
                }
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "mul" | "fmul" => {
             if operands.len() == 3 {
                if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                    let src2_expr = petakanOperandKeEkspresiSsaAarch64(&operands[2], cs);
                    let op = if mnem == "fmul" { MicroBinOp::KaliFloat } else { MicroBinOp::Mul };
                    vec![MicroInstruction::Assign(
                        dest_var,
                        MicroExpr::OperasiBiner(
                            op,
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
        "udiv" | "sdiv" | "fdiv" => {
             if operands.len() == 3 {
                if let Arm64OperandType::Reg(reg_id) = operands[0].op_type {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1_expr = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                    let src2_expr = petakanOperandKeEkspresiSsaAarch64(&operands[2], cs);
                    let op = if mnem == "fdiv" { MicroBinOp::BagiFloat } else { MicroBinOp::Div };
                    vec![MicroInstruction::Assign(
                        dest_var,
                        MicroExpr::OperasiBiner(
                            op,
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
        "cmp" | "fcmp" => {
            if operands.len() == 2 {
                let op1 = petakanOperandKeEkspresiSsaAarch64(&operands[0], cs);
                let op2 = petakanOperandKeEkspresiSsaAarch64(&operands[1], cs);
                let flags_var = buatSsaVariabel("NZCV".to_string());
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
        "b.eq" | "b.ne" | "b.cs" | "b.hs" | "b.cc" | "b.lo" | "b.mi" | "b.pl" | "b.vs" | "b.vc" | "b.hi" | "b.ls" | "b.ge" | "b.lt" | "b.gt" | "b.le" => {
             if operands.len() == 1 {
                let flags_var = buatSsaVariabel("NZCV".to_string());
                let cond_expr = MicroExpr::Operand(MicroOperand::SsaVar(flags_var));
                let target_expr = petakanOperandKeEkspresiSsaAarch64(&operands[0], cs);
                vec![MicroInstruction::LompatKondisi(cond_expr, target_expr)]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        }
        "bl" | "blr" => {
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
        "svc" | "hvc" | "smc" => vec![MicroInstruction::Syscall],
        "mrs" | "msr" => vec![MicroInstruction::Nop], // Privilege Access
        _ => vec![MicroInstruction::TidakTerdefinisi],
    }
}

#[allow(non_snake_case)]
fn petakanAlamatMemoriMips(mem_op: &MipsOpMem, cs: &Capstone) -> MicroExpr {
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
fn petakanOperandKeEkspresiSsaMips(op: &MipsOperand, cs: &Capstone) -> MicroExpr {
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
        "and" | "andi" => {
             if operands.len() == 3 {
                if let MipsOperand::Reg(reg_id) = operands[0] {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1 = petakanOperandKeEkspresiSsaMips(&operands[1], cs);
                    let src2 = petakanOperandKeEkspresiSsaMips(&operands[2], cs);
                    vec![MicroInstruction::Assign(
                        dest_var,
                        MicroExpr::OperasiBiner(MicroBinOp::And, Box::new(src1), Box::new(src2))
                    )]
                } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "or" | "ori" => {
             if operands.len() == 3 {
                if let MipsOperand::Reg(reg_id) = operands[0] {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1 = petakanOperandKeEkspresiSsaMips(&operands[1], cs);
                    let src2 = petakanOperandKeEkspresiSsaMips(&operands[2], cs);
                    vec![MicroInstruction::Assign(
                        dest_var,
                        MicroExpr::OperasiBiner(MicroBinOp::Or, Box::new(src1), Box::new(src2))
                    )]
                } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "xor" | "xori" => {
             if operands.len() == 3 {
                if let MipsOperand::Reg(reg_id) = operands[0] {
                    let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                    let src1 = petakanOperandKeEkspresiSsaMips(&operands[1], cs);
                    let src2 = petakanOperandKeEkspresiSsaMips(&operands[2], cs);
                    vec![MicroInstruction::Assign(
                        dest_var,
                        MicroExpr::OperasiBiner(MicroBinOp::Xor, Box::new(src1), Box::new(src2))
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
        "beq" | "bne" | "bgtz" | "blez" => {
             if operands.len() >= 2 {
                 let cond = buatSsaVariabel("COND_BRANCH".to_string());
                 let target = operands.last().unwrap();
                 let target_expr = petakanOperandKeEkspresiSsaMips(target, cs);
                 vec![MicroInstruction::LompatKondisi(MicroExpr::Operand(MicroOperand::SsaVar(cond)), target_expr)]
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "syscall" => vec![MicroInstruction::Syscall],
        "nop" => vec![MicroInstruction::Nop],
        _ => vec![MicroInstruction::TidakTerdefinisi],
    }
}

#[allow(non_snake_case)]
fn petakanAlamatMemoriRiscv(mem_op: &RiscVOpMem, cs: &Capstone) -> MicroExpr {
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
fn petakanOperandKeEkspresiSsaRiscv(op: &RiscVOperand, cs: &Capstone) -> MicroExpr {
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
        "sub" | "subw" => {
             if operands.len() == 3 {
                 if let RiscVOperand::Reg(reg_id) = operands[0] {
                     let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                     let src1 = petakanOperandKeEkspresiSsaRiscv(&operands[1], cs);
                     let src2 = petakanOperandKeEkspresiSsaRiscv(&operands[2], cs);
                     vec![MicroInstruction::Assign(dest_var, MicroExpr::OperasiBiner(MicroBinOp::Sub, Box::new(src1), Box::new(src2)))]
                 } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "and" | "andi" => {
             if operands.len() == 3 {
                 if let RiscVOperand::Reg(reg_id) = operands[0] {
                     let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                     let src1 = petakanOperandKeEkspresiSsaRiscv(&operands[1], cs);
                     let src2 = petakanOperandKeEkspresiSsaRiscv(&operands[2], cs);
                     vec![MicroInstruction::Assign(dest_var, MicroExpr::OperasiBiner(MicroBinOp::And, Box::new(src1), Box::new(src2)))]
                 } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "or" | "ori" => {
             if operands.len() == 3 {
                 if let RiscVOperand::Reg(reg_id) = operands[0] {
                     let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                     let src1 = petakanOperandKeEkspresiSsaRiscv(&operands[1], cs);
                     let src2 = petakanOperandKeEkspresiSsaRiscv(&operands[2], cs);
                     vec![MicroInstruction::Assign(dest_var, MicroExpr::OperasiBiner(MicroBinOp::Or, Box::new(src1), Box::new(src2)))]
                 } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "xor" | "xori" => {
             if operands.len() == 3 {
                 if let RiscVOperand::Reg(reg_id) = operands[0] {
                     let dest_var = buatSsaVariabelDariRegId(reg_id, cs);
                     let src1 = petakanOperandKeEkspresiSsaRiscv(&operands[1], cs);
                     let src2 = petakanOperandKeEkspresiSsaRiscv(&operands[2], cs);
                     vec![MicroInstruction::Assign(dest_var, MicroExpr::OperasiBiner(MicroBinOp::Xor, Box::new(src1), Box::new(src2)))]
                 } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "jal" => {
            if operands.len() >= 1 {
                let target = operands.last().unwrap();
                vec![MicroInstruction::Panggil(petakanOperandKeEkspresiSsaRiscv(target, cs))]
            } else {
                vec![MicroInstruction::TidakTerdefinisi]
            }
        },
        "jalr" => {
             if operands.len() >= 1 {
                 let target = if operands.len() == 2 { &operands[1] } else { &operands[0] };
                 vec![MicroInstruction::Panggil(petakanOperandKeEkspresiSsaRiscv(target, cs))]
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu" => {
             if operands.len() == 3 {
                 let cond = buatSsaVariabel("BRANCH_COND".to_string());
                 let target = &operands[2];
                 vec![MicroInstruction::LompatKondisi(MicroExpr::Operand(MicroOperand::SsaVar(cond)), petakanOperandKeEkspresiSsaRiscv(target, cs))]
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
        "ecall" | "ebreak" => vec![MicroInstruction::Syscall],
        "nop" => vec![MicroInstruction::Nop],
        "mv" => {
             if operands.len() == 2 {
                 if let RiscVOperand::Reg(reg_id) = operands[0] {
                     let dest = buatSsaVariabelDariRegId(reg_id, cs);
                     let src = petakanOperandKeEkspresiSsaRiscv(&operands[1], cs);
                     vec![MicroInstruction::Assign(dest, src)]
                 } else {
                     vec![MicroInstruction::TidakTerdefinisi]
                 }
             } else {
                 vec![MicroInstruction::TidakTerdefinisi]
             }
        },
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