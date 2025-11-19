//! Author: [Seclususs](https://github.com/seclususs)

use crate::error::ReToolsError;
use crate::logic::data_flow::vsa::{analyze_set_nilai, VsaState};
use crate::logic::ir::instruction::{MicroBinOp, MicroExpr, MicroInstruction, MicroOperand};
use crate::logic::ir::lifter::lift_blok_instr;
use crate::logic::static_analysis::cfg::{build_cfg_internal, BasicBlock};
use crate::logic::static_analysis::disasm::ArsitekturDisasm;
use crate::logic::static_analysis::parser::Binary;
use crate::logic::tracer;
use crate::logic::tracer::types::C_Registers;
use log::{debug, info};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet};

pub struct SmartAnalysisResult {
    pub cfg: DiGraph<BasicBlock, &'static str>,
    pub vsa_results: HashMap<NodeIndex, (VsaState, VsaState)>,
    pub dynamic_coverage: usize,
    pub iteration_count: usize,
}

pub struct SmartAnalyzer {
    biner: Binary,
    peta_target_dinamis: HashMap<u64, u64>,
    peta_nilai_konkret: HashMap<u64, HashMap<String, u64>>,
    set_va_terkunjungi: HashSet<u64>,
}

impl SmartAnalyzer {
    pub fn new(path_berkas: &str) -> Result<Self, ReToolsError> {
        let biner = Binary::load(path_berkas)?;
        Ok(SmartAnalyzer {
            biner,
            peta_target_dinamis: HashMap::new(),
            peta_nilai_konkret: HashMap::new(),
            set_va_terkunjungi: HashSet::new(),
        })
    }
    pub fn run_smart_analysis(&mut self, pid: i32, max_steps: usize) -> Result<SmartAnalysisResult, ReToolsError> {
        info!("Memulai Smart Analysis pada PID {}", pid);
        self.record_trace_and_resolve(pid, max_steps)?;
        let total_coverage = self.peta_target_dinamis.len();
        info!("Trace selesai. Ditemukan {} target dinamis unik.", total_coverage);
        info!("Membangun ulang CFG final...");
        let cfg = build_cfg_internal(&self.biner, Some(&self.peta_target_dinamis))?;
        info!("Menjalankan VSA final dengan {} hint blok...", self.peta_nilai_konkret.len());
        let vsa_results = analyze_set_nilai(&cfg, &self.biner, Some(&self.peta_nilai_konkret));
        Ok(SmartAnalysisResult {
            cfg,
            vsa_results,
            dynamic_coverage: total_coverage,
            iteration_count: 1, 
        })
    }
    fn record_trace_and_resolve(&mut self, pid: i32, max_steps: usize) -> Result<(), ReToolsError> {
        let mut debugger = tracer::new_debugger(pid)?;
        let arch = self.biner.header.get_disasm_arch();
        info!("Tracer terpasang. Melakukan stepping {} instruksi...", max_steps);
        for step in 0..max_steps {
            let regs = match debugger.get_register() {
                Ok(r) => r,
                Err(_) => break,
            };
            let va_kini = regs.rip;
            self.set_va_terkunjungi.insert(va_kini);
            let bytes_instr = match debugger.read_memori(va_kini, 16) {
                Ok(b) => b,
                Err(_) => break, 
            };
            if let Ok((_, irs)) = lift_blok_instr(&bytes_instr, va_kini, arch) {
                for ir in irs {
                    match ir {
                        MicroInstruction::Jump(expr) | MicroInstruction::Call(expr) => {
                            if !self.is_static_target(&expr) {
                                if let Some(va_target) = self.eval_runtime_expr(&expr, &regs, &mut *debugger) {
                                    if !self.peta_target_dinamis.contains_key(&va_kini) {
                                        debug!("Resolved Dynamic Jump [Step {}]: 0x{:x} -> 0x{:x}", step, va_kini, va_target);
                                        self.peta_target_dinamis.insert(va_kini, va_target);
                                        self.snapshot_registers(va_kini, &regs, arch);
                                    }
                                } else {
                                    debug!("Gagal resolve dynamic jump di 0x{:x}", va_kini);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            if let Err(_) = debugger.step_instruksi() {
                break;
            }
        }
        Ok(())
    }
    fn is_static_target(&self, expr: &MicroExpr) -> bool {
        matches!(expr, MicroExpr::Operand(MicroOperand::Konstanta(_)))
    }
    fn eval_runtime_expr(
        &self, 
        expr: &MicroExpr, 
        regs: &C_Registers, 
        debugger: &mut dyn crate::logic::tracer::platform::PlatformTracer
    ) -> Option<u64> {
        match expr {
            MicroExpr::Operand(MicroOperand::Konstanta(k)) => Some(*k),
            MicroExpr::Operand(MicroOperand::SsaVar(v)) => {
                Some(self.read_reg_val(regs, &v.id_reg))
            },
            MicroExpr::BinaryOp(op, left, right) => {
                let val_l = self.eval_runtime_expr(left, regs, debugger)?;
                let val_r = self.eval_runtime_expr(right, regs, debugger)?;
                match op {
                    MicroBinOp::Add => Some(val_l.wrapping_add(val_r)),
                    MicroBinOp::Sub => Some(val_l.wrapping_sub(val_r)),
                    MicroBinOp::Mul => Some(val_l.wrapping_mul(val_r)),
                    MicroBinOp::Div => if val_r != 0 { Some(val_l.wrapping_div(val_r)) } else { None },
                    MicroBinOp::And => Some(val_l & val_r),
                    MicroBinOp::Or => Some(val_l | val_r),
                    MicroBinOp::Xor => Some(val_l ^ val_r),
                    MicroBinOp::Shl => Some(val_l << (val_r as u32)),
                    MicroBinOp::Shr => Some(val_l >> (val_r as u32)),
                    _ => None
                }
            },
            MicroExpr::LoadMemori(addr_expr) => {
                let addr_mem = self.eval_runtime_expr(addr_expr, regs, debugger)?;
                match debugger.read_memori(addr_mem, 8) {
                    Ok(bytes) if bytes.len() == 8 => {
                         let ptr_val = u64::from_le_bytes(bytes.try_into().unwrap());
                         Some(ptr_val)
                    },
                    Ok(bytes) if bytes.len() == 4 => {
                         let ptr_val = u32::from_le_bytes(bytes.try_into().unwrap()) as u64;
                         Some(ptr_val)
                    }
                    _ => None
                }
            },
            _ => None
        }
    }
    fn read_reg_val(&self, regs: &C_Registers, reg_name: &str) -> u64 {
        let nama_lower = reg_name.to_lowercase();
        match nama_lower.as_str() {
            "rax" | "eax" | "ax" | "al" | "x0" => regs.rax,
            "rbx" | "ebx" | "bx" | "bl" | "x1" => regs.rbx,
            "rcx" | "ecx" | "cx" | "cl" | "x2" => regs.rcx,
            "rdx" | "edx" | "dx" | "dl" | "x3" => regs.rdx,
            "rdi" | "edi" | "di" | "dil" | "x4" => regs.rdi,
            "rsi" | "esi" | "si" | "sil" | "x5" => regs.rsi,
            "rbp" | "ebp" | "bp" | "bpl" | "fp" | "x29" => regs.rbp,
            "rsp" | "esp" | "sp" | "spl" | "x31" => regs.rsp,
            "r8" | "r8d" | "r8w" | "r8b" => regs.r8,
            "r9" | "r9d" | "r9w" | "r9b" => regs.r9,
            "r10" | "r10d" => regs.r10,
            "r11" | "r11d" => regs.r11,
            "r12" | "r12d" => regs.r12,
            "r13" | "r13d" => regs.r13,
            "r14" | "r14d" => regs.r14,
            "r15" | "r15d" => regs.r15,
            "rip" | "eip" | "pc" => regs.rip,
            _ => 0
        }
    }
    fn snapshot_registers(&mut self, va: u64, regs: &C_Registers, arch: ArsitekturDisasm) {
        let mut map_regs = HashMap::new();
        match arch {
            ArsitekturDisasm::ARCH_X86_64 => {
                map_regs.insert("rax".to_string(), regs.rax);
                map_regs.insert("rbx".to_string(), regs.rbx);
                map_regs.insert("rcx".to_string(), regs.rcx);
                map_regs.insert("rdx".to_string(), regs.rdx);
                map_regs.insert("rsi".to_string(), regs.rsi);
                map_regs.insert("rdi".to_string(), regs.rdi);
                map_regs.insert("rbp".to_string(), regs.rbp);
                map_regs.insert("rsp".to_string(), regs.rsp);
                map_regs.insert("r8".to_string(), regs.r8);
                map_regs.insert("r9".to_string(), regs.r9);
                map_regs.insert("r10".to_string(), regs.r10);
                map_regs.insert("r11".to_string(), regs.r11);
                map_regs.insert("r12".to_string(), regs.r12);
                map_regs.insert("r13".to_string(), regs.r13);
                map_regs.insert("r14".to_string(), regs.r14);
                map_regs.insert("r15".to_string(), regs.r15);
            },
            ArsitekturDisasm::ARCH_ARM_64 => {
                map_regs.insert("x0".to_string(), regs.rax);
                map_regs.insert("x1".to_string(), regs.rbx);
                map_regs.insert("x2".to_string(), regs.rcx);
                map_regs.insert("x3".to_string(), regs.rdx);
                map_regs.insert("x4".to_string(), regs.rdi);
                map_regs.insert("x5".to_string(), regs.rsi);
                map_regs.insert("fp".to_string(), regs.rbp);
                map_regs.insert("sp".to_string(), regs.rsp);
            },
            _ => {
                map_regs.insert("rax".to_string(), regs.rax);
            }
        }
        self.peta_nilai_konkret.insert(va, map_regs);
    }
}