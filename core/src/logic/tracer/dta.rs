//! Author: [Seclususs](https://github.com/seclususs)

use std::collections::{HashMap, HashSet};
use petgraph::graph::{DiGraph, NodeIndex};
use serde::Serialize;

use crate::logic::ir::instruction::{
    MicroBinOp, MicroExpr, MicroInstruction, MicroOperand, SsaVariabel,
};
use crate::logic::ir::lifter::lift_blok_instr;
use crate::logic::tracer::platform::PlatformTracer;
use crate::logic::tracer::types::{u64, C_Registers};
use crate::error::ReToolsError;
use crate::logic::static_analysis::disasm::ArsitekturDisasm;
use crate::logic::static_analysis::cfg::BasicBlock;

#[derive(Debug, Clone, Default)]
pub struct TaintState {
    pub register_taint: HashMap<String, bool>,
    pub memory_taint: HashMap<u64, bool>,
}

#[derive(Debug, Clone)]
pub enum TaintSourceType {
    NetworkPacket,
    FileRead,
    FunctionArgument(usize), 
    EnvironmentVariable,
    UserBuffer(u64, usize),
}

#[derive(Debug, Clone)]
pub struct TaintSource {
    pub kind_source: TaintSourceType,
    pub desc_info: String,
}

#[derive(Debug, Clone)]
pub struct TaintSink {
    pub alamat: u64,
    pub nama: String,
    pub cek_arg_regs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DtaReport {
    pub va: u64,
    pub instruksi_str: String,
    pub pesan: String,
    pub static_block_id: Option<usize>, 
}

pub struct StaticTaintMapper<'a> {
    pub cfg: Option<&'a DiGraph<BasicBlock, &'static str>>,
    pub tainted_blocks: HashSet<NodeIndex>,
}

pub struct DtaEngine<'a> {
    pub tracer: &'a mut Box<dyn PlatformTracer + Send + Sync>,
    pub taint_state: TaintState,
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
    pub laporan_forensik: Vec<DtaReport>,
    pub static_mapper: StaticTaintMapper<'a>,
    arsitektur: ArsitekturDisasm,
}

impl<'a> DtaEngine<'a> {
    pub fn new(
        tracer: &'a mut Box<dyn PlatformTracer + Send + Sync>,
        arsitektur: ArsitekturDisasm,
    ) -> Self {
        DtaEngine {
            tracer,
            taint_state: TaintState::default(),
            sources: Vec::new(),
            sinks: Vec::new(),
            laporan_forensik: Vec::new(),
            static_mapper: StaticTaintMapper {
                cfg: None,
                tainted_blocks: HashSet::new(),
            },
            arsitektur,
        }
    }
    pub fn attach_static_cfg(&mut self, cfg: &'a DiGraph<BasicBlock, &'static str>) {
        self.static_mapper.cfg = Some(cfg);
    }
    pub fn add_source_external(&mut self, kind_source: TaintSourceType, desc_info: &str) {
        self.sources.push(TaintSource {
            kind_source,
            desc_info: desc_info.to_string(),
        });
    }
    pub fn add_sink(&mut self, sink: TaintSink) {
        self.sinks.push(sink);
    }
    pub fn inject_taint_mem(&mut self, va_mulai: u64, sz_region: usize, label_info: &str) {
        for i in 0..sz_region {
            self.taint_state.memory_taint.insert(va_mulai + i as u64, true);
        }
        self.laporan_forensik.push(DtaReport {
            va: va_mulai,
            instruksi_str: "Manual Injection".to_string(),
            pesan: format!("Inject taint pada 0x{:x} (len: {}) [{}]", va_mulai, sz_region, label_info),
            static_block_id: None,
        });
    }
    pub fn process_source_init(&mut self, regs: &C_Registers) {
        let sources = std::mem::take(&mut self.sources);
        for source in &sources {
            match &source.kind_source {
                TaintSourceType::FunctionArgument(idx) => {
                    let nama_reg = self.get_nama_reg_arg(*idx);
                    if let Some(r) = nama_reg {
                         self.taint_state.register_taint.insert(r.to_string(), true);
                         self.laporan_forensik.push(DtaReport {
                             va: regs.rip,
                             instruksi_str: "Source Init".to_string(),
                             pesan: format!("Argumen fungsi #{} ({}) ditandai tainted", idx, r),
                             static_block_id: None,
                         });
                    }
                }
                TaintSourceType::UserBuffer(va_buf, sz_buf) => {
                    self.inject_taint_mem(*va_buf, *sz_buf, &source.desc_info);
                }
                _ => {}
            }
        }
        self.sources = sources;
    }
    fn get_nama_reg_arg(&self, index: usize) -> Option<&'static str> {
        match self.arsitektur {
            ArsitekturDisasm::ARCH_X86_64 => match index {
                0 => Some("rdi"),
                1 => Some("rsi"),
                2 => Some("rdx"),
                3 => Some("rcx"),
                4 => Some("r8"),
                5 => Some("r9"),
                _ => None,
            },
            ArsitekturDisasm::ARCH_ARM_64 => match index {
                0 => Some("x0"),
                1 => Some("x1"),
                2 => Some("x2"),
                3 => Some("x3"),
                _ => None,
            },
            _ => None, 
        }
    }
    fn map_runtime_to_static(&mut self, va_runtime: u64) -> Option<NodeIndex> {
        if let Some(cfg) = self.static_mapper.cfg {
             for idx_node in cfg.node_indices() {
                 let blok = &cfg[idx_node];
                 if va_runtime >= blok.va_start && va_runtime < blok.va_end {
                     return Some(idx_node);
                 }
             }
        }
        None
    }
    fn read_val_reg(&self, regs: &C_Registers, nama_reg: &str) -> u64 {
        match nama_reg.to_lowercase().as_str() {
            "rax" | "x0" => regs.rax,
            "rbx" | "x1" => regs.rbx,
            "rcx" | "x2" => regs.rcx,
            "rdx" | "x3" => regs.rdx,
            "rsi" | "x4" => regs.rsi,
            "rdi" | "x5" => regs.rdi,
            "rbp" | "fp" => regs.rbp,
            "rsp" | "sp" => regs.rsp,
            "r8" => regs.r8,
            "r9" => regs.r9,
            "r10" => regs.r10,
            "r11" => regs.r11,
            "r12" => regs.r12,
            "r13" => regs.r13,
            "r14" => regs.r14,
            "r15" => regs.r15,
            "rip" | "pc" => regs.rip,
            _ => 0,
        }
    }
    fn check_expr_taint(
        &mut self,
        expr: &MicroExpr,
        regs: &C_Registers,
        node_static_kini: Option<NodeIndex>,
    ) -> (bool, Option<u64>) {
        let expr = expr.clone();
        match &expr {
            MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { id_reg: nama_dasar, .. })) => {
                let tainted = self
                    .taint_state
                    .register_taint
                    .get(nama_dasar)
                    .cloned()
                    .unwrap_or(false);
                let nilai = self.read_val_reg(regs, nama_dasar);
                (tainted, Some(nilai))
            }
            MicroExpr::Operand(MicroOperand::Konstanta(k)) => (false, Some(*k)),
            MicroExpr::UnaryOp(_, inner) => self.check_expr_taint(inner, regs, node_static_kini),
            MicroExpr::BinaryOp(op, kiri, kanan) => {
                let (l_taint, l_val) = self.check_expr_taint(kiri, regs, node_static_kini);
                let (r_taint, r_val) = self.check_expr_taint(kanan, regs, node_static_kini);
                let res_val = if let (Some(l), Some(r)) = (l_val, r_val) {
                     match op {
                        MicroBinOp::Add => Some(l.wrapping_add(r)),
                        MicroBinOp::Sub => Some(l.wrapping_sub(r)),
                        MicroBinOp::Mul => Some(l.wrapping_mul(r)),
                        MicroBinOp::And => Some(l & r),
                        MicroBinOp::Or => Some(l | r),
                        MicroBinOp::Xor => Some(l ^ r),
                        _ => None,
                    }
                } else {
                    None
                };
                (l_taint || r_taint, res_val)
            }
            MicroExpr::LoadMemori(addr_expr) => {
                let (addr_tainted, addr_val) = self.check_expr_taint(addr_expr, regs, node_static_kini);
                if addr_tainted {
                     self.laporan_forensik.push(DtaReport {
                        va: regs.rip,
                        instruksi_str: "Memory Load".to_string(),
                        pesan: "Tainted pointer dereference detected!".to_string(),
                        static_block_id: node_static_kini.map(|n| n.index()),
                    });
                }
                if let Some(addr) = addr_val {
                    let val_tainted = self.taint_state.memory_taint.get(&addr).cloned().unwrap_or(false);
                    let mem_val = self.tracer.read_memori(addr, 8).ok()
                        .and_then(|b| b.try_into().ok())
                        .map(u64::from_le_bytes);
                    (val_tainted, mem_val)
                } else {
                    (false, None)
                }
            }
            _ => (false, None),
        }
    }
    fn spread_taint_data(
        &mut self,
        ir: &MicroInstruction,
        va: u64,
        regs: &C_Registers,
        instruksi_str: String,
        static_node: Option<NodeIndex>,
    ) {
        match ir {
            MicroInstruction::Assign(dest, src) => {
                let (is_tainted, _) = self.check_expr_taint(src, regs, static_node);
                let old_status = self.taint_state.register_taint.insert(dest.id_reg.clone(), is_tainted).unwrap_or(false);
                
                if is_tainted && !old_status {
                    if let Some(node_idx) = static_node {
                        self.static_mapper.tainted_blocks.insert(node_idx);
                    }
                    self.laporan_forensik.push(DtaReport {
                        va,
                        instruksi_str,
                        pesan: format!("Taint menyebar ke register {}", dest.id_reg),
                        static_block_id: static_node.map(|n| n.index()),
                    });
                }
            }
            MicroInstruction::StoreMemori(addr_expr, val_expr) => {
                let (val_tainted, _) = self.check_expr_taint(val_expr, regs, static_node);
                let (addr_tainted, addr_val) = self.check_expr_taint(addr_expr, regs, static_node);
                if addr_tainted {
                     self.laporan_forensik.push(DtaReport {
                        va,
                        instruksi_str: instruksi_str.clone(),
                        pesan: "Write to Tainted Address (Arbitrary Write Potential)".to_string(),
                        static_block_id: static_node.map(|n| n.index()),
                    });
                }
                if let Some(addr) = addr_val {
                     if val_tainted {
                         self.taint_state.memory_taint.insert(addr, true);
                         if let Some(node_idx) = static_node {
                            self.static_mapper.tainted_blocks.insert(node_idx);
                         }
                     } else {
                         self.taint_state.memory_taint.remove(&addr);
                     }
                }
            }
            MicroInstruction::JumpKondisi(cond, _) => {
                 let (cond_tainted, _) = self.check_expr_taint(cond, regs, static_node);
                 if cond_tainted {
                      self.laporan_forensik.push(DtaReport {
                        va,
                        instruksi_str,
                        pesan: "Tainted Branch Condition (Control Flow Hijack Risk)".to_string(),
                        static_block_id: static_node.map(|n| n.index()),
                    });
                 }
            }
            MicroInstruction::Jump(target) | MicroInstruction::Call(target) => {
                let (target_tainted, _) = self.check_expr_taint(target, regs, static_node);
                if target_tainted {
                     self.laporan_forensik.push(DtaReport {
                        va,
                        instruksi_str,
                        pesan: "Tainted Jump/Call Target (ROP/Hijack Risk)".to_string(),
                        static_block_id: static_node.map(|n| n.index()),
                    });
                }
            }
            _ => {}
        }
    }
    fn check_sink_safe(&mut self, va: u64, _regs: &C_Registers, static_node: Option<NodeIndex>) {
        for sink in &self.sinks {
            if sink.alamat == va {
                for reg in &sink.cek_arg_regs {
                    if *self.taint_state.register_taint.get(reg).unwrap_or(&false) {
                         self.laporan_forensik.push(DtaReport {
                            va,
                            instruksi_str: "Sink Check".to_string(),
                            pesan: format!("VULNERABILITY: Data tainted mencapai sink '{}' via register {}", sink.nama, reg),
                            static_block_id: static_node.map(|n| n.index()),
                        });
                    }
                }
            }
        }
    }
    pub fn step_and_analyze(&mut self, regs: &C_Registers) -> Result<(), ReToolsError> {
        let va = regs.rip;
        let static_node = self.map_runtime_to_static(va);
        let bytes = self.tracer.read_memori(va, 16)?;
        let (_, irs) = lift_blok_instr(&bytes, va, self.arsitektur)?;
        self.check_sink_safe(va, regs, static_node);
        for ir in irs {
            let instr_debug = format!("{:?}", ir);
            self.spread_taint_data(&ir, va, regs, instr_debug, static_node);
        }
        Ok(())
    }
}