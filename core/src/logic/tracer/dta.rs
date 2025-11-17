//! Author: [Seclususs](https://github.com/seclususs)

use std::collections::HashMap;

use crate::logic::ir::instruction::{
    MicroBinOp, MicroExpr, MicroInstruction, MicroOperand, SsaVariabel,
};
use crate::logic::ir::lifter::angkat_blok_instruksi;
use crate::logic::tracer::platform::PlatformTracer;
use crate::logic::tracer::types::{u64, C_Registers};
use crate::error::ReToolsError;
use crate::logic::static_analysis::disasm::ArsitekturDisasm;

#[derive(Debug, Clone, Default)]
pub struct TaintState {
    pub register_taint: HashMap<String, bool>,
    pub memory_taint: HashMap<u64, bool>,
}

#[derive(Debug, Clone)]
pub struct TaintSource {
    pub alamat: u64,
    pub ukuran: usize,
    pub nama: String,
}

#[derive(Debug, Clone)]
pub struct TaintSink {
    pub alamat: u64,
    pub nama: String,
    pub cek_arg_regs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DtaReport {
    pub va: u64,
    pub instruksi_str: String,
    pub pesan: String,
}

pub struct DtaEngine<'a> {
    pub tracer: &'a mut Box<dyn PlatformTracer + Send + Sync>,
    pub taint_state: TaintState,
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
    pub laporan_forensik: Vec<DtaReport>,
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
            arsitektur,
        }
    }
    pub fn tambah_source(&mut self, source: TaintSource) {
        self.sources.push(source);
    }
    pub fn tambah_sink(&mut self, sink: TaintSink) {
        self.sinks.push(sink);
    }
    pub fn inisialisasi_sources(&mut self) -> Result<(), ReToolsError> {
        for source in self.sources.iter() {
            for i in 0..source.ukuran {
                let alamat_mem = source.alamat + i as u64;
                self.taint_state.memory_taint.insert(alamat_mem, true);
            }
            self.laporan_forensik.push(DtaReport {
                va: source.alamat,
                instruksi_str: "Taint Source".to_string(),
                pesan: format!(
                    "Menandai (mark) memory di 0x{:x} (size: {}) sebagai tainted from '{}'",
                    source.alamat, source.ukuran, source.nama
                ),
            });
        }
        Ok(())
    }
    fn ambil_nilai_register(&self, regs: &C_Registers, nama_reg: &str) -> u64 {
        match nama_reg.to_lowercase().as_str() {
            "rax" => regs.rax,
            "rbx" => regs.rbx,
            "rcx" => regs.rcx,
            "rdx" => regs.rdx,
            "rsi" => regs.rsi,
            "rdi" => regs.rdi,
            "rbp" => regs.rbp,
            "rsp" => regs.rsp,
            "r8" => regs.r8,
            "r9" => regs.r9,
            "r10" => regs.r10,
            "r11" => regs.r11,
            "r12" => regs.r12,
            "r13" => regs.r13,
            "r14" => regs.r14,
            "r15" => regs.r15,
            "rip" => regs.rip,
            _ => 0,
        }
    }
    fn cek_ekspresi_taint(
        &mut self,
        expr: &MicroExpr,
        regs: &C_Registers,
    ) -> (bool, Option<u64>) {
        match expr {
            MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { nama_dasar, .. })) => {
                let tainted = self
                    .taint_state
                    .register_taint
                    .get(nama_dasar)
                    .cloned()
                    .unwrap_or(false);
                let value = self.ambil_nilai_register(regs, nama_dasar);
                (tainted, Some(value))
            }
            MicroExpr::Operand(MicroOperand::Konstanta(k)) => (false, Some(*k)),
            MicroExpr::OperasiUnary(_, inner) => self.cek_ekspresi_taint(inner, regs),
            MicroExpr::OperasiBiner(op, left, right) => {
                let (left_tainted, left_val_opt) = self.cek_ekspresi_taint(left, regs);
                let (right_tainted, right_val_opt) = self.cek_ekspresi_taint(right, regs);
                let result_tainted = left_tainted || right_tainted;
                let result_val = if let (Some(l), Some(r)) = (left_val_opt, right_val_opt) {
                    match op {
                        MicroBinOp::Add => Some(l.wrapping_add(r)),
                        MicroBinOp::Sub => Some(l.wrapping_sub(r)),
                        MicroBinOp::Mul => Some(l.wrapping_mul(r)),
                        MicroBinOp::Div => Some(l.wrapping_div(r)),
                        MicroBinOp::And => Some(l & r),
                        MicroBinOp::Or => Some(l | r),
                        MicroBinOp::Xor => Some(l ^ r),
                        _ => None,
                    }
                } else {
                    None
                };
                (result_tainted, result_val)
            }
            MicroExpr::MuatMemori(addr_expr) => {
                let (addr_tainted, addr_val_opt) = self.cek_ekspresi_taint(addr_expr, regs);
                if addr_tainted {
                    self.laporan_forensik.push(DtaReport {
                        va: regs.rip,
                        instruksi_str: "Memory Load".to_string(),
                        pesan: "Alamat akses memory (pointer) adalah tainted.".to_string(),
                    });
                }
                if let Some(addr) = addr_val_opt {
                    let mem_tainted = self
                        .taint_state
                        .memory_taint
                        .get(&addr)
                        .cloned()
                        .unwrap_or(false);
                    let val_bytes = self.tracer.baca_memory(addr, 8).unwrap_or(vec![0; 8]);
                    let val = u64::from_le_bytes(val_bytes.try_into().unwrap_or([0; 8]));
                    (mem_tainted, Some(val))
                } else {
                    (false, None)
                }
            }
            MicroExpr::Bandingkan(left, right) | MicroExpr::UjiBit(left, right) => {
                let (left_tainted, _) = self.cek_ekspresi_taint(left, regs);
                let (right_tainted, _) = self.cek_ekspresi_taint(right, regs);
                (left_tainted || right_tainted, Some(0))
            }
        }
    }
    fn propagate_taint(
        &mut self,
        ir: &MicroInstruction,
        va: u64,
        regs: &C_Registers,
        instruksi_str: String,
    ) {
        match ir {
            MicroInstruction::Assign(dest, src_expr) => {
                let (src_tainted, _) = self.cek_ekspresi_taint(src_expr, regs);
                let old_taint = self
                    .taint_state
                    .register_taint
                    .insert(dest.nama_dasar.clone(), src_tainted)
                    .unwrap_or(false);
                if src_tainted && !old_taint {
                    self.laporan_forensik.push(DtaReport {
                        va,
                        instruksi_str,
                        pesan: format!("Taint disebar (propagated) ke register {}", dest.nama_dasar),
                    });
                }
            }
            MicroInstruction::SimpanMemori(addr_expr, data_expr) => {
                let (data_tainted, _) = self.cek_ekspresi_taint(data_expr, regs);
                let (addr_tainted, addr_val_opt) = self.cek_ekspresi_taint(addr_expr, regs);
                if addr_tainted {
                    self.laporan_forensik.push(DtaReport {
                        va,
                        instruksi_str: instruksi_str.clone(),
                        pesan: "Arbitrary Write: Alamat penulisan memori adalah tainted!".to_string(),
                    });
                }
                if let Some(addr) = addr_val_opt {
                    let old_taint = self
                        .taint_state
                        .memory_taint
                        .insert(addr, data_tainted)
                        .unwrap_or(false);
                    if data_tainted && !old_taint {
                        self.laporan_forensik.push(DtaReport {
                            va,
                            instruksi_str,
                            pesan: format!("Data tainted ditulis ke alamat memori 0x{:x}", addr),
                        });
                    }
                }
            }
            MicroInstruction::LompatKondisi(cond_expr, _) => {
                let (cond_tainted, _) = self.cek_ekspresi_taint(cond_expr, regs);
                if cond_tainted {
                    self.laporan_forensik.push(DtaReport {
                        va,
                        instruksi_str,
                        pesan: "Control-Flow Hijack: Lompatan kondisional (conditional jump) bergantung pada data tainted.".to_string(),
                    });
                }
            }
            MicroInstruction::Lompat(target_expr) | MicroInstruction::Panggil(target_expr) => {
                let (target_tainted, _) = self.cek_ekspresi_taint(target_expr, regs);
                if target_tainted {
                    self.laporan_forensik.push(DtaReport {
                        va,
                        instruksi_str,
                        pesan: "Control-Flow Hijack: Target lompatan (jump/call) adalah tainted.".to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    fn cek_sinks(&mut self, va: u64, _regs: &C_Registers, instruksi_str: String) {
        for sink in self.sinks.iter() {
            if sink.alamat == va {
                for reg_nama in &sink.cek_arg_regs {
                    let tainted = self
                        .taint_state
                        .register_taint
                        .get(reg_nama)
                        .cloned()
                        .unwrap_or(false);
                    if tainted {
                        self.laporan_forensik.push(DtaReport {
                            va,
                            instruksi_str: instruksi_str.clone(),
                            pesan: format!(
                                "!!! VULNERABILITY DETECTED !!!\n    Data Tainted mencapai sink '{}' (0x{:x}) melalui register argumen {}.",
                                sink.nama, sink.alamat, reg_nama
                            ),
                        });
                    }
                }
            }
        }
    }
    pub fn proses_event_step(&mut self, regs: &C_Registers) -> Result<(), ReToolsError> {
        let va = regs.rip;
        let bytes_instruksi = self.tracer.baca_memory(va, 16)?;
        let (size, irs) =
            angkat_blok_instruksi(&bytes_instruksi, va, self.arsitektur)?;
        if size == 0 {
            return Err(ReToolsError::Generic(format!("Gagal mengangkat IR pada 0x{:x}", va)));
        }
        let instruksi_str = format!("0x{:x}: [IRs: {}]", va, irs.len());
        self.cek_sinks(va, regs, instruksi_str.clone());
        for ir in irs {
            self.propagate_taint(&ir, va, regs, instruksi_str.clone());
        }
        Ok(())
    }
}