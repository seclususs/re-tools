//! Author: [Seclususs](https://github.com/seclususs)

use crate::logic::ir::instruction::{MicroBinOp, MicroExpr, MicroInstruction, MicroOperand};
use crate::logic::static_analysis::cfg::BasicBlock;
use crate::logic::data_flow::liveness::hitung_analisis_liveness;
use petgraph::graph::DiGraph;
use std::collections::{HashMap, HashSet};

pub struct IrOptimizer {
    changed: bool,
}

impl IrOptimizer {
    pub fn new() -> Self {
        IrOptimizer { changed: false }
    }
    pub fn jalankan_optimasi(&mut self, cfg: &mut DiGraph<BasicBlock, &'static str>) {
        loop {
            self.changed = false;
            self.pass_constant_propagation(cfg);
            self.pass_expression_simplification(cfg);
            self.pass_dead_code_elimination(cfg);
            if !self.changed {
                break;
            }
        }
    }
    fn pass_constant_propagation(&mut self, cfg: &mut DiGraph<BasicBlock, &'static str>) {
        let mut constants_map: HashMap<String, u64> = HashMap::new();
        for node_idx in cfg.node_indices() {
            let block = &cfg[node_idx];
            for (_, instrs) in &block.instructions {
                for instr in instrs {
                    if let MicroInstruction::Assign(dest, expr) = instr {
                        if let MicroExpr::Operand(MicroOperand::Konstanta(val)) = expr {
                            constants_map.insert(dest.nama_dasar.clone(), *val);
                        }
                    }
                }
            }
        }
        if constants_map.is_empty() {
            return;
        }
        for node_idx in cfg.node_indices() {
            let block = &mut cfg[node_idx];
            for (_, instrs) in &mut block.instructions {
                for instr in instrs.iter_mut() {
                    match instr {
                        MicroInstruction::Assign(_, expr) |
                        MicroInstruction::SimpanMemori(expr, _) | 
                        MicroInstruction::Lompat(expr) |
                        MicroInstruction::LompatKondisi(expr, _) |
                        MicroInstruction::Panggil(expr) => {
                            if self.ganti_variabel_dengan_konstanta(expr, &constants_map) {
                                self.changed = true;
                            }
                            if let MicroInstruction::SimpanMemori(_, data) = instr {
                                if self.ganti_variabel_dengan_konstanta(data, &constants_map) {
                                    self.changed = true;
                                }
                            }
                            if let MicroInstruction::LompatKondisi(_, target) = instr {
                                if self.ganti_variabel_dengan_konstanta(target, &constants_map) {
                                    self.changed = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    fn ganti_variabel_dengan_konstanta(&self, expr: &mut MicroExpr, constants: &HashMap<String, u64>) -> bool {
        let mut modified = false;
        match expr {
            MicroExpr::Operand(MicroOperand::SsaVar(var)) => {
                if let Some(val) = constants.get(&var.nama_dasar) {
                    *expr = MicroExpr::Operand(MicroOperand::Konstanta(*val));
                    modified = true;
                }
            }
            MicroExpr::OperasiUnary(_, inner) |
            MicroExpr::MuatMemori(inner) => {
                modified = self.ganti_variabel_dengan_konstanta(inner, constants);
            }
            MicroExpr::OperasiBiner(_, left, right) |
            MicroExpr::Bandingkan(left, right) |
            MicroExpr::UjiBit(left, right) => {
                let m1 = self.ganti_variabel_dengan_konstanta(left, constants);
                let m2 = self.ganti_variabel_dengan_konstanta(right, constants);
                modified = m1 || m2;
            }
            MicroExpr::Operand(MicroOperand::Konstanta(_)) => {
            }
        }
        modified
    }
    fn pass_expression_simplification(&mut self, cfg: &mut DiGraph<BasicBlock, &'static str>) {
        for node_idx in cfg.node_indices() {
            let block = &mut cfg[node_idx];
            for (_, instrs) in &mut block.instructions {
                for instr in instrs.iter_mut() {
                    match instr {
                        MicroInstruction::Assign(_, expr) => {
                            if self.sederhanakan_ekspresi(expr) {
                                self.changed = true;
                            }
                        }
                        MicroInstruction::SimpanMemori(addr, data) => {
                            let c1 = self.sederhanakan_ekspresi(addr);
                            let c2 = self.sederhanakan_ekspresi(data);
                            if c1 || c2 { self.changed = true; }
                        }
                        MicroInstruction::LompatKondisi(cond, target) => {
                            let c1 = self.sederhanakan_ekspresi(cond);
                            let c2 = self.sederhanakan_ekspresi(target);
                            if c1 || c2 { self.changed = true; }
                        }
                        MicroInstruction::Lompat(expr) | MicroInstruction::Panggil(expr) => {
                            if self.sederhanakan_ekspresi(expr) {
                                self.changed = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    fn sederhanakan_ekspresi(&self, expr: &mut MicroExpr) -> bool {
        match expr {
            MicroExpr::OperasiBiner(op, left, right) => {
                self.sederhanakan_ekspresi(left);
                self.sederhanakan_ekspresi(right);
                match (&mut **left, &mut **right) {
                    (MicroExpr::Operand(MicroOperand::Konstanta(c1)), MicroExpr::Operand(MicroOperand::Konstanta(c2))) => {
                        let res = match op {
                            MicroBinOp::Add => c1.wrapping_add(*c2),
                            MicroBinOp::Sub => c1.wrapping_sub(*c2),
                            MicroBinOp::Mul => c1.wrapping_mul(*c2),
                            MicroBinOp::Div if *c2 != 0 => c1.wrapping_div(*c2),
                            MicroBinOp::And => *c1 & *c2,
                            MicroBinOp::Or => *c1 | *c2,
                            MicroBinOp::Xor => *c1 ^ *c2,
                            _ => return false,
                        };
                        *expr = MicroExpr::Operand(MicroOperand::Konstanta(res));
                        return true;
                    }
                    (inner, MicroExpr::Operand(MicroOperand::Konstanta(0))) if matches!(op, MicroBinOp::Add | MicroBinOp::Sub) => {
                        *expr = inner.clone();
                        return true;
                    }
                    (MicroExpr::Operand(MicroOperand::Konstanta(0)), inner) if matches!(op, MicroBinOp::Add) => {
                        *expr = inner.clone();
                        return true;
                    }
                    (inner, MicroExpr::Operand(MicroOperand::Konstanta(1))) if matches!(op, MicroBinOp::Mul | MicroBinOp::Div) => {
                        *expr = inner.clone();
                        return true;
                    }
                    (_, MicroExpr::Operand(MicroOperand::Konstanta(0))) if matches!(op, MicroBinOp::Mul) => {
                        *expr = MicroExpr::Operand(MicroOperand::Konstanta(0));
                        return true;
                    }
                    _ => false
                }
            }
            _ => false,
        }
    }
    fn pass_dead_code_elimination(&mut self, cfg: &mut DiGraph<BasicBlock, &'static str>) {
        let liveness_info = hitung_analisis_liveness(cfg);
        for node_idx in cfg.node_indices() {
            if let Some(block) = cfg.node_weight_mut(node_idx) {
                let mut live_vars = liveness_info.live_out.get(&node_idx).cloned().unwrap_or_default();
                let mut new_instrs = Vec::new();
                for (va, instrs) in block.instructions.iter().rev() {
                    let mut block_instrs_rev = Vec::new();
                    for instr in instrs.iter().rev() {
                        match instr {
                            MicroInstruction::Assign(dest, expr) => {
                                if live_vars.contains(&dest.nama_dasar) {
                                    live_vars.remove(&dest.nama_dasar);
                                    self.tambah_uses_ke_live(expr, &mut live_vars);
                                    block_instrs_rev.push(instr.clone());
                                } else {
                                    self.changed = true;
                                }
                            }
                            MicroInstruction::SimpanMemori(addr, data) => {
                                self.tambah_uses_ke_live(addr, &mut live_vars);
                                self.tambah_uses_ke_live(data, &mut live_vars);
                                block_instrs_rev.push(instr.clone());
                            }
                            MicroInstruction::LompatKondisi(cond, target) => {
                                self.tambah_uses_ke_live(cond, &mut live_vars);
                                self.tambah_uses_ke_live(target, &mut live_vars);
                                block_instrs_rev.push(instr.clone());
                            }
                            MicroInstruction::Lompat(target) | MicroInstruction::Panggil(target) => {
                                self.tambah_uses_ke_live(target, &mut live_vars);
                                block_instrs_rev.push(instr.clone());
                            }
                            _ => {
                                block_instrs_rev.push(instr.clone());
                            }
                        }
                    }
                    block_instrs_rev.reverse();
                    new_instrs.push((*va, block_instrs_rev));
                }
                new_instrs.reverse();
                block.instructions = new_instrs;
            }
        }
    }
    fn tambah_uses_ke_live(&self, expr: &MicroExpr, live: &mut HashSet<String>) {
        match expr {
            MicroExpr::Operand(MicroOperand::SsaVar(var)) => {
                live.insert(var.nama_dasar.clone());
            }
            MicroExpr::OperasiUnary(_, inner) | MicroExpr::MuatMemori(inner) => {
                self.tambah_uses_ke_live(inner, live);
            }
            MicroExpr::OperasiBiner(_, left, right) |
            MicroExpr::Bandingkan(left, right) |
            MicroExpr::UjiBit(left, right) => {
                self.tambah_uses_ke_live(left, live);
                self.tambah_uses_ke_live(right, live);
            }
            _ => {}
        }
    }
}