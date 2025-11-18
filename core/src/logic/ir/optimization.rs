//! Author: [Seclususs](https://github.com/seclususs)

use crate::logic::ir::instruction::{MicroBinOp, MicroExpr, MicroInstruction, MicroOperand};
use crate::logic::static_analysis::cfg::BasicBlock;
use crate::logic::data_flow::liveness::calc_live_var;
use petgraph::graph::DiGraph;
use std::collections::{HashMap, HashSet};

pub struct IrOptimizer {
    changed: bool,
}

impl IrOptimizer {
    pub fn new() -> Self {
        IrOptimizer { changed: false }
    }
    pub fn run_pass_opt(&mut self, cfg: &mut DiGraph<BasicBlock, &'static str>) {
        loop {
            self.changed = false;
            self.exec_prop_const(cfg);
            self.exec_simp_expr(cfg);
            self.exec_dce(cfg);
            if !self.changed {
                break;
            }
        }
    }
    fn exec_prop_const(&mut self, cfg: &mut DiGraph<BasicBlock, &'static str>) {
        let mut peta_konstanta: HashMap<String, u64> = HashMap::new();
        for idx_simpul in cfg.node_indices() {
            let blok = &cfg[idx_simpul];
            for (_, list_instr) in &blok.instructions {
                for instr in list_instr {
                    match instr {
                         MicroInstruction::Assign(tujuan, ekspresi) => {
                            if let MicroExpr::Operand(MicroOperand::Konstanta(nilai)) = ekspresi {
                                peta_konstanta.insert(format!("{}_{}", tujuan.id_reg, tujuan.versi), *nilai);
                                peta_konstanta.insert(tujuan.id_reg.clone(), *nilai); 
                            }
                        }
                        MicroInstruction::Phi { tujuan: _tujuan, sumber } => {
                            let mut first_val = None;
                            let all_same = true;
                            for (_, _) in sumber {
                                if first_val.is_none() {
                                    first_val = Some(0); 
                                }
                            }
                            if all_same && first_val.is_some() {}
                        }
                        _ => {}
                    }
                }
            }
        }
        if peta_konstanta.is_empty() {
            return;
        }
        for idx_simpul in cfg.node_indices() {
            let blok = &mut cfg[idx_simpul];
            for (_, list_instr) in &mut blok.instructions {
                for instr in list_instr.iter_mut() {
                    match instr {
                        MicroInstruction::Assign(_, ekspresi) |
                        MicroInstruction::StoreMemori(ekspresi, _) | 
                        MicroInstruction::Jump(ekspresi) |
                        MicroInstruction::JumpKondisi(ekspresi, _) |
                        MicroInstruction::Call(ekspresi) => {
                            if self.replace_var_const(ekspresi, &peta_konstanta) {
                                self.changed = true;
                            }
                            if let MicroInstruction::StoreMemori(_, data) = instr {
                                if self.replace_var_const(data, &peta_konstanta) {
                                    self.changed = true;
                                }
                            }
                            if let MicroInstruction::JumpKondisi(_, target) = instr {
                                if self.replace_var_const(target, &peta_konstanta) {
                                    self.changed = true;
                                }
                            }
                        }
                        MicroInstruction::AtomicRMW { addr_mem: alamat, nilai, .. } => {
                            let c1 = self.replace_var_const(alamat, &peta_konstanta);
                            let c2 = self.replace_var_const(nilai, &peta_konstanta);
                            if c1 || c2 { self.changed = true; }
                        }
                        MicroInstruction::UpdateFlag(_, ekspresi) => {
                            if self.replace_var_const(ekspresi, &peta_konstanta) {
                                self.changed = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    fn replace_var_const(&self, ekspresi: &mut MicroExpr, peta_konstanta: &HashMap<String, u64>) -> bool {
        let mut modified = false;
        match ekspresi {
            MicroExpr::Operand(MicroOperand::SsaVar(var)) => {
                let kunci = format!("{}_{}", var.id_reg, var.versi);
                if let Some(nilai) = peta_konstanta.get(&kunci).or_else(|| peta_konstanta.get(&var.id_reg)) {
                    *ekspresi = MicroExpr::Operand(MicroOperand::Konstanta(*nilai));
                    modified = true;
                }
            }
            MicroExpr::UnaryOp(_, inner) |
            MicroExpr::LoadMemori(inner) => {
                modified = self.replace_var_const(inner, peta_konstanta);
            }
            MicroExpr::BinaryOp(_, kiri, kanan) |
            MicroExpr::Compare(kiri, kanan) |
            MicroExpr::TestBit(kiri, kanan) => {
                let m1 = self.replace_var_const(kiri, peta_konstanta);
                let m2 = self.replace_var_const(kanan, peta_konstanta);
                modified = m1 || m2;
            }
            MicroExpr::Operand(MicroOperand::Konstanta(_)) => {}
            MicroExpr::Operand(MicroOperand::Flag(_)) => {}
        }
        modified
    }
    fn exec_simp_expr(&mut self, cfg: &mut DiGraph<BasicBlock, &'static str>) {
        for idx_simpul in cfg.node_indices() {
            let blok = &mut cfg[idx_simpul];
            for (_, list_instr) in &mut blok.instructions {
                for instr in list_instr.iter_mut() {
                    match instr {
                        MicroInstruction::Assign(_, ekspresi) => {
                            if self.simplify_expr(ekspresi) {
                                self.changed = true;
                            }
                        }
                        MicroInstruction::StoreMemori(addr, data) => {
                            let c1 = self.simplify_expr(addr);
                            let c2 = self.simplify_expr(data);
                            if c1 || c2 { self.changed = true; }
                        }
                        MicroInstruction::JumpKondisi(kondisi, target) => {
                            let c1 = self.simplify_expr(kondisi);
                            let c2 = self.simplify_expr(target);
                            if c1 || c2 { self.changed = true; }
                        }
                        MicroInstruction::Jump(ekspresi) | MicroInstruction::Call(ekspresi) => {
                            if self.simplify_expr(ekspresi) {
                                self.changed = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    fn simplify_expr(&self, ekspresi: &mut MicroExpr) -> bool {
        match ekspresi {
            MicroExpr::BinaryOp(op, kiri, kanan) => {
                self.simplify_expr(kiri);
                self.simplify_expr(kanan);
                match (&mut **kiri, &mut **kanan) {
                    (MicroExpr::Operand(MicroOperand::Konstanta(c1)), MicroExpr::Operand(MicroOperand::Konstanta(c2))) => {
                        let hasil = match op {
                            MicroBinOp::Add => c1.wrapping_add(*c2),
                            MicroBinOp::Sub => c1.wrapping_sub(*c2),
                            MicroBinOp::Mul => c1.wrapping_mul(*c2),
                            MicroBinOp::Div if *c2 != 0 => c1.wrapping_div(*c2),
                            MicroBinOp::And => *c1 & *c2,
                            MicroBinOp::Or => *c1 | *c2,
                            MicroBinOp::Xor => *c1 ^ *c2,
                            _ => return false,
                        };
                        *ekspresi = MicroExpr::Operand(MicroOperand::Konstanta(hasil));
                        return true;
                    }
                    (inner, MicroExpr::Operand(MicroOperand::Konstanta(0))) if matches!(op, MicroBinOp::Add | MicroBinOp::Sub) => {
                        *ekspresi = inner.clone();
                        return true;
                    }
                    (MicroExpr::Operand(MicroOperand::Konstanta(0)), inner) if matches!(op, MicroBinOp::Add) => {
                        *ekspresi = inner.clone();
                        return true;
                    }
                    (inner, MicroExpr::Operand(MicroOperand::Konstanta(1))) if matches!(op, MicroBinOp::Mul | MicroBinOp::Div) => {
                        *ekspresi = inner.clone();
                        return true;
                    }
                    (_, MicroExpr::Operand(MicroOperand::Konstanta(0))) if matches!(op, MicroBinOp::Mul) => {
                        *ekspresi = MicroExpr::Operand(MicroOperand::Konstanta(0));
                        return true;
                    }
                    _ => false
                }
            }
            _ => false,
        }
    }
    fn exec_dce(&mut self, cfg: &mut DiGraph<BasicBlock, &'static str>) {
        let info_liveness = calc_live_var(cfg);
        for idx_simpul in cfg.node_indices() {
            if let Some(blok) = cfg.node_weight_mut(idx_simpul) {
                let mut set_hidup = info_liveness.live_out.get(&idx_simpul).cloned().unwrap_or_default();
                let mut list_instr_baru = Vec::new();
                for (va, list_instr) in blok.instructions.iter().rev() {
                    let mut blok_instr_rev = Vec::new();
                    for instr in list_instr.iter().rev() {
                        match instr {
                            MicroInstruction::Assign(tujuan, ekspresi) => {
                                if set_hidup.contains(&tujuan.id_reg) {
                                    set_hidup.remove(&tujuan.id_reg);
                                    self.insert_use_live(ekspresi, &mut set_hidup);
                                    blok_instr_rev.push(instr.clone());
                                } else {
                                    self.changed = true;
                                }
                            }
                            MicroInstruction::Phi { tujuan, sumber } => {
                                if set_hidup.contains(&tujuan.id_reg) {
                                    set_hidup.remove(&tujuan.id_reg);
                                    for (src, _) in sumber {
                                        set_hidup.insert(src.id_reg.clone());
                                    }
                                    blok_instr_rev.push(instr.clone());
                                } else {
                                    self.changed = true;
                                }
                            }
                            MicroInstruction::StoreMemori(addr, data) => {
                                self.insert_use_live(addr, &mut set_hidup);
                                self.insert_use_live(data, &mut set_hidup);
                                blok_instr_rev.push(instr.clone());
                            }
                            MicroInstruction::JumpKondisi(kondisi, target) => {
                                self.insert_use_live(kondisi, &mut set_hidup);
                                self.insert_use_live(target, &mut set_hidup);
                                blok_instr_rev.push(instr.clone());
                            }
                            MicroInstruction::Jump(target) | MicroInstruction::Call(target) => {
                                self.insert_use_live(target, &mut set_hidup);
                                blok_instr_rev.push(instr.clone());
                            }
                            MicroInstruction::AtomicRMW { addr_mem: alamat, nilai, tujuan_lama, .. } => {
                                self.insert_use_live(alamat, &mut set_hidup);
                                self.insert_use_live(nilai, &mut set_hidup);
                                if let Some(old) = tujuan_lama {
                                    if set_hidup.contains(&old.id_reg) {
                                        set_hidup.remove(&old.id_reg);
                                    }
                                }
                                blok_instr_rev.push(instr.clone());
                            }
                            MicroInstruction::UpdateFlag(_, ekspresi) => {
                                self.insert_use_live(ekspresi, &mut set_hidup);
                                blok_instr_rev.push(instr.clone());
                            }
                            _ => {
                                blok_instr_rev.push(instr.clone());
                            }
                        }
                    }
                    blok_instr_rev.reverse();
                    list_instr_baru.push((*va, blok_instr_rev));
                }
                list_instr_baru.reverse();
                blok.instructions = list_instr_baru;
            }
        }
    }
    fn insert_use_live(&self, ekspresi: &MicroExpr, set_hidup: &mut HashSet<String>) {
        match ekspresi {
            MicroExpr::Operand(MicroOperand::SsaVar(var)) => {
                set_hidup.insert(var.id_reg.clone());
            }
            MicroExpr::UnaryOp(_, inner) | MicroExpr::LoadMemori(inner) => {
                self.insert_use_live(inner, set_hidup);
            }
            MicroExpr::BinaryOp(_, kiri, kanan) |
            MicroExpr::Compare(kiri, kanan) |
            MicroExpr::TestBit(kiri, kanan) => {
                self.insert_use_live(kiri, set_hidup);
                self.insert_use_live(kanan, set_hidup);
            }
            _ => {}
        }
    }
}