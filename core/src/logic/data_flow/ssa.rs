//! Author: [Seclususs](https://github.com/seclususs)

use crate::logic::ir::instruction::{MicroExpr, MicroInstruction, MicroOperand, SsaVariabel};
use crate::logic::static_analysis::cfg::{hitungDominators, BasicBlock};
use petgraph::algo::dominators::Dominators;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::IntoNodeIdentifiers;
use petgraph::Direction;
use std::collections::{HashMap, HashSet};

struct RenameState {
    var_stacks: HashMap<String, Vec<u32>>,
    var_counters: HashMap<String, u32>,
}

impl RenameState {
    fn new(vars: &HashSet<String>) -> Self {
        let mut stacks = HashMap::new();
        let mut counters = HashMap::new();
        for var in vars {
            stacks.insert(var.clone(), vec![0]);
            counters.insert(var.clone(), 0);
        }
        RenameState {
            var_stacks: stacks,
            var_counters: counters,
        }
    }
}

pub struct SsaBuilder<'a> {
    cfg: &'a mut DiGraph<BasicBlock, &'static str>,
    dominators: Dominators<NodeIndex>,
    dominance_frontiers: HashMap<NodeIndex, HashSet<NodeIndex>>,
    def_sites: HashMap<String, HashSet<NodeIndex>>,
    original_vars: HashSet<String>,
}

impl<'a> SsaBuilder<'a> {
    pub fn new(cfg: &'a mut DiGraph<BasicBlock, &'static str>) -> Self {
        let start_node = cfg.node_identifiers().next().unwrap();
        let doms = hitungDominators(cfg, start_node);
        SsaBuilder {
            cfg,
            dominators: doms,
            dominance_frontiers: HashMap::new(),
            def_sites: HashMap::new(),
            original_vars: HashSet::new(),
        }
    }
    pub fn jalankan_konstruksi_ssa(&mut self) {
        self.hitung_dominance_frontiers();
        self.kumpulkan_variable_defs();
        self.sisipkan_phi_nodes();
        let mut state = RenameState::new(&self.original_vars);
        let root = self.cfg.node_identifiers().next().unwrap();
        self.rename_recursive(root, &mut state);
    }
    fn hitung_dominance_frontiers(&mut self) {
        let mut frontiers: HashMap<NodeIndex, HashSet<NodeIndex>> = HashMap::new();
        for node in self.cfg.node_indices() {
            frontiers.insert(node, HashSet::new());
        }
        for node in self.cfg.node_indices() {
            let predecessors: Vec<NodeIndex> = self.cfg
                .neighbors_directed(node, Direction::Incoming)
                .collect();
            if predecessors.len() >= 2 {
                for &p in &predecessors {
                    let mut runner = p;
                    while runner != self.dominators.immediate_dominator(node).unwrap_or(runner) && runner != node {
                        if let Some(set) = frontiers.get_mut(&runner) {
                            set.insert(node);
                        }
                        match self.dominators.immediate_dominator(runner) {
                            Some(idom) if idom != runner => runner = idom,
                            _ => break,
                        }
                    }
                }
            }
        }
        self.dominance_frontiers = frontiers;
    }
    fn kumpulkan_variable_defs(&mut self) {
        for node in self.cfg.node_indices() {
            let block = &self.cfg[node];
            for (_, instrs) in &block.instructions {
                for instr in instrs {
                    if let MicroInstruction::Assign(dest, _) = instr {
                        self.def_sites
                            .entry(dest.nama_dasar.clone())
                            .or_default()
                            .insert(node);
                        self.original_vars.insert(dest.nama_dasar.clone());
                    } else if let MicroInstruction::AtomicRMW { tujuan_lama: Some(dest), .. } = instr {
                        self.def_sites
                             .entry(dest.nama_dasar.clone())
                             .or_default()
                             .insert(node);
                        self.original_vars.insert(dest.nama_dasar.clone());
                    } else if let MicroInstruction::InstruksiVektor { tujuan, .. } = instr {
                         self.def_sites
                             .entry(tujuan.nama_dasar.clone())
                             .or_default()
                             .insert(node);
                        self.original_vars.insert(tujuan.nama_dasar.clone());
                    }
                }
            }
        }
    }
    fn sisipkan_phi_nodes(&mut self) {
        for var in self.original_vars.clone() {
            let mut worklist: Vec<NodeIndex> = self.def_sites.get(&var).unwrap().iter().cloned().collect();
            let mut has_phi = HashSet::new();
            let mut processed = HashSet::new();
            while let Some(n) = worklist.pop() {
                if let Some(frontier) = self.dominance_frontiers.get(&n) {
                    for &y in frontier {
                        if !has_phi.contains(&y) {
                            let preds: Vec<u64> = self.cfg
                                .neighbors_directed(y, Direction::Incoming)
                                .map(|p| self.cfg[p].va_start) 
                                .collect();
                            let phi_sources = preds.iter().map(|&va| (
                                SsaVariabel { nama_dasar: var.clone(), versi: 0 },
                                va
                            )).collect();
                            let phi_instr = MicroInstruction::Phi {
                                tujuan: SsaVariabel { nama_dasar: var.clone(), versi: 0 },
                                sumber: phi_sources,
                            };
                            if let Some(block) = self.cfg.node_weight_mut(y) {
                                if block.instructions.is_empty() {
                                     block.instructions.push((block.va_start, vec![phi_instr]));
                                } else {
                                     block.instructions[0].1.insert(0, phi_instr);
                                }
                            }
                            has_phi.insert(y);
                            if !processed.contains(&y) && !self.def_sites.get(&var).unwrap().contains(&y) {
                                worklist.push(y);
                                processed.insert(y);
                            }
                        }
                    }
                }
            }
        }
    }
    fn rename_recursive(&mut self, u: NodeIndex, state: &mut RenameState) {
        let mut push_counts: HashMap<String, usize> = HashMap::new();
        if let Some(block) = self.cfg.node_weight_mut(u) {
            for (_, instrs) in &mut block.instructions {
                for instr in instrs {
                    match instr {
                        MicroInstruction::Phi { tujuan, .. } => {
                            let base = &tujuan.nama_dasar;
                            let new_ver = *state.var_counters.get(base).unwrap() + 1;
                            state.var_counters.insert(base.clone(), new_ver);
                            state.var_stacks.get_mut(base).unwrap().push(new_ver);
                            tujuan.versi = new_ver;
                            *push_counts.entry(base.clone()).or_default() += 1;
                        }
                        _ => {
                           Self::rename_uses_in_instr(instr, state);
                           if let Some(dest_var) = Self::get_def_var_mut(instr) {
                               let base = &dest_var.nama_dasar;
                               let new_ver = *state.var_counters.get(base).unwrap() + 1;
                               state.var_counters.insert(base.clone(), new_ver);
                               state.var_stacks.get_mut(base).unwrap().push(new_ver);
                               dest_var.versi = new_ver;
                               *push_counts.entry(base.clone()).or_default() += 1;
                           }
                        }
                    }
                }
            }
        }
        let u_va = self.cfg[u].va_start;
        let successors: Vec<NodeIndex> = self.cfg.neighbors_directed(u, Direction::Outgoing).collect();
        for succ_idx in successors {
             if let Some(succ_block) = self.cfg.node_weight_mut(succ_idx) {
                 for (_, instrs) in &mut succ_block.instructions {
                     for instr in instrs {
                         if let MicroInstruction::Phi { sumber, .. } = instr {
                             for (src_var, src_block_va) in sumber {
                                 if *src_block_va == u_va {
                                     if let Some(stack) = state.var_stacks.get(&src_var.nama_dasar) {
                                         if let Some(&ver) = stack.last() {
                                             src_var.versi = ver;
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
        }
        let mut children: Vec<NodeIndex> = self.dominators
            .immediately_dominated_by(u)
            .map(|n| n)
            .collect();
        children.sort_by(|a, b| a.index().cmp(&b.index()));
        for v in children {
            if v != u {
                self.rename_recursive(v, state);
            }
        }
        for (var, count) in push_counts {
            let stack = state.var_stacks.get_mut(&var).unwrap();
            for _ in 0..count {
                stack.pop();
            }
        }
    }
    fn rename_uses_in_instr(instr: &mut MicroInstruction, state: &RenameState) {
        match instr {
            MicroInstruction::Assign(_, expr) 
            | MicroInstruction::Lompat(expr) 
            | MicroInstruction::Panggil(expr) 
            | MicroInstruction::UpdateFlag(_, expr) => {
                Self::rename_uses_in_expr(expr, state);
            },
            MicroInstruction::SimpanMemori(addr, val) => {
                Self::rename_uses_in_expr(addr, state);
                Self::rename_uses_in_expr(val, state);
            },
            MicroInstruction::LompatKondisi(cond, target) => {
                Self::rename_uses_in_expr(cond, state);
                Self::rename_uses_in_expr(target, state);
            },
            MicroInstruction::AtomicRMW { alamat, nilai, .. } => {
                Self::rename_uses_in_expr(alamat, state);
                Self::rename_uses_in_expr(nilai, state);
            },
            MicroInstruction::InstruksiVektor { operand_1, operand_2, .. } => {
                for op in operand_1.iter_mut().chain(operand_2.iter_mut()) {
                    if let MicroOperand::SsaVar(v) = op {
                        if let Some(stack) = state.var_stacks.get(&v.nama_dasar) {
                             if let Some(&ver) = stack.last() {
                                 v.versi = ver;
                             }
                        }
                    }
                }
            },
            _ => {}
        }
    }
    fn rename_uses_in_expr(expr: &mut MicroExpr, state: &RenameState) {
        match expr {
            MicroExpr::Operand(MicroOperand::SsaVar(v)) => {
                if let Some(stack) = state.var_stacks.get(&v.nama_dasar) {
                    if let Some(&ver) = stack.last() {
                        v.versi = ver;
                    }
                }
            }
            MicroExpr::OperasiUnary(_, inner) | MicroExpr::MuatMemori(inner) => {
                Self::rename_uses_in_expr(inner, state);
            }
            MicroExpr::OperasiBiner(_, left, right) 
            | MicroExpr::Bandingkan(left, right) 
            | MicroExpr::UjiBit(left, right) => {
                Self::rename_uses_in_expr(left, state);
                Self::rename_uses_in_expr(right, state);
            }
            _ => {}
        }
    }
    fn get_def_var_mut<'b>(instr: &'b mut MicroInstruction) -> Option<&'b mut SsaVariabel> {
        match instr {
            MicroInstruction::Assign(dest, _) => Some(dest),
            MicroInstruction::AtomicRMW { tujuan_lama: Some(dest), .. } => Some(dest),
            MicroInstruction::InstruksiVektor { tujuan, .. } => Some(tujuan),
            _ => None
        }
    }
}

pub fn konstruksi_ssa_lengkap(cfg: &mut DiGraph<BasicBlock, &'static str>) {
    let mut builder = SsaBuilder::new(cfg);
    builder.jalankan_konstruksi_ssa();
}