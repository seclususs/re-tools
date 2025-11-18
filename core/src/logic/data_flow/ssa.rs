//! Author: [Seclususs](https://github.com/seclususs)

use crate::logic::ir::instruction::{MicroExpr, MicroInstruction, MicroOperand, SsaVariabel};
use crate::logic::static_analysis::cfg::{calc_dominators, BasicBlock};
use petgraph::algo::dominators::Dominators;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::IntoNodeIdentifiers;
use petgraph::Direction;
use std::collections::{HashMap, HashSet};

struct StateRename {
    stack_var: HashMap<String, Vec<u32>>,
    cnt_var: HashMap<String, u32>,
}

impl StateRename {
    fn new(vars: &HashSet<String>) -> Self {
        let mut stacks = HashMap::new();
        let mut counters = HashMap::new();
        for var in vars {
            stacks.insert(var.clone(), vec![0]);
            counters.insert(var.clone(), 0);
        }
        StateRename {
            stack_var: stacks,
            cnt_var: counters,
        }
    }
}

pub struct SsaBuilder<'a> {
    graf_cfg: &'a mut DiGraph<BasicBlock, &'static str>,
    doms: Dominators<NodeIndex>,
    peta_frontier: HashMap<NodeIndex, HashSet<NodeIndex>>,
    peta_situs_def: HashMap<String, HashSet<NodeIndex>>,
    set_var_asli: HashSet<String>,
}

impl<'a> SsaBuilder<'a> {
    pub fn new(cfg: &'a mut DiGraph<BasicBlock, &'static str>) -> Self {
        let idx_simpul_mulai = cfg.node_identifiers().next().unwrap();
        let doms = calc_dominators(cfg, idx_simpul_mulai);
        SsaBuilder {
            graf_cfg: cfg,
            doms,
            peta_frontier: HashMap::new(),
            peta_situs_def: HashMap::new(),
            set_var_asli: HashSet::new(),
        }
    }
    pub fn run_construct_ssa(&mut self) {
        self.calc_dom_frontiers();
        self.collect_var_defs();
        self.insert_node_phi();
        let mut state = StateRename::new(&self.set_var_asli);
        let root = self.graf_cfg.node_identifiers().next().unwrap();
        self.rename_rekursif(root, &mut state);
    }
    fn calc_dom_frontiers(&mut self) {
        let mut frontiers: HashMap<NodeIndex, HashSet<NodeIndex>> = HashMap::new();
        for idx_simpul in self.graf_cfg.node_indices() {
            frontiers.insert(idx_simpul, HashSet::new());
        }
        for idx_simpul in self.graf_cfg.node_indices() {
            let list_pred: Vec<NodeIndex> = self.graf_cfg
                .neighbors_directed(idx_simpul, Direction::Incoming)
                .collect();
            if list_pred.len() >= 2 {
                for &p in &list_pred {
                    let mut simpul_jalan = p;
                    while simpul_jalan != self.doms.immediate_dominator(idx_simpul).unwrap_or(simpul_jalan) && simpul_jalan != idx_simpul {
                        if let Some(set) = frontiers.get_mut(&simpul_jalan) {
                            set.insert(idx_simpul);
                        }
                        match self.doms.immediate_dominator(simpul_jalan) {
                            Some(idom) if idom != simpul_jalan => simpul_jalan = idom,
                            _ => break,
                        }
                    }
                }
            }
        }
        self.peta_frontier = frontiers;
    }
    fn collect_var_defs(&mut self) {
        for idx_simpul in self.graf_cfg.node_indices() {
            let blok = &self.graf_cfg[idx_simpul];
            for (_, list_instr) in &blok.instructions {
                for instr in list_instr {
                    if let MicroInstruction::Assign(dest, _) = instr {
                        self.peta_situs_def
                            .entry(dest.id_reg.clone())
                            .or_default()
                            .insert(idx_simpul);
                        self.set_var_asli.insert(dest.id_reg.clone());
                    } else if let MicroInstruction::AtomicRMW { tujuan_lama: Some(dest), .. } = instr {
                        self.peta_situs_def
                             .entry(dest.id_reg.clone())
                             .or_default()
                             .insert(idx_simpul);
                        self.set_var_asli.insert(dest.id_reg.clone());
                    } else if let MicroInstruction::VectorOp { tujuan, .. } = instr {
                         self.peta_situs_def
                             .entry(tujuan.id_reg.clone())
                             .or_default()
                             .insert(idx_simpul);
                        self.set_var_asli.insert(tujuan.id_reg.clone());
                    }
                }
            }
        }
    }
    fn insert_node_phi(&mut self) {
        for var in self.set_var_asli.clone() {
            let mut list_kerja: Vec<NodeIndex> = self.peta_situs_def.get(&var).unwrap().iter().cloned().collect();
            let mut has_phi = HashSet::new();
            let mut processed = HashSet::new();
            while let Some(n) = list_kerja.pop() {
                if let Some(frontier) = self.peta_frontier.get(&n) {
                    for &y in frontier {
                        if !has_phi.contains(&y) {
                            let preds: Vec<u64> = self.graf_cfg
                                .neighbors_directed(y, Direction::Incoming)
                                .map(|p| self.graf_cfg[p].va_start) 
                                .collect();
                            let phi_sources = preds.iter().map(|&va| (
                                SsaVariabel { id_reg: var.clone(), versi: 0 },
                                va
                            )).collect();
                            let phi_instr = MicroInstruction::Phi {
                                tujuan: SsaVariabel { id_reg: var.clone(), versi: 0 },
                                sumber: phi_sources,
                            };
                            if let Some(blok) = self.graf_cfg.node_weight_mut(y) {
                                if blok.instructions.is_empty() {
                                     blok.instructions.push((blok.va_start, vec![phi_instr]));
                                } else {
                                     blok.instructions[0].1.insert(0, phi_instr);
                                }
                            }
                            has_phi.insert(y);
                            if !processed.contains(&y) && !self.peta_situs_def.get(&var).unwrap().contains(&y) {
                                list_kerja.push(y);
                                processed.insert(y);
                            }
                        }
                    }
                }
            }
        }
    }
    fn rename_rekursif(&mut self, u: NodeIndex, state: &mut StateRename) {
        let mut cnt_push: HashMap<String, usize> = HashMap::new();
        if let Some(blok) = self.graf_cfg.node_weight_mut(u) {
            for (_, list_instr) in &mut blok.instructions {
                for instr in list_instr {
                    match instr {
                        MicroInstruction::Phi { tujuan, .. } => {
                            let base = &tujuan.id_reg;
                            let new_ver = *state.cnt_var.get(base).unwrap() + 1;
                            state.cnt_var.insert(base.clone(), new_ver);
                            state.stack_var.get_mut(base).unwrap().push(new_ver);
                            tujuan.versi = new_ver;
                            *cnt_push.entry(base.clone()).or_default() += 1;
                        }
                        _ => {
                           Self::rename_use_instr(instr, state);
                           if let Some(dest_var) = Self::get_def_var_mut(instr) {
                               let base = &dest_var.id_reg;
                               let new_ver = *state.cnt_var.get(base).unwrap() + 1;
                               state.cnt_var.insert(base.clone(), new_ver);
                               state.stack_var.get_mut(base).unwrap().push(new_ver);
                               dest_var.versi = new_ver;
                               *cnt_push.entry(base.clone()).or_default() += 1;
                           }
                        }
                    }
                }
            }
        }
        let va_u = self.graf_cfg[u].va_start;
        let successors: Vec<NodeIndex> = self.graf_cfg.neighbors_directed(u, Direction::Outgoing).collect();
        for idx_succ in successors {
             if let Some(blok_succ) = self.graf_cfg.node_weight_mut(idx_succ) {
                 for (_, list_instr) in &mut blok_succ.instructions {
                     for instr in list_instr {
                         if let MicroInstruction::Phi { sumber, .. } = instr {
                             for (src_var, src_blok_va) in sumber {
                                 if *src_blok_va == va_u {
                                     if let Some(stack) = state.stack_var.get(&src_var.id_reg) {
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
        let mut children: Vec<NodeIndex> = self.doms
            .immediately_dominated_by(u)
            .map(|n| n)
            .collect();
        children.sort_by(|a, b| a.index().cmp(&b.index()));
        for v in children {
            if v != u {
                self.rename_rekursif(v, state);
            }
        }
        for (var, count) in cnt_push {
            let stack = state.stack_var.get_mut(&var).unwrap();
            for _ in 0..count {
                stack.pop();
            }
        }
    }
    fn rename_use_instr(instr: &mut MicroInstruction, state: &StateRename) {
        match instr {
            MicroInstruction::Assign(_, expr) 
            | MicroInstruction::Jump(expr) 
            | MicroInstruction::Call(expr) 
            | MicroInstruction::UpdateFlag(_, expr) => {
                Self::rename_use_expr(expr, state);
            },
            MicroInstruction::StoreMemori(addr, val) => {
                Self::rename_use_expr(addr, state);
                Self::rename_use_expr(val, state);
            },
            MicroInstruction::JumpKondisi(cond, target) => {
                Self::rename_use_expr(cond, state);
                Self::rename_use_expr(target, state);
            },
            MicroInstruction::AtomicRMW { addr_mem, nilai, .. } => {
                Self::rename_use_expr(addr_mem, state);
                Self::rename_use_expr(nilai, state);
            },
            MicroInstruction::VectorOp { op_1, op_2, .. } => {
                for op in op_1.iter_mut().chain(op_2.iter_mut()) {
                    if let MicroOperand::SsaVar(v) = op {
                        if let Some(stack) = state.stack_var.get(&v.id_reg) {
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
    fn rename_use_expr(expr: &mut MicroExpr, state: &StateRename) {
        match expr {
            MicroExpr::Operand(MicroOperand::SsaVar(v)) => {
                if let Some(stack) = state.stack_var.get(&v.id_reg) {
                    if let Some(&ver) = stack.last() {
                        v.versi = ver;
                    }
                }
            }
            MicroExpr::UnaryOp(_, inner) | MicroExpr::LoadMemori(inner) => {
                Self::rename_use_expr(inner, state);
            }
            MicroExpr::BinaryOp(_, left, right) 
            | MicroExpr::Compare(left, right) 
            | MicroExpr::TestBit(left, right) => {
                Self::rename_use_expr(left, state);
                Self::rename_use_expr(right, state);
            }
            _ => {}
        }
    }
    fn get_def_var_mut<'b>(instr: &'b mut MicroInstruction) -> Option<&'b mut SsaVariabel> {
        match instr {
            MicroInstruction::Assign(dest, _) => Some(dest),
            MicroInstruction::AtomicRMW { tujuan_lama: Some(dest), .. } => Some(dest),
            MicroInstruction::VectorOp { tujuan, .. } => Some(tujuan),
            _ => None
        }
    }
}

pub fn construct_ssa_complete(cfg: &mut DiGraph<BasicBlock, &'static str>) {
    let mut builder = SsaBuilder::new(cfg);
    builder.run_construct_ssa();
}