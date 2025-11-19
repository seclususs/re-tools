//! Author: [Seclususs](https://github.com/seclususs)

use super::ast::{
    map_expr_ke_ekspresi_pseudo, map_ir_ke_pernyataan_pseudo, EkspresiPseudo, NodeStruktur, PernyataanPseudo,
};
use crate::error::ReToolsError;
use crate::logic::ir::instruction::MicroInstruction;
use crate::logic::static_analysis::cfg::{calc_dominators, BasicBlock};
use petgraph::algo::dominators::Dominators;
use petgraph::algo::kosaraju_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::{IntoNodeIdentifiers, Reversed};
use petgraph::Direction;
use std::collections::{HashMap, HashSet};

struct ContextAnalisis<'a> {
    cfg: &'a DiGraph<BasicBlock, &'static str>,
    dominators: Dominators<NodeIndex>,
    post_dominators: Dominators<NodeIndex>,
    loop_headers: HashSet<NodeIndex>,
    back_edges: HashMap<NodeIndex, Vec<NodeIndex>>,
}

pub fn build_struct_cfg(
    cfg: &DiGraph<BasicBlock, &'static str>,
    start_node: NodeIndex,
) -> Result<NodeStruktur, ReToolsError> {
    let dominators = calc_dominators(cfg, start_node);
    let reversed_graph = Reversed(cfg);
    let exit_nodes: Vec<NodeIndex> = cfg
        .node_identifiers()
        .filter(|n| cfg.neighbors_directed(*n, Direction::Outgoing).count() == 0)
        .collect();
    let post_dom_root = if !exit_nodes.is_empty() {
        exit_nodes[0]
    } else {
        start_node
    };
    let post_dominators = petgraph::algo::dominators::simple_fast(&reversed_graph, post_dom_root);
    let mut context = ContextAnalisis {
        cfg,
        dominators,
        post_dominators,
        loop_headers: HashSet::new(),
        back_edges: HashMap::new(),
    };
    context.deteksi_loops(start_node);
    let scc = kosaraju_scc(cfg);
    let root_structure = context.proses_region_skop(start_node, None, &scc);
    Ok(root_structure)
}

impl<'a> ContextAnalisis<'a> {
    fn deteksi_loops(&mut self, entry: NodeIndex) {
        let mut worklist = vec![entry];
        let mut visited = HashSet::new();
        while let Some(node) = worklist.pop() {
            if !visited.insert(node) {
                continue;
            }
            for succ in self.cfg.neighbors_directed(node, Direction::Outgoing) {
                if self.dominators.dominators(node).map_or(false, |mut d| d.any(|x| x == succ)) {
                    self.loop_headers.insert(succ);
                    self.back_edges.entry(succ).or_default().push(node);
                } else {
                    worklist.push(succ);
                }
            }
        }
    }
    fn cari_titik_konvergensi(&self, node: NodeIndex) -> Option<NodeIndex> {
        self.post_dominators.immediate_dominator(node)
    }
    fn proses_region_skop(
        &mut self,
        entry: NodeIndex,
        region_exit: Option<NodeIndex>,
        sccs: &[Vec<NodeIndex>],
    ) -> NodeStruktur {
        if Some(entry) == region_exit {
            return NodeStruktur::Sekuen(vec![]);
        }
        if self.loop_headers.contains(&entry) {
            let loop_exit = self.cari_titik_konvergensi(entry);
            let effective_exit = if let Some(lx) = loop_exit {
                if let Some(rx) = region_exit {
                    if self.dominators.dominators(lx).map_or(false, |mut d| d.any(|x| x == rx)) {
                        Some(rx) 
                    } else {
                         Some(lx)
                    }
                } else {
                    Some(lx)
                }
            } else {
                region_exit
            };
            let loop_struct = self.bentuk_struktur_loop(entry, effective_exit, sccs);
            let next_struct = if let Some(exit) = effective_exit {
                self.proses_region_skop(exit, region_exit, sccs)
            } else {
                NodeStruktur::Sekuen(vec![])
            };
            return NodeStruktur::Sekuen(vec![loop_struct, next_struct]);
        }
        let successors: Vec<NodeIndex> = self
            .cfg
            .neighbors_directed(entry, Direction::Outgoing)
            .collect();
        if successors.is_empty() {
            return self.konversi_block_ke_node(&self.cfg[entry]);
        }
        if successors.len() == 1 {
            let next_node = successors[0];
            let current_block = self.konversi_block_ke_node(&self.cfg[entry]);
            if Some(next_node) == region_exit {
                return current_block;
            }
            let rest = self.proses_region_skop(next_node, region_exit, sccs);
            return NodeStruktur::Sekuen(vec![current_block, rest]);
        }
        let merge_point = self.cari_titik_konvergensi(entry).or(region_exit);
        if successors.len() > 2 {
            return self.bentuk_struktur_switch(entry, merge_point, &successors, sccs, region_exit);
        }
        if successors.len() == 2 {
            let true_node = successors[0];
            let false_node = successors[1];
            return self.bentuk_struktur_if_else(entry, true_node, false_node, merge_point, region_exit, sccs);
        }
        NodeStruktur::Goto(self.cfg[entry].va_start)
    }
    fn bentuk_struktur_loop(
        &mut self,
        header: NodeIndex,
        loop_exit: Option<NodeIndex>,
        sccs: &[Vec<NodeIndex>],
    ) -> NodeStruktur {
        let header_block = &self.cfg[header];
        let kondisi_awal = self.ekstrak_kondisi_cabang(header_block);
        let latches = self.back_edges.get(&header).cloned().unwrap_or_default();
        if latches.len() == 1 && kondisi_awal.is_some() {
            let latch = latches[0];
            let update_stmt = self.ekstrak_pernyataan_tunggal(&self.cfg[latch]);
            let body_struct = self.proses_region_skop(
                self.cfg.neighbors_directed(header, Direction::Outgoing).find(|&n| n != loop_exit.unwrap_or(NodeIndex::end())).unwrap_or(header),
                Some(latch),
                sccs
            );
            return NodeStruktur::LoopFor {
                inisialisasi: None,
                kondisi: kondisi_awal.unwrap(),
                update: update_stmt.map(Box::new),
                badan_loop: Box::new(body_struct),
            };
        }
        let body_entry = self.cfg.neighbors_directed(header, Direction::Outgoing)
            .find(|&n| Some(n) != loop_exit)
            .unwrap_or(header);
        let body_struct = self.proses_region_skop(body_entry, Some(header), sccs);
        if let Some(cond) = kondisi_awal {
            NodeStruktur::LoopSementara {
                kondisi: cond,
                badan_loop: Box::new(body_struct),
            }
        } else {
            if !latches.is_empty() {
                let latch = latches[0];
                let latch_cond = self.ekstrak_kondisi_cabang(&self.cfg[latch]);
                if let Some(cond) = latch_cond {
                    return NodeStruktur::LoopLakukan {
                        badan_loop: Box::new(body_struct),
                        kondisi: cond,
                    };
                }
            }
            NodeStruktur::LoopTakTerbatas(Box::new(body_struct))
        }
    }
    fn bentuk_struktur_switch(
        &mut self,
        header: NodeIndex,
        merge_point: Option<NodeIndex>,
        targets: &[NodeIndex],
        sccs: &[Vec<NodeIndex>],
        global_exit: Option<NodeIndex>,
    ) -> NodeStruktur {
        let header_block = &self.cfg[header];
        let switch_var = self.ekstrak_variabel_switch(header_block)
            .unwrap_or(EkspresiPseudo::TidakDiketahui);
        let mut cases = Vec::new();
        let mut processed_targets = HashSet::new();
        for (idx, &target) in targets.iter().enumerate() {
            if Some(target) == merge_point || processed_targets.contains(&target) {
                continue;
            }
            processed_targets.insert(target);
            let case_val = idx as u64; 
            let body = self.proses_region_skop(target, merge_point, sccs);
            cases.push((vec![case_val], Box::new(body)));
        }
        let switch_node = NodeStruktur::KondisiSwitch {
            kondisi: switch_var,
            kasus: cases,
            opsi_default: None,
        };
        let next_part = if let Some(merge) = merge_point {
            self.proses_region_skop(merge, global_exit, sccs)
        } else {
            NodeStruktur::Sekuen(vec![])
        };
        NodeStruktur::Sekuen(vec![switch_node, next_part])
    }
    fn bentuk_struktur_if_else(
        &mut self,
        header: NodeIndex,
        true_target: NodeIndex,
        false_target: NodeIndex,
        merge_point: Option<NodeIndex>,
        global_exit: Option<NodeIndex>,
        sccs: &[Vec<NodeIndex>],
    ) -> NodeStruktur {
        let block = &self.cfg[header];
        let kondisi = self.ekstrak_kondisi_cabang(block).unwrap_or(EkspresiPseudo::Konstanta(1));
        let true_body = if Some(true_target) != merge_point {
            Box::new(self.proses_region_skop(true_target, merge_point, sccs))
        } else {
            Box::new(NodeStruktur::Sekuen(vec![]))
        };
        let false_body = if Some(false_target) != merge_point {
            Some(Box::new(self.proses_region_skop(false_target, merge_point, sccs)))
        } else {
            None
        };
        let if_node = NodeStruktur::KondisiJika {
            kondisi,
            blok_true: true_body,
            blok_false: false_body,
        };
        let next_part = if let Some(merge) = merge_point {
            self.proses_region_skop(merge, global_exit, sccs)
        } else {
            NodeStruktur::Sekuen(vec![])
        };
        NodeStruktur::Sekuen(vec![if_node, next_part])
    }
    fn konversi_block_ke_node(&self, block: &BasicBlock) -> NodeStruktur {
        let mut stmts = Vec::new();
        for (va, irs) in &block.instructions {
            for ir in irs {
                if !self.is_control_flow_instruction(ir) {
                    stmts.push(map_ir_ke_pernyataan_pseudo(ir, *va));
                }
            }
        }
        if stmts.is_empty() {
            NodeStruktur::Sekuen(vec![])
        } else if stmts.len() == 1 {
            NodeStruktur::Pernyataan(stmts.remove(0))
        } else {
             let mut seq = Vec::new();
             for s in stmts {
                 seq.push(NodeStruktur::Pernyataan(s));
             }
             NodeStruktur::Sekuen(seq)
        }
    }
    fn ekstrak_pernyataan_tunggal(&self, block: &BasicBlock) -> Option<PernyataanPseudo> {
        let mut valid_stmt = None;
        for (va, irs) in &block.instructions {
            for ir in irs {
                if !self.is_control_flow_instruction(ir) {
                    valid_stmt = Some(map_ir_ke_pernyataan_pseudo(ir, *va));
                }
            }
        }
        valid_stmt
    }
    fn is_control_flow_instruction(&self, ir: &MicroInstruction) -> bool {
        matches!(ir, MicroInstruction::Jump(_) | MicroInstruction::JumpKondisi(_, _) | MicroInstruction::Call(_) | MicroInstruction::Return)
    }
    fn ekstrak_kondisi_cabang(&self, block: &BasicBlock) -> Option<EkspresiPseudo> {
        if let Some((_, irs)) = block.instructions.last() {
            if let Some(last_ir) = irs.last() {
                if let MicroInstruction::JumpKondisi(cond, _) = last_ir {
                    return Some(map_expr_ke_ekspresi_pseudo(cond));
                }
            }
        }
        None
    }
    fn ekstrak_variabel_switch(&self, block: &BasicBlock) -> Option<EkspresiPseudo> {
        if let Some((_, irs)) = block.instructions.last() {
            if let Some(last_ir) = irs.last() {
                if let MicroInstruction::Jump(expr) = last_ir {
                     if let crate::logic::ir::instruction::MicroExpr::LoadMemori(_) = expr {
                         return Some(map_expr_ke_ekspresi_pseudo(expr));
                     }
                }
            }
        }
        None
    }
}