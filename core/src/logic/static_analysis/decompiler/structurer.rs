//! Author: [Seclususs](https://github.com/seclususs)

use super::ast::{
    map_expr_ke_ekspresi_pseudo, map_ir_ke_pernyataan_pseudo, EkspresiPseudo, NodeStruktur,
};
use crate::error::ReToolsError;
use crate::logic::ir::instruction::MicroInstruction;
use crate::logic::static_analysis::cfg::{hitungDominators, BasicBlock};
use petgraph::algo::dominators::Dominators;
use petgraph::algo::kosaraju_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::{IntoNodeIdentifiers, Reversed};
use petgraph::Direction;
use std::collections::HashSet;

struct ContextAnalisis<'a> {
    cfg: &'a DiGraph<BasicBlock, &'static str>,
    dominators: Dominators<NodeIndex>,
    post_dominators: Dominators<NodeIndex>,
    loop_headers: HashSet<NodeIndex>,
    processed_nodes: HashSet<NodeIndex>,
}

pub fn analyze_structure(
    cfg: &DiGraph<BasicBlock, &'static str>,
    start_node: NodeIndex,
) -> Result<NodeStruktur, ReToolsError> {
    let dominators = hitungDominators(cfg, start_node);
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
        processed_nodes: HashSet::new(),
    };
    context.deteksi_natural_loops(start_node);
    let scc = kosaraju_scc(cfg);
    let root_structure = context.proses_region_skop(start_node, None, &scc);
    Ok(root_structure)
}

impl<'a> ContextAnalisis<'a> {
    fn deteksi_natural_loops(&mut self, entry: NodeIndex) {
        let mut worklist = vec![entry];
        let mut visited = HashSet::new();
        while let Some(node) = worklist.pop() {
            if !visited.insert(node) {
                continue;
            }
            for neighbor in self.cfg.neighbors_directed(node, Direction::Outgoing) {
                if self.dominators.dominators(node).map_or(false, |mut d| d.any(|x| x == neighbor)) {
                    self.loop_headers.insert(neighbor);
                }
                worklist.push(neighbor);
            }
        }
    }
    fn cari_titik_konvergensi(&self, node: NodeIndex) -> Option<NodeIndex> {
        self.post_dominators.immediate_dominator(node)
    }
    fn proses_region_skop(
        &mut self,
        entry: NodeIndex,
        exit: Option<NodeIndex>,
        sccs: &[Vec<NodeIndex>],
    ) -> NodeStruktur {
        if Some(entry) == exit || self.processed_nodes.contains(&entry) {
            return NodeStruktur::Sekuen(vec![]);
        }
        let current_scc = sccs.iter().find(|component| component.contains(&entry));
        let is_loop_complex = current_scc.map_or(false, |c| c.len() > 1);
        if is_loop_complex || self.loop_headers.contains(&entry) {
            return self.bentuk_struktur_loop(entry, exit, sccs);
        }
        let successors: Vec<NodeIndex> = self
            .cfg
            .neighbors_directed(entry, Direction::Outgoing)
            .collect();
        if successors.is_empty() {
            self.processed_nodes.insert(entry);
            return self.konversi_block_ke_node(&self.cfg[entry]);
        }
        if successors.len() == 1 {
            let next_node = successors[0];
            let current_block = self.konversi_block_ke_node(&self.cfg[entry]);
            self.processed_nodes.insert(entry);
            let rest = self.proses_region_skop(next_node, exit, sccs);
            return NodeStruktur::Sekuen(vec![current_block, rest]);
        }
        if successors.len() == 2 {
            return self.bentuk_struktur_percabangan(entry, exit, successors[0], successors[1], sccs);
        }
        if successors.len() > 2 {
            return self.bentuk_struktur_switch_case(entry, exit, &successors, sccs);
        }
        NodeStruktur::Sekuen(vec![])
    }
    fn bentuk_struktur_loop(
        &mut self,
        header: NodeIndex,
        global_exit: Option<NodeIndex>,
        sccs: &[Vec<NodeIndex>],
    ) -> NodeStruktur {
        let mut loop_body_nodes = HashSet::new();
        let mut stack = vec![header];
        let mut latch_node = None;
        while let Some(n) = stack.pop() {
            if !loop_body_nodes.insert(n) {
                continue;
            }
            for neighbor in self.cfg.neighbors_directed(n, Direction::Outgoing) {
                if neighbor == header {
                    latch_node = Some(n);
                } else if Some(neighbor) != global_exit && !self.dominators.dominators(header).map_or(false, |mut d| d.any(|x| x == neighbor)) {
                     
                } else {
                   if self.dominators.dominators(n).map_or(false, |mut d| d.any(|x| x == header)) {
                       stack.push(neighbor);
                   }
                }
            }
        }
        let loop_exit = self.cari_titik_konvergensi(header).or(global_exit);
        self.processed_nodes.insert(header);
        let header_block = &self.cfg[header];
        let condition = self.ekstrak_kondisi_cabang(header_block);
        let body_structure = if let Some(_latch) = latch_node {
             self.proses_region_skop(header, Some(header), sccs) 
        } else {
             let next_in_loop = self.cfg.neighbors_directed(header, Direction::Outgoing)
                .find(|&n| loop_body_nodes.contains(&n))
                .unwrap_or(header);
             self.proses_region_skop(next_in_loop, Some(header), sccs)
        };
        let loop_node = if let Some(cond) = condition {
            NodeStruktur::LoopSementara {
                kondisi: cond,
                badan_loop: Box::new(body_structure),
            }
        } else {
            NodeStruktur::LoopTakTerbatas(Box::new(body_structure))
        };
        let next_part = if let Some(exit_node) = loop_exit {
            self.proses_region_skop(exit_node, global_exit, sccs)
        } else {
            NodeStruktur::Sekuen(vec![])
        };
        NodeStruktur::Sekuen(vec![loop_node, next_part])
    }
    fn bentuk_struktur_percabangan(
        &mut self,
        node: NodeIndex,
        global_exit: Option<NodeIndex>,
        true_target: NodeIndex,
        false_target: NodeIndex,
        sccs: &[Vec<NodeIndex>],
    ) -> NodeStruktur {
        let block = &self.cfg[node];
        let kondisi = self.ekstrak_kondisi_cabang(block).unwrap_or(EkspresiPseudo::Konstanta(1));
        let merge_point = self.cari_titik_konvergensi(node).or(global_exit);
        self.processed_nodes.insert(node);
        let true_branch = if Some(true_target) != merge_point {
            self.proses_region_skop(true_target, merge_point, sccs)
        } else {
            NodeStruktur::Sekuen(vec![])
        };
        let false_branch = if Some(false_target) != merge_point {
            Some(Box::new(self.proses_region_skop(false_target, merge_point, sccs)))
        } else {
            None
        };
        let if_node = NodeStruktur::KondisiJika {
            kondisi,
            blok_true: Box::new(true_branch),
            blok_false: false_branch,
        };
        let next_part = if let Some(merge) = merge_point {
             self.proses_region_skop(merge, global_exit, sccs)
        } else {
            NodeStruktur::Sekuen(vec![])
        };
        NodeStruktur::Sekuen(vec![if_node, next_part])
    }
    fn bentuk_struktur_switch_case(
        &mut self,
        node: NodeIndex,
        global_exit: Option<NodeIndex>,
        targets: &[NodeIndex],
        sccs: &[Vec<NodeIndex>],
    ) -> NodeStruktur {
        let block = &self.cfg[node];
        let switch_var = self.ekstrak_variabel_switch(block);
        let merge_point = self.cari_titik_konvergensi(node).or(global_exit);
        self.processed_nodes.insert(node);
        let mut current_if_chain: Option<NodeStruktur> = None;
        for (idx, &target) in targets.iter().enumerate().rev() {
            if Some(target) == merge_point {
                continue;
            }
            let case_body = self.proses_region_skop(target, merge_point, sccs);
            let compare_val = idx as u64; 
            let condition = if let Some(ref var) = switch_var {
                EkspresiPseudo::OperasiBiner {
                    op: "==".to_string(),
                    kiri: Box::new(var.clone()),
                    kanan: Box::new(EkspresiPseudo::Konstanta(compare_val)),
                }
            } else {
                EkspresiPseudo::TidakDiketahui
            };
            let new_if = NodeStruktur::KondisiJika {
                kondisi: condition,
                blok_true: Box::new(case_body),
                blok_false: current_if_chain.map(Box::new),
            };
            current_if_chain = Some(new_if);
        }
        let switch_structure = current_if_chain.unwrap_or(NodeStruktur::Sekuen(vec![]));
        let next_part = if let Some(merge) = merge_point {
             self.proses_region_skop(merge, global_exit, sccs)
        } else {
            NodeStruktur::Sekuen(vec![])
        };
        NodeStruktur::Sekuen(vec![switch_structure, next_part])
    }
    fn konversi_block_ke_node(&self, block: &BasicBlock) -> NodeStruktur {
        let mut insts = Vec::new();
        for (va, irs) in &block.instructions {
            for ir in irs {
                if !self.is_control_flow_instruction(ir) {
                    insts.push(map_ir_ke_pernyataan_pseudo(ir, *va));
                }
            }
        }
        if insts.is_empty() {
            NodeStruktur::Sekuen(vec![])
        } else if insts.len() == 1 {
            NodeStruktur::Pernyataan(insts.remove(0))
        } else {
             let mut seq = Vec::new();
             for inst in insts {
                 seq.push(NodeStruktur::Pernyataan(inst));
             }
             NodeStruktur::Sekuen(seq)
        }
    }
    fn is_control_flow_instruction(&self, ir: &MicroInstruction) -> bool {
        matches!(ir, MicroInstruction::Lompat(_) | MicroInstruction::LompatKondisi(_, _) | MicroInstruction::Panggil(_) | MicroInstruction::Kembali)
    }
    fn ekstrak_kondisi_cabang(&self, block: &BasicBlock) -> Option<EkspresiPseudo> {
        if let Some((_, irs)) = block.instructions.last() {
            if let Some(last_ir) = irs.last() {
                if let MicroInstruction::LompatKondisi(cond, _) = last_ir {
                    return Some(map_expr_ke_ekspresi_pseudo(cond));
                }
            }
        }
        None
    }
    fn ekstrak_variabel_switch(&self, block: &BasicBlock) -> Option<EkspresiPseudo> {
        if let Some((_, irs)) = block.instructions.last() {
            if let Some(last_ir) = irs.last() {
                if let MicroInstruction::Lompat(expr) = last_ir {
                     if let crate::logic::ir::instruction::MicroExpr::MuatMemori(_) = expr {
                         return Some(map_expr_ke_ekspresi_pseudo(expr));
                     }
                }
            }
        }
        None
    }
}