//! Author: [Seclususs](https://github.com/seclususs)

#![allow(unused_imports, dead_code)]
use super::ast::{
	map_expr_ke_ekspresi_pseudo, map_ir_ke_pernyataan_pseudo, EkspresiPseudo, NodeStruktur,
	PernyataanPseudo,
};
use crate::error::ReToolsError;
use crate::logic::ir::instruction::MicroInstruction;
use crate::logic::static_analysis::cfg::{bangun_cfg_internal, hitungDominators, BasicBlock};
use crate::logic::static_analysis::parser::Binary;
use petgraph::algo::dominators::Dominators;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::{Dfs, EdgeRef, IntoNodeIdentifiers, VisitMap, Visitable};
use petgraph::Direction;
use std::collections::{HashMap, HashSet};

struct Structurer<'a> {
	cfg: &'a DiGraph<BasicBlock, &'static str>,
	dominators: Dominators<NodeIndex>,
	terkunjungi: HashSet<NodeIndex>,
	post_order: Vec<NodeIndex>,
	loop_headers: HashSet<NodeIndex>,
}

pub fn analyze_structure(
	cfg: &DiGraph<BasicBlock, &'static str>,
	start_node: NodeIndex,
) -> Result<NodeStruktur, ReToolsError> {
	let dominators = hitungDominators(cfg, start_node);
	let mut structurer = Structurer {
		cfg,
		dominators,
		terkunjungi: HashSet::new(),
		post_order: Vec::new(),
		loop_headers: HashSet::new(),
	};
	structurer.detect_loops(start_node);
	let ast_node = structurer.structure_region(start_node, None);
	Ok(ast_node)
}

impl<'a> Structurer<'a> {
	fn detect_loops(&mut self, start_node: NodeIndex) {
		let mut dfs = Dfs::new(self.cfg, start_node);
		while let Some(node) = dfs.next(self.cfg) {
			for edge in self.cfg.edges_directed(node, Direction::Outgoing) {
				let target = edge.target();
				if self
					.dominators
					.dominators(node)
					.map_or(false, |mut doms| doms.any(|d| d == target))
				{
					self.loop_headers.insert(target);
				}
			}
		}
	}
	fn structure_region(&mut self, entry: NodeIndex, exit_node: Option<NodeIndex>) -> NodeStruktur {
		let mut nodes_in_region = Vec::new();
		let mut stack = vec![entry];
		let mut region_visited = HashSet::new();
		while let Some(current) = stack.pop() {
			if !region_visited.insert(current) {
				continue;
			}
			if self.terkunjungi.contains(&current) {
				continue;
			}
			if Some(current) == exit_node {
				continue;
			}
			nodes_in_region.push(current);
			if self.loop_headers.contains(&current) && current != entry {
				continue;
			}
			for neighbor in self.cfg.neighbors_directed(current, Direction::Outgoing) {
				stack.push(neighbor);
			}
		}
		self.terkunjungi.extend(nodes_in_region.iter());
		if nodes_in_region.is_empty() {
			return NodeStruktur::Sekuen(vec![]);
		}
		if nodes_in_region.len() == 1 {
			let node = nodes_in_region[0];
			let block = &self.cfg[node];
			return self.map_basic_block_to_node(block);
		}
		let mut sekuen = Vec::new();
		for node in nodes_in_region {
			sekuen.push(self.map_basic_block_to_node(&self.cfg[node]));
		}
		NodeStruktur::Sekuen(sekuen)
	}
	fn map_basic_block_to_node(&self, block: &BasicBlock) -> NodeStruktur {
		let mut insts = Vec::new();
		for (va, irs) in &block.instructions {
			for ir in irs {
				insts.push((*va, format!("{:?}", ir)));
			}
		}
		NodeStruktur::Pernyataan(PernyataanPseudo::BlokInstruksi(insts))
	}
}