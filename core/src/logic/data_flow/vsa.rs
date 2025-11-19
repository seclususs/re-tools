//! Author: [Seclususs](https://github.com/seclususs)

use crate::logic::ir::instruction::{MicroBinOp, MicroExpr, MicroInstruction, MicroOperand, SsaVariabel};
use crate::logic::static_analysis::cfg::BasicBlock;
use crate::logic::static_analysis::parser::Binary;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::cmp::{min, max};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash, PartialOrd, Ord)]
pub enum MemoryRegion {
    Stack,
    Heap,
    Global,
    UnknownRegion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash, PartialOrd, Ord)]
pub struct AbstractLocation {
    pub region: MemoryRegion,
    pub offset: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub enum ValueDomain {
    Unknown,
    Constant(u64),
    Range(u64, u64),
    Pointer(AbstractLocation),
    PointerSet(BTreeSet<AbstractLocation>),
    Tainted(Box<ValueDomain>),
}

impl ValueDomain {
    pub fn is_tainted(&self) -> bool {
        matches!(self, ValueDomain::Tainted(_))
    }
    pub fn unwrap_taint(&self) -> &ValueDomain {
        if let ValueDomain::Tainted(inner) = self {
            inner
        } else {
            self
        }
    }
    pub fn meet(&self, other: &Self) -> Self {
        let a = self.unwrap_taint();
        let b = other.unwrap_taint();
        let status_taint = self.is_tainted() || other.is_tainted();
        let res = match (a, b) {
            (ValueDomain::Unknown, _) | (_, ValueDomain::Unknown) => ValueDomain::Unknown,
            (ValueDomain::Constant(c1), ValueDomain::Constant(c2)) => {
                if c1 == c2 {
                    ValueDomain::Constant(*c1)
                } else {
                    ValueDomain::Range(min(*c1, *c2), max(*c1, *c2))
                }
            }
            (ValueDomain::Constant(c), ValueDomain::Range(r_min, r_max))
            | (ValueDomain::Range(r_min, r_max), ValueDomain::Constant(c)) => {
                ValueDomain::Range(min(*c, *r_min), max(*c, *r_max))
            }
            (ValueDomain::Range(min1, max1), ValueDomain::Range(min2, max2)) => {
                ValueDomain::Range(min(*min1, *min2), max(*max1, *max2))
            }
            (ValueDomain::Pointer(loc1), ValueDomain::Pointer(loc2)) => {
                if loc1 == loc2 {
                    ValueDomain::Pointer(loc1.clone())
                } else if loc1.region == loc2.region {
                    let mut set = BTreeSet::new();
                    set.insert(loc1.clone());
                    set.insert(loc2.clone());
                    ValueDomain::PointerSet(set)
                } else {
                    ValueDomain::Unknown
                }
            }
            (ValueDomain::Pointer(loc), ValueDomain::PointerSet(set)) 
            | (ValueDomain::PointerSet(set), ValueDomain::Pointer(loc)) => {
                let mut new_set = set.clone();
                new_set.insert(loc.clone());
                ValueDomain::PointerSet(new_set)
            }
            (ValueDomain::PointerSet(set1), ValueDomain::PointerSet(set2)) => {
                let mut new_set = set1.clone();
                new_set.extend(set2.iter().cloned());
                ValueDomain::PointerSet(new_set)
            }
            _ => ValueDomain::Unknown,
        };
        if status_taint {
            ValueDomain::Tainted(Box::new(res))
        } else {
            res
        }
    }
    pub fn add(&self, other: &Self) -> Self {
        let a = self.unwrap_taint();
        let b = other.unwrap_taint();
        let status_taint = self.is_tainted() || other.is_tainted();
        let res = match (a, b) {
            (ValueDomain::Constant(c1), ValueDomain::Constant(c2)) => {
                ValueDomain::Constant(c1.wrapping_add(*c2))
            }
            (ValueDomain::Pointer(loc), ValueDomain::Constant(offset)) 
            | (ValueDomain::Constant(offset), ValueDomain::Pointer(loc)) => {
                let new_offset = loc.offset.wrapping_add(*offset as i64);
                ValueDomain::Pointer(AbstractLocation {
                    region: loc.region.clone(),
                    offset: new_offset,
                })
            }
            (ValueDomain::Range(min1, max1), ValueDomain::Constant(c)) => {
                ValueDomain::Range(min1.wrapping_add(*c), max1.wrapping_add(*c))
            }
            _ => ValueDomain::Unknown,
        };
        if status_taint { ValueDomain::Tainted(Box::new(res)) } else { res }
    }
    pub fn sub(&self, other: &Self) -> Self {
        let a = self.unwrap_taint();
        let b = other.unwrap_taint();
        let status_taint = self.is_tainted() || other.is_tainted();
        let res = match (a, b) {
            (ValueDomain::Constant(c1), ValueDomain::Constant(c2)) => {
                ValueDomain::Constant(c1.wrapping_sub(*c2))
            }
            (ValueDomain::Pointer(loc), ValueDomain::Constant(offset)) => {
                let new_offset = loc.offset.wrapping_sub(*offset as i64);
                ValueDomain::Pointer(AbstractLocation {
                    region: loc.region.clone(),
                    offset: new_offset,
                })
            }
            _ => ValueDomain::Unknown,
        };
        if status_taint { ValueDomain::Tainted(Box::new(res)) } else { res }
    }
}

impl Default for ValueDomain {
    fn default() -> Self {
        ValueDomain::Unknown
    }
}

#[derive(Debug, Clone)]
pub struct RingkasanFungsi {
    pub ret_heap_baru: bool,
    pub prop_taint: bool,
    pub ret_tetap: Option<ValueDomain>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VsaState {
    pub variables: HashMap<String, ValueDomain>,
    pub memory_abstract: HashMap<AbstractLocation, ValueDomain>,
}

impl VsaState {
    pub fn new() -> Self {
        VsaState {
            variables: HashMap::new(),
            memory_abstract: HashMap::new(),
        }
    }
    pub fn merge(&self, other: &Self) -> Self {
        let mut merged_vars = self.variables.clone();
        for (k, v) in &other.variables {
            merged_vars
                .entry(k.clone())
                .and_modify(|e| *e = e.meet(v))
                .or_insert(v.clone());
        }
        let mut merged_mem = self.memory_abstract.clone();
        for (k, v) in &other.memory_abstract {
            merged_mem
                .entry(k.clone())
                .and_modify(|e| *e = e.meet(v))
                .or_insert(v.clone());
        }
        VsaState {
            variables: merged_vars,
            memory_abstract: merged_mem,
        }
    }
    pub fn inject_hint(&mut self, hints: &HashMap<String, u64>) {
        for (reg, val) in hints {
            self.variables.insert(reg.clone(), ValueDomain::Constant(*val));
        }
    }
}

fn eval_expr_alias(expr: &MicroExpr, state: &VsaState) -> ValueDomain {
    match expr {
        MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { id_reg: nama_dasar, versi })) => {
            let unique_name = format!("{}_{}", nama_dasar, versi);
            if nama_dasar == "rsp" || nama_dasar == "esp" || nama_dasar == "sp" {
                return ValueDomain::Pointer(AbstractLocation {
                    region: MemoryRegion::Stack,
                    offset: 0,
                });
            }
            state.variables.get(&unique_name).cloned().unwrap_or_else(|| {
                 state.variables.get(nama_dasar).cloned().unwrap_or_default()
            })
        }
        MicroExpr::Operand(MicroOperand::Konstanta(c)) => ValueDomain::Constant(*c),
        MicroExpr::BinaryOp(op, left, right) => {
            let v1 = eval_expr_alias(left, state);
            let v2 = eval_expr_alias(right, state);
            match op {
                MicroBinOp::Add => v1.add(&v2),
                MicroBinOp::Sub => v1.sub(&v2),
                _ => ValueDomain::Unknown,
            }
        }
        MicroExpr::LoadMemori(addr_expr) => {
            let addr_val = eval_expr_alias(addr_expr, state);
            match addr_val.unwrap_taint() {
                ValueDomain::Pointer(loc) => {
                    state.memory_abstract.get(loc).cloned().unwrap_or(ValueDomain::Unknown)
                }
                ValueDomain::Constant(addr) => {
                    let loc = AbstractLocation { region: MemoryRegion::Global, offset: *addr as i64 };
                    state.memory_abstract.get(&loc).cloned().unwrap_or(ValueDomain::Unknown)
                }
                _ => ValueDomain::Unknown,
            }
        }
        _ => ValueDomain::Unknown,
    }
}

fn get_ringkasan_bawaan() -> HashMap<String, RingkasanFungsi> {
    let mut m = HashMap::new();
    let heap_alloc = RingkasanFungsi { ret_heap_baru: true, prop_taint: false, ret_tetap: None };
    m.insert("malloc".to_string(), heap_alloc.clone());
    m.insert("calloc".to_string(), heap_alloc.clone());
    m.insert("realloc".to_string(), heap_alloc.clone());
    m.insert("operator new".to_string(), heap_alloc.clone());
    let taint_prop = RingkasanFungsi { ret_heap_baru: false, prop_taint: true, ret_tetap: None };
    m.insert("memcpy".to_string(), taint_prop.clone());
    m.insert("strcpy".to_string(), taint_prop.clone());
    m.insert("strncpy".to_string(), taint_prop.clone());
    m
}

fn resolve_function_name(addr: u64, binary: &Binary) -> Option<String> {
    if let Some(s) = binary.symbols.iter().find(|s| s.addr == addr && s.symbol_type == "FUNC") {
        return Some(s.name.clone());
    }
    if let Some(imp) = binary.imports.iter().find(|_i| false) { 
        return Some(imp.name.clone());
    }
    None
}

fn func_transfer_alias(
    blok: &BasicBlock, 
    state_in: &VsaState, 
    binary: &Binary,
    summaries: &HashMap<String, RingkasanFungsi>,
    trace_hints: Option<&HashMap<String, u64>>
) -> VsaState {
    let mut state_out = state_in.clone();
    if let Some(hints) = trace_hints {
         state_out.inject_hint(hints);
    }
    for (_, list_instr) in &blok.instructions {
        for instr in list_instr {
            match instr {
                MicroInstruction::Assign(SsaVariabel { id_reg: nama_dasar, versi }, expr) => {
                    let value = eval_expr_alias(expr, &state_out);
                    let unique_name = format!("{}_{}", nama_dasar, versi);
                    state_out.variables.insert(unique_name, value);
                }
                MicroInstruction::Phi { tujuan, sumber } => {
                    let mut merged_val = ValueDomain::Unknown;
                    let mut first = true;
                    for (src_var, _) in sumber {
                         let src_name = format!("{}_{}", src_var.id_reg, src_var.versi);
                         let val = state_out.variables.get(&src_name).cloned().unwrap_or(ValueDomain::Unknown);
                         if first {
                             merged_val = val;
                             first = false;
                         } else {
                             merged_val = merged_val.meet(&val);
                         }
                    }
                    let dest_name = format!("{}_{}", tujuan.id_reg, tujuan.versi);
                    state_out.variables.insert(dest_name, merged_val);
                }
                MicroInstruction::StoreMemori(addr_expr, data_expr) => {
                    let addr_val = eval_expr_alias(addr_expr, &state_out);
                    let data_val = eval_expr_alias(data_expr, &state_out);     
                    match addr_val.unwrap_taint() {
                        ValueDomain::Pointer(loc) => {
                            state_out.memory_abstract.insert(loc.clone(), data_val);
                        }
                        ValueDomain::Constant(c) => {
                            let loc = AbstractLocation { region: MemoryRegion::Global, offset: *c as i64 };
                            state_out.memory_abstract.insert(loc, data_val);
                        }
                        ValueDomain::PointerSet(locs) => {
                            for loc in locs {
                                let current = state_out.memory_abstract.get(loc).unwrap_or(&ValueDomain::Unknown);
                                let merged = current.meet(&data_val);
                                state_out.memory_abstract.insert(loc.clone(), merged);
                            }
                        }
                        _ => {}
                    }
                }
                MicroInstruction::Call(target_expr) => {
                    let target_val = eval_expr_alias(target_expr, &state_out);
                    if let ValueDomain::Constant(addr) = target_val.unwrap_taint() {
                        let func_name = resolve_function_name(*addr, binary);
                        let return_reg = if binary.header.arch == "x86-64" { "rax" } else { "x0" };
                        if let Some(name) = func_name {
                            if let Some(summary) = summaries.get(&name) {
                                let mut ret_val = ValueDomain::Unknown;
                                if summary.ret_heap_baru {
                                    ret_val = ValueDomain::Pointer(AbstractLocation {
                                        region: MemoryRegion::Heap,
                                        offset: 0
                                    });
                                } else if let Some(fixed) = &summary.ret_tetap {
                                    ret_val = fixed.clone();
                                }
                                if summary.prop_taint {
                                    if target_val.is_tainted() {
                                        ret_val = ValueDomain::Tainted(Box::new(ret_val));
                                    }
                                }
                                state_out.variables.insert(return_reg.to_string(), ret_val);
                            } else {
                                state_out.variables.insert(return_reg.to_string(), ValueDomain::Unknown);
                            }
                        } else {
                             state_out.variables.insert(return_reg.to_string(), ValueDomain::Unknown);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    state_out
}

pub fn analyze_set_nilai(
    graf: &DiGraph<BasicBlock, &'static str>,
    binary: &Binary,
    peta_hint_trace: Option<&HashMap<u64, HashMap<String, u64>>>
) -> HashMap<NodeIndex, (VsaState, VsaState)> {
    let summaries = get_ringkasan_bawaan();
    let mut peta_state_masuk: HashMap<NodeIndex, VsaState> = HashMap::new();
    let mut peta_state_keluar: HashMap<NodeIndex, VsaState> = HashMap::new();
    let list_simpul: Vec<NodeIndex> = graf.node_indices().collect();
    for &simpul in &list_simpul {
        peta_state_masuk.insert(simpul, VsaState::new());
        peta_state_keluar.insert(simpul, VsaState::new());
    }
    let mut list_kerja: Vec<NodeIndex> = list_simpul.clone();
    let mut iter = 0;
    const MAX_ITERASI: usize = 100; 
    while let Some(simpul) = list_kerja.pop() {
        iter += 1;
        if iter > list_simpul.len() * MAX_ITERASI {
            return list_simpul.into_iter().map(|n| (n, (VsaState::new(), VsaState::new()))).collect();
        }
        let mut state_masuk_baru = VsaState::new();
        let mut first_pred = true;
        for simpul_pred in graf.neighbors_directed(simpul, Direction::Incoming) {
            let pred_out = peta_state_keluar.get(&simpul_pred).unwrap();
            if first_pred {
                state_masuk_baru = pred_out.clone();
                first_pred = false;
            } else {
                state_masuk_baru = state_masuk_baru.merge(pred_out);
            }
        }
        let va_blok = graf.node_weight(simpul).unwrap().va_start;
        let hint_blok = peta_hint_trace.and_then(|m| m.get(&va_blok));
        if state_masuk_baru != *peta_state_masuk.get(&simpul).unwrap() {
            peta_state_masuk.insert(simpul, state_masuk_baru.clone());
            let state_keluar_baru = func_transfer_alias(
                graf.node_weight(simpul).unwrap(), 
                &state_masuk_baru,
                binary,
                &summaries,
                hint_blok
            );
            if state_keluar_baru != *peta_state_keluar.get(&simpul).unwrap() {
                peta_state_keluar.insert(simpul, state_keluar_baru);
                for simpul_suksesor in graf.neighbors_directed(simpul, Direction::Outgoing) {
                    list_kerja.push(simpul_suksesor);
                }
            }
        }
    }
    list_simpul
        .into_iter()
        .map(|node| {
            (
                node,
                (
                    peta_state_masuk.remove(&node).unwrap(),
                    peta_state_keluar.remove(&node).unwrap(),
                ),
            )
        })
        .collect()
}