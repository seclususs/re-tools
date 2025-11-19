//! Author: [Seclususs](https://github.com/seclususs)

#![allow(dead_code)]

use crate::logic::ir::instruction::{MicroBinOp, MicroExpr, MicroInstruction, MicroOperand, SsaVariabel};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EkspresiPseudo {
	Variabel(SsaVariabel),
	Konstanta(u64),
	Flag(String),
	OperasiBiner {
		op: String,
		kiri: Box<EkspresiPseudo>,
		kanan: Box<EkspresiPseudo>,
	},
	OperasiUnary {
		op: String,
		operand: Box<EkspresiPseudo>,
	},
	MuatMemori {
		alamat: Box<EkspresiPseudo>,
	},
	AksesArray {
		basis: Box<EkspresiPseudo>,
		indeks: Box<EkspresiPseudo>,
	},
	AksesStruct {
		basis: Box<EkspresiPseudo>,
		offset: u64,
	},
	PanggilFungsi {
		nama: Box<EkspresiPseudo>,
		argumen: Vec<EkspresiPseudo>,
	},
	TidakDiketahui,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PernyataanPseudo {
	Assign {
		tujuan: SsaVariabel,
		sumber: EkspresiPseudo,
	},
	StoreMem {
		alamat: EkspresiPseudo,
		nilai: EkspresiPseudo,
	},
	JumpTarget(u64),
	LompatKondisi {
		kondisi: EkspresiPseudo,
		target_true: u64,
		target_false: u64,
	},
	Panggil(EkspresiPseudo),
	Kembali(Option<EkspresiPseudo>),
	Syscall,
	BlokInstruksi(Vec<(u64, String)>),
	TidakTerdefinisi,
	AtomicOp {
		deskripsi: String,
	},
	Fence,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NodeStruktur {
	BlokDasar(PernyataanPseudo),
	Sekuen(Vec<NodeStruktur>),
	KondisiJika {
		kondisi: EkspresiPseudo,
		blok_true: Box<NodeStruktur>,
		blok_false: Option<Box<NodeStruktur>>,
	},
	KondisiSwitch {
		kondisi: EkspresiPseudo,
		kasus: Vec<(Vec<u64>, Box<NodeStruktur>)>,
		opsi_default: Option<Box<NodeStruktur>>,
	},
	LoopSementara {
		kondisi: EkspresiPseudo,
		badan_loop: Box<NodeStruktur>,
	},
	LoopLakukan {
		badan_loop: Box<NodeStruktur>,
		kondisi: EkspresiPseudo,
	},
	LoopFor {
		inisialisasi: Option<Box<PernyataanPseudo>>,
		kondisi: EkspresiPseudo,
		update: Option<Box<PernyataanPseudo>>,
		badan_loop: Box<NodeStruktur>,
	},
	LoopTakTerbatas(Box<NodeStruktur>),
	Pernyataan(PernyataanPseudo),
	Goto(u64),
}

pub fn map_ir_ke_pernyataan_pseudo(
	ir: &MicroInstruction,
	va: u64,
) -> PernyataanPseudo {
	match ir {
		MicroInstruction::Assign(var, expr) => PernyataanPseudo::Assign {
			tujuan: var.clone(),
			sumber: map_expr_ke_ekspresi_pseudo(expr),
		},
		MicroInstruction::StoreMemori(addr, data) => {
			PernyataanPseudo::StoreMem {
				alamat: map_expr_ke_ekspresi_pseudo(addr),
				nilai: map_expr_ke_ekspresi_pseudo(data),
			}
		}
		MicroInstruction::Jump(expr) => {
			if let EkspresiPseudo::Konstanta(target) = map_expr_ke_ekspresi_pseudo(expr) {
				PernyataanPseudo::JumpTarget(target)
			} else {
				PernyataanPseudo::TidakTerdefinisi
			}
		}
		MicroInstruction::JumpKondisi(cond, target) => {
			if let EkspresiPseudo::Konstanta(target_true) = map_expr_ke_ekspresi_pseudo(target) {
				PernyataanPseudo::LompatKondisi {
					kondisi: map_expr_ke_ekspresi_pseudo(cond),
					target_true,
					target_false: va
						.saturating_add(4),
				}
			} else {
				PernyataanPseudo::TidakTerdefinisi
			}
		}
		MicroInstruction::Call(expr) => {
			PernyataanPseudo::Panggil(map_expr_ke_ekspresi_pseudo(expr))
		}
		MicroInstruction::Return => {
			PernyataanPseudo::Kembali(None)
		}
		MicroInstruction::Syscall => PernyataanPseudo::Syscall,
		MicroInstruction::AtomicRMW { op, .. } => {
			PernyataanPseudo::AtomicOp { deskripsi: format!("{:?}", op) }
		},
		MicroInstruction::MemoryFence => PernyataanPseudo::Fence,
		_ => PernyataanPseudo::TidakTerdefinisi,
	}
}

fn detect_pola_array(
	expr: &MicroExpr,
) -> Option<(Box<EkspresiPseudo>, Box<EkspresiPseudo>)> {
	if let MicroExpr::BinaryOp(MicroBinOp::Add, kiri, kanan) = expr {
		if let MicroExpr::BinaryOp(MicroBinOp::Mul, idx, scale) = &**kanan {
			if let MicroExpr::Operand(MicroOperand::Konstanta(_)) = &**scale {
				return Some((
					Box::new(map_expr_ke_ekspresi_pseudo(kiri)),
					Box::new(map_expr_ke_ekspresi_pseudo(idx)),
				));
			}
		}
		if let MicroExpr::BinaryOp(MicroBinOp::Mul, idx, scale) = &**kiri {
			if let MicroExpr::Operand(MicroOperand::Konstanta(_)) = &**scale {
				return Some((
					Box::new(map_expr_ke_ekspresi_pseudo(kanan)),
					Box::new(map_expr_ke_ekspresi_pseudo(idx)),
				));
			}
		}
	}
	None
}

fn detect_pola_struct(expr: &MicroExpr) -> Option<(Box<EkspresiPseudo>, u64)> {
	if let MicroExpr::BinaryOp(MicroBinOp::Add, kiri, kanan) = expr {
		if let MicroExpr::Operand(MicroOperand::Konstanta(off)) = &**kanan {
			return Some((Box::new(map_expr_ke_ekspresi_pseudo(kiri)), *off));
		}
		if let MicroExpr::Operand(MicroOperand::Konstanta(off)) = &**kiri {
			return Some((Box::new(map_expr_ke_ekspresi_pseudo(kanan)), *off));
		}
	}
	None
}

pub fn map_expr_ke_ekspresi_pseudo(expr: &MicroExpr) -> EkspresiPseudo {
	match expr {
		MicroExpr::Operand(MicroOperand::SsaVar(var)) => EkspresiPseudo::Variabel(var.clone()),
		MicroExpr::Operand(MicroOperand::Konstanta(k)) => EkspresiPseudo::Konstanta(*k),
		MicroExpr::Operand(MicroOperand::Flag(f)) => EkspresiPseudo::Flag(f.clone()),
		MicroExpr::UnaryOp(op, inner) => EkspresiPseudo::OperasiUnary {
			op: format!("{:?}", op),
			operand: Box::new(map_expr_ke_ekspresi_pseudo(inner)),
		},
		MicroExpr::BinaryOp(op, l, r) => EkspresiPseudo::OperasiBiner {
			op: format!("{:?}", op),
			kiri: Box::new(map_expr_ke_ekspresi_pseudo(l)),
			kanan: Box::new(map_expr_ke_ekspresi_pseudo(r)),
		},
		MicroExpr::LoadMemori(addr) => {
			if let Some((base, index)) = detect_pola_array(addr) {
				EkspresiPseudo::AksesArray { basis: base, indeks: index }
			} else if let Some((base, offset)) = detect_pola_struct(addr) {
				EkspresiPseudo::AksesStruct { basis: base, offset }
			} else {
				EkspresiPseudo::MuatMemori {
					alamat: Box::new(map_expr_ke_ekspresi_pseudo(addr)),
				}
			}
		},
		MicroExpr::Compare(l, r) => EkspresiPseudo::OperasiBiner {
			op: "==".to_string(),
			kiri: Box::new(map_expr_ke_ekspresi_pseudo(l)),
			kanan: Box::new(map_expr_ke_ekspresi_pseudo(r)),
		},
		MicroExpr::TestBit(l, r) => EkspresiPseudo::OperasiBiner {
			op: "&".to_string(),
			kiri: Box::new(map_expr_ke_ekspresi_pseudo(l)),
			kanan: Box::new(map_expr_ke_ekspresi_pseudo(r)),
		},
	}
}