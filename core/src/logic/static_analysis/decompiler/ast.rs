//! Author: [Seclususs](https://github.com/seclususs)

#![allow(dead_code)]

use crate::logic::ir::instruction::{MicroExpr, MicroOperand, SsaVariabel};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EkspresiPseudo {
	Variabel(SsaVariabel),
	Konstanta(u64),
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
	SimpanMemori {
		alamat: EkspresiPseudo,
		nilai: EkspresiPseudo,
	},
	Lompat(u64),
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
	LoopSementara {
		kondisi: EkspresiPseudo,
		badan_loop: Box<NodeStruktur>,
	},
	LoopLakukan {
		badan_loop: Box<NodeStruktur>,
		kondisi: EkspresiPseudo,
	},
	LoopTakTerbatas(Box<NodeStruktur>),
	Pernyataan(PernyataanPseudo),
}

pub fn map_ir_ke_pernyataan_pseudo(
	ir: &crate::logic::ir::instruction::MicroInstruction,
	va: u64,
) -> PernyataanPseudo {
	match ir {
		crate::logic::ir::instruction::MicroInstruction::Assign(var, expr) => PernyataanPseudo::Assign {
			tujuan: var.clone(),
			sumber: map_expr_ke_ekspresi_pseudo(expr),
		},
		crate::logic::ir::instruction::MicroInstruction::SimpanMemori(addr, data) => {
			PernyataanPseudo::SimpanMemori {
				alamat: map_expr_ke_ekspresi_pseudo(addr),
				nilai: map_expr_ke_ekspresi_pseudo(data),
			}
		}
		crate::logic::ir::instruction::MicroInstruction::Lompat(expr) => {
			if let EkspresiPseudo::Konstanta(target) = map_expr_ke_ekspresi_pseudo(expr) {
				PernyataanPseudo::Lompat(target)
			} else {
				PernyataanPseudo::TidakTerdefinisi
			}
		}
		crate::logic::ir::instruction::MicroInstruction::LompatKondisi(cond, target) => {
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
		crate::logic::ir::instruction::MicroInstruction::Panggil(expr) => {
			PernyataanPseudo::Panggil(map_expr_ke_ekspresi_pseudo(expr))
		}
		crate::logic::ir::instruction::MicroInstruction::Kembali => {
			PernyataanPseudo::Kembali(None)
		}
		crate::logic::ir::instruction::MicroInstruction::Syscall => PernyataanPseudo::Syscall,
		_ => PernyataanPseudo::TidakTerdefinisi,
	}
}

pub fn map_expr_ke_ekspresi_pseudo(expr: &MicroExpr) -> EkspresiPseudo {
	match expr {
		MicroExpr::Operand(MicroOperand::SsaVar(var)) => EkspresiPseudo::Variabel(var.clone()),
		MicroExpr::Operand(MicroOperand::Konstanta(k)) => EkspresiPseudo::Konstanta(*k),
		MicroExpr::OperasiUnary(op, inner) => EkspresiPseudo::OperasiUnary {
			op: format!("{:?}", op),
			operand: Box::new(map_expr_ke_ekspresi_pseudo(inner)),
		},
		MicroExpr::OperasiBiner(op, l, r) => EkspresiPseudo::OperasiBiner {
			op: format!("{:?}", op),
			kiri: Box::new(map_expr_ke_ekspresi_pseudo(l)),
			kanan: Box::new(map_expr_ke_ekspresi_pseudo(r)),
		},
		MicroExpr::MuatMemori(addr) => EkspresiPseudo::MuatMemori {
			alamat: Box::new(map_expr_ke_ekspresi_pseudo(addr)),
		},
		MicroExpr::Bandingkan(l, r) => EkspresiPseudo::OperasiBiner {
			op: "==".to_string(),
			kiri: Box::new(map_expr_ke_ekspresi_pseudo(l)),
			kanan: Box::new(map_expr_ke_ekspresi_pseudo(r)),
		},
		MicroExpr::UjiBit(l, r) => EkspresiPseudo::OperasiBiner {
			op: "&".to_string(),
			kiri: Box::new(map_expr_ke_ekspresi_pseudo(l)),
			kanan: Box::new(map_expr_ke_ekspresi_pseudo(r)),
		},
	}
}