//! Author: [Seclususs](https://github.com/seclususs)

use super::ast::{EkspresiPseudo, NodeStruktur, PernyataanPseudo};
use std::fmt::Write;

struct PrinterState {
	output: String,
	indent_level: usize,
}

impl PrinterState {
	fn new() -> Self {
		PrinterState {
			output: String::new(),
			indent_level: 0,
		}
	}
	fn indent(&mut self) {
		self.indent_level += 1;
	}
	fn dedent(&mut self) {
		if self.indent_level > 0 {
			self.indent_level -= 1;
		}
	}
	fn write_indent(&mut self) {
		for _ in 0..self.indent_level {
			write!(self.output, "    ").unwrap();
		}
	}
	fn write_line(&mut self, line: &str) {
		self.write_indent();
		writeln!(self.output, "{}", line).unwrap();
	}
	fn write(&mut self, s: &str) {
		write!(self.output, "{}", s).unwrap();
	}
}

pub fn print_ast_to_string(node: &NodeStruktur, nama_fungsi: &str) -> String {
	let mut state = PrinterState::new();
	state.write_line(&format!("void {}(void) {{", nama_fungsi));
	state.indent();
	print_node(node, &mut state);
	state.dedent();
	state.write_line("}");
	state.output
}

fn print_node(node: &NodeStruktur, state: &mut PrinterState) {
	match node {
		NodeStruktur::Sekuen(nodes) => {
			for n in nodes {
				print_node(n, state);
			}
		}
		NodeStruktur::KondisiJika {
			kondisi,
			blok_true,
			blok_false,
		} => {
			state.write_indent();
			state.write(&format!("if ({}) {{\n", print_ekspresi(kondisi)));
			state.indent();
			print_node(blok_true, state);
			state.dedent();
			state.write_line("}");
			if let Some(bf) = blok_false {
				state.write_line("else {");
				state.indent();
				print_node(bf, state);
				state.dedent();
				state.write_line("}");
			}
		}
		NodeStruktur::LoopSementara { kondisi, badan_loop } => {
			state.write_indent();
			state.write(&format!("while ({}) {{\n", print_ekspresi(kondisi)));
			state.indent();
			print_node(badan_loop, state);
			state.dedent();
			state.write_line("}");
		}
		NodeStruktur::LoopLakukan { badan_loop, kondisi } => {
			state.write_line("do {");
			state.indent();
			print_node(badan_loop, state);
			state.dedent();
			state.write_indent();
			state.write(&format!("}} while ({});\n", print_ekspresi(kondisi)));
		}
		NodeStruktur::LoopTakTerbatas(badan_loop) => {
			state.write_line("while (true) {");
			state.indent();
			print_node(badan_loop, state);
			state.dedent();
			state.write_line("}");
		}
		NodeStruktur::Pernyataan(pernyataan) => {
			print_pernyataan(pernyataan, state);
		}
		NodeStruktur::BlokDasar(pernyataan) => {
			print_pernyataan(pernyataan, state);
		}
	}
}

fn print_pernyataan(pernyataan: &PernyataanPseudo, state: &mut PrinterState) {
	state.write_indent();
	match pernyataan {
		PernyataanPseudo::Assign { tujuan, sumber } => {
			writeln!(
				state.output,
				"{} = {};",
				tujuan.nama_dasar,
				print_ekspresi(sumber)
			)
			.unwrap();
		}
		PernyataanPseudo::SimpanMemori { alamat, nilai } => {
			writeln!(
				state.output,
				"*({}) = {};",
				print_ekspresi(alamat),
				print_ekspresi(nilai)
			)
			.unwrap();
		}
		PernyataanPseudo::Lompat(target) => {
			writeln!(state.output, "goto loc_{:x};", target).unwrap();
		}
		PernyataanPseudo::LompatKondisi {
			kondisi,
			target_true,
			..
		} => {
			writeln!(
				state.output,
				"if ({}) goto loc_{:x};",
				print_ekspresi(kondisi),
				target_true
			)
			.unwrap();
		}
		PernyataanPseudo::Panggil(ekspresi) => {
			writeln!(state.output, "{}(...);", print_ekspresi(ekspresi)).unwrap();
		}
		PernyataanPseudo::Kembali(Some(ekspresi)) => {
			writeln!(state.output, "return {};", print_ekspresi(ekspresi)).unwrap();
		}
		PernyataanPseudo::Kembali(None) => {
			state.write_line("return;");
		}
		PernyataanPseudo::Syscall => {
			state.write_line("syscall();");
		}
		PernyataanPseudo::BlokInstruksi(insts) => {
			state.write_line("{");
			state.indent();
			for (va, inst_str) in insts {
				state.write_line(&format!("loc_{:x}: {}", va, inst_str));
			}
			state.dedent();
			state.write_line("}");
		}
		PernyataanPseudo::TidakTerdefinisi => {
			state.write_line("// (instruksi tidak terdefinisi)");
		}
	}
}

fn print_ekspresi(ekspresi: &EkspresiPseudo) -> String {
	match ekspresi {
		EkspresiPseudo::Variabel(var) => var.nama_dasar.clone(),
		EkspresiPseudo::Konstanta(k) => format!("0x{:x}", k),
		EkspresiPseudo::OperasiBiner { op, kiri, kanan } => {
			format!(
				"({} {} {})",
				print_ekspresi(kiri),
				op,
				print_ekspresi(kanan)
			)
		}
		EkspresiPseudo::OperasiUnary { op, operand } => {
			format!("({}{})", op, print_ekspresi(operand))
		}
		EkspresiPseudo::MuatMemori { alamat } => {
			format!("*({})", print_ekspresi(alamat))
		}
		EkspresiPseudo::PanggilFungsi { nama, argumen } => {
			let args_str = argumen
				.iter()
				.map(print_ekspresi)
				.collect::<Vec<_>>()
				.join(", ");
			format!("{}({})", print_ekspresi(nama), args_str)
		}
		EkspresiPseudo::TidakDiketahui => "UNKNOWN".to_string(),
	}
}