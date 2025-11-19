pub mod ast;
pub mod printer;
pub mod structurer;

use crate::error::ReToolsError;
use crate::logic::static_analysis::cfg::build_cfg_internal;
use crate::logic::static_analysis::parser::Binary;
use log::{error, info};

pub fn decompile_function_internal(
	binary: &Binary,
	function_address: u64,
) -> Result<String, ReToolsError> {
	info!(
		"Mulai dekompilasi untuk fungsi di 0x{:x} pada file {}",
		function_address, binary.path_berkas
	);
	let cfg = match build_cfg_internal(binary, None) {
		Ok(g) => g,
		Err(e) => {
			error!("Gagal membangun CFG: {}", e);
			return Err(e);
		}
	};
	let start_node = match cfg
		.node_indices()
		.find(|i| cfg[*i].va_start == function_address)
	{
		Some(node) => node,
		None => {
			let msg = format!(
				"Alamat fungsi 0x{:x} tidak ditemukan sebagai leader di CFG",
				function_address
			);
			error!("{}", msg);
			return Err(ReToolsError::Generic(msg));
		}
	};
	let func_symbol_name = binary
		.symbols
		.iter()
		.find(|s| s.addr == function_address && s.symbol_type == "FUNC")
		.map_or_else(|| format!("sub_{:x}", function_address), |s| s.name.clone());
	info!("Menganalisis struktur CFG untuk '{}'", func_symbol_name);
	let ast_node = match structurer::build_struct_cfg(&cfg, start_node) {
		Ok(node) => node,
		Err(e) => {
			error!("Gagal menganalisis struktur: {}", e);
			return Err(e);
		}
	};
	info!("Menghasilkan pseudocode untuk '{}'", func_symbol_name);
	let pseudocode = printer::render_ast_code(&ast_node, &func_symbol_name);
	Ok(pseudocode)
}