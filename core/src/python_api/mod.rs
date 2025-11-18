use pyo3::prelude::*;

use crate::logic::static_analysis::disasm::ArsitekturDisasm;

pub mod api_ir;
pub mod api_static;
pub mod api_data_flow;

#[pymodule]
fn re_tools(m: &Bound<'_, PyModule>) -> PyResult<()> {
	api_static::init_modul_static(m)?;
	api_ir::init_modul_ir(m)?;
	api_data_flow::init_modul_data_flow(m)?;
	m.add("ARCH_UNKNOWN", ArsitekturDisasm::ARCH_UNKNOWN as u32)?;
	m.add("ARCH_X86_32", ArsitekturDisasm::ARCH_X86_32 as u32)?;
	m.add("ARCH_X86_64", ArsitekturDisasm::ARCH_X86_64 as u32)?;
	m.add("ARCH_ARM_32", ArsitekturDisasm::ARCH_ARM_32 as u32)?;
	m.add("ARCH_ARM_64", ArsitekturDisasm::ARCH_ARM_64 as u32)?;
	m.add("ARCH_RISCV_32", ArsitekturDisasm::ARCH_RISCV_32 as u32)?;
	m.add("ARCH_RISCV_64", ArsitekturDisasm::ARCH_RISCV_64 as u32)?;
	m.add("ARCH_MIPS_32", ArsitekturDisasm::ARCH_MIPS_32 as u32)?;
	m.add("ARCH_MIPS_64", ArsitekturDisasm::ARCH_MIPS_64 as u32)?;
	Ok(())
}