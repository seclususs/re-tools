use pyo3::prelude::*;

use crate::logic::static_analysis::disasm::ArsitekturDisasm;

pub mod api_ir;
pub mod api_static;


#[pymodule]
fn re_tools(m: &Bound<'_, PyModule>) -> PyResult<()> {
    api_static::register_static_functions(m)?;
    api_ir::register_ir_functions(m)?;
    m.add("ARCH_UNKNOWN", ArsitekturDisasm::ARCH_UNKNOWN as u32)?;
    m.add("ARCH_X86_32", ArsitekturDisasm::ARCH_X86_32 as u32)?;
    m.add("ARCH_X86_64", ArsitekturDisasm::ARCH_X86_64 as u32)?;
    m.add("ARCH_ARM_32", ArsitekturDisasm::ARCH_ARM_32 as u32)?;
    m.add("ARCH_ARM_64", ArsitekturDisasm::ARCH_ARM_64 as u32)?;
    Ok(())
}