import sys

try:
    import re_tools
except ImportError:
    print("Error: Gagal mengimpor modul 're_tools' (PyO3).", file=sys.stderr)
    re_tools = None

if re_tools:
    ARCH_UNKNOWN = re_tools.ARCH_UNKNOWN
    ARCH_X86_32 = re_tools.ARCH_X86_32
    ARCH_X86_64 = re_tools.ARCH_X86_64
    ARCH_ARM_32 = re_tools.ARCH_ARM_32
    ARCH_ARM_64 = re_tools.ARCH_ARM_64
else:
    ARCH_UNKNOWN = 0
    ARCH_X86_32 = 1
    ARCH_X86_64 = 2
    ARCH_ARM_32 = 3
    ARCH_ARM_64 = 4

def decodeInstruksi(byte_data: bytes, offset: int, arch: int, base_va: int = 0) -> tuple:
    if not re_tools:
        raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat")
    
    if arch == ARCH_UNKNOWN:
        arch = ARCH_X86_64
    
    try:
        instr_dict = re_tools.decodeInstruksi(byte_data, offset, arch, base_va)
        
        if not instr_dict["valid"]:
            size = instr_dict["size"] if instr_dict["size"] > 0 else 1
            return ("INVALID", [], size)
        
        mnemonic = instr_dict["mnemonic"]
        op_str = instr_dict["operands"]
        operands = [op.strip() for op in op_str.split(',')] if op_str else []
        
        return (mnemonic, operands, instr_dict["size"])
        
    except Exception as e:
        print(f"Error saat memanggil re_tools.decodeInstruksi: {e}", file=sys.stderr)
        return ("INVALID", [], 1)