import ctypes
from utils.lib_loader import _lib

# Definisi Enum Arsitektur
ARCH_UNKNOWN = 0
ARCH_X86_32 = 1
ARCH_X86_64 = 2
ARCH_ARM_32 = 3
ARCH_ARM_64 = 4

class C_Instruksi(ctypes.Structure):
    _fields_ = [
        ("mnemonic_instruksi", ctypes.c_char * 32),
        ("str_operand", ctypes.c_char * 64),
        ("ukuran", ctypes.c_int),
        ("valid", ctypes.c_int)
    ]

if _lib:
    # c_decodeInstruksi(const uint8_t* bytes, size_t len, size_t offset, uint64_t instruction_base_va, int arch)
    _lib.c_decodeInstruksi.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte), 
        ctypes.c_size_t, 
        ctypes.c_size_t,
        ctypes.c_uint64,
        ctypes.c_int
    ]
    _lib.c_decodeInstruksi.restype = C_Instruksi

def decodeInstruksi(byte_data: bytes, offset: int, arch: int, base_va: int = 0) -> tuple:
    """
    Mendekode satu instruksi.
    
    Args:
        byte_data (bytes): Seluruh buffer bytes.
        offset (int): Offset di dalam buffer untuk mulai decode.
        arch (int): Enum arsitektur.
        base_va (int, optional): Virtual Address dari byte_data[0]. Default ke 0.
    """
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    if arch == ARCH_UNKNOWN:
        # Jika tidak diketahui, coba default ke X86_64
        arch = ARCH_X86_64

    # Konversi bytes Python ke array ctypes
    ByteArr = ctypes.c_ubyte * len(byte_data)
    c_bytes = ByteArr.from_buffer_copy(byte_data)

    # Teruskan VA instruksi (base_va + offset)
    instruction_va = base_va + offset
    c_instr = _lib.c_decodeInstruksi(c_bytes, len(byte_data), offset, instruction_va, arch)

    if not c_instr.valid:
        size = c_instr.ukuran if c_instr.ukuran > 0 else 1
        return ("INVALID", [], size)
    
    # Konversi ke huruf besar
    mnemonic = c_instr.mnemonic_instruksi.decode('utf-8').upper()
    op_str = c_instr.str_operand.decode('utf-8')
    operands = [op.strip() for op in op_str.split(',')] if op_str else []

    return (mnemonic, operands, c_instr.ukuran)