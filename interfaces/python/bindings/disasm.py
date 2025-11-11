import ctypes
from utils.lib_loader import _lib

class C_Instruksi(ctypes.Structure):
    _fields_ = [
        ("mnemonic_instruksi", ctypes.c_char * 32),
        ("str_operand", ctypes.c_char * 64),
        ("ukuran", ctypes.c_int),
        ("valid", ctypes.c_int)
    ]

if _lib:
    # c_decodeInstruksi(const uint8_t* bytes, size_t len, size_t offset)
    _lib.c_decodeInstruksi.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.c_size_t]
    _lib.c_decodeInstruksi.restype = C_Instruksi

def decodeInstruksi(byte_data: bytes, offset: int) -> tuple:
    """
    Mendekode satu instruksi dari bytearray pada offset tertentu.
    Return: (mnemonic: str, operands: list[str], size: int)
    """
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")

    # Konversi bytes Python ke array ctypes
    ByteArr = ctypes.c_ubyte * len(byte_data)
    c_bytes = ByteArr.from_buffer_copy(byte_data)

    c_instr = _lib.c_decodeInstruksi(c_bytes, len(byte_data), offset)

    if not c_instr.valid:
        size = c_instr.ukuran if c_instr.ukuran > 0 else 1
        return ("INVALID", [], size)
    
    # Konversi ke huruf besar
    mnemonic = c_instr.mnemonic_instruksi.decode('utf-8').upper()
    op_str = c_instr.str_operand.decode('utf-8')
    operands = [op.strip() for op in op_str.split(',')] if op_str else []

    return (mnemonic, operands, c_instr.ukuran)