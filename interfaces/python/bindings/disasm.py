import ctypes
import os

# Setup path library (duplikasi logika dari parser.py, idealnya di file common)
LIB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../build/lib'))
if os.name == 'nt':
    LIB_FILE = 'retools_core.dll'
else:
    LIB_FILE = 'libretools_core.so'
FULL_PATH = os.path.join(LIB_PATH, LIB_FILE)

try:
    _lib = ctypes.CDLL(FULL_PATH)
except OSError:
    _lib = None

class C_Instruksi(ctypes.Structure):
    _fields_ = [
        ("mnemonic", ctypes.c_char * 32),
        ("op_str", ctypes.c_char * 64),
        ("size", ctypes.c_int),
        ("valid", ctypes.c_int)
    ]

if _lib:
    # c_decodeInstruksi(const uint8_t* bytes, int len, int offset)
    _lib.c_decodeInstruksi.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.c_int]
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
        return ("INVALID", [], 0)

    mnemonic = c_instr.mnemonic.decode('utf-8')
    op_str = c_instr.op_str.decode('utf-8')
    operands = [op.strip() for op in op_str.split(',')] if op_str else []

    return (mnemonic, operands, c_instr.size)