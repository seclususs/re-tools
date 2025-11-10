import ctypes
import os
import sys

# Setup path library
LIB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../build/lib'))
if os.name == 'nt':
    LIB_FILE = 'retools_core.dll'
else:
    LIB_FILE = 'libretools_core.so'

FULL_PATH = os.path.join(LIB_PATH, LIB_FILE)
try:
    _lib = ctypes.CDLL(FULL_PATH)
except OSError:
    try:
        _lib = ctypes.CDLL(LIB_FILE)
    except OSError:
        print(f"Gagal memuat library re-tools dari {FULL_PATH}")
        # Lanjut agar bisa di-import meski error saat runtime nanti
        _lib = None

# Definisi Struktur C untuk ctypes
class C_ElfHeader(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_char * 5),
        ("entry_point", ctypes.c_uint64),
        ("machine", ctypes.c_uint16),
        ("section_count", ctypes.c_uint16),
        ("valid", ctypes.c_int)
    ]

# Setup prototype fungsi C
if _lib:
    _lib.c_parseHeaderElf.argtypes = [ctypes.c_char_p]
    _lib.c_parseHeaderElf.restype = C_ElfHeader

class ElfHeader:
    def __init__(self, c_hdr):
        self.magic = c_hdr.magic.decode('utf-8')
        self.entry_point = c_hdr.entry_point
        self.machine = c_hdr.machine
        self.section_count = c_hdr.section_count
        self.valid = bool(c_hdr.valid)

    def __repr__(self):
        return f"<ElfHeader magic={self.magic} entry=0x{self.entry_point:x} valid={self.valid}>"

def parseHeaderElf(filename: str) -> ElfHeader:
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    c_filename = filename.encode('utf-8')
    c_hdr = _lib.c_parseHeaderElf(c_filename)
    return ElfHeader(c_hdr)

def parseSectionsElf(filename: str) -> list:
    print("PERINGATAN: parseSectionsElf belum diimplementasikan penuh di binding Python")
    return []

def parseSymbolElf(filename: str) -> list:
    print("PERINGATAN: parseSymbolElf belum diimplementasikan penuh di binding Python")
    return []