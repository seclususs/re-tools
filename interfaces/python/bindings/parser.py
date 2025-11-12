import ctypes
from utils.lib_loader import _lib

# Definisi Struktur C untuk ctypes
class C_ElfHeader(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_char * 5),
        ("entry_point", ctypes.c_uint64),
        ("machine", ctypes.c_uint16),
        ("section_count", ctypes.c_uint16),
        ("valid", ctypes.c_int),
        ("ukuran_file_size", ctypes.c_uint64),
        ("padding", ctypes.c_uint64)
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
        self.file_size = c_hdr.ukuran_file_size

    def __repr__(self):
        return f"<ElfHeader magic={self.magic} entry=0x{self.entry_point:x} valid={self.valid}>"

def parseHeaderElf(filename: str) -> ElfHeader:
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    c_filename = filename.encode('utf-8')
    c_hdr = _lib.c_parseHeaderElf(c_filename)
    return ElfHeader(c_hdr)

def parseSectionsElf(filename: str) -> list:
    print("PERINGATAN: parseSectionsElf (C++) telah dihapus.")
    print("PERINGATAN: Implementasi C-ABI untuk 'sections' belum dibuat.")
    return []

def parseSymbolElf(filename: str) -> list:
    print("PERINGATAN: parseSymbolElf (C++) telah dihapus.")
    print("PERINGATAN: Implementasi C-ABI untuk 'symbols' belum dibuat.")
    return []