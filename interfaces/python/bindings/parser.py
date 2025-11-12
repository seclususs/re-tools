import ctypes
import json
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
    # C_ElfHeader c_parseHeaderElf(const char* filename);
    _lib.c_parseHeaderElf.argtypes = [ctypes.c_char_p]
    _lib.c_parseHeaderElf.restype = C_ElfHeader

    # char* c_parseSectionsElf(const char* filename);
    _lib.c_parseSectionsElf.argtypes = [ctypes.c_char_p]
    _lib.c_parseSectionsElf.restype = ctypes.c_char_p

    # char* c_parseSymbolsElf(const char* filename);
    _lib.c_parseSymbolsElf.argtypes = [ctypes.c_char_p]
    _lib.c_parseSymbolsElf.restype = ctypes.c_char_p

    # void c_freeJsonString(char* s);
    _lib.c_freeJsonString.argtypes = [ctypes.c_char_p]
    _lib.c_freeJsonString.restype = None

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
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    c_filename = filename.encode('utf-8')
    json_ptr = _lib.c_parseSectionsElf(c_filename)
    
    if not json_ptr:
        print("PERINGATAN: c_parseSectionsElf (Rust) mengembalikan pointer null.")
        return []
        
    try:
        json_str = ctypes.string_at(json_ptr).decode('utf-8')
        hasil_list = json.loads(json_str)
    except Exception as e:
        print(f"Error saat parsing JSON dari c_parseSectionsElf: {e}")
        hasil_list = []
    finally:
        _lib.c_freeJsonString(json_ptr)
        
    return hasil_list

def parseSymbolElf(filename: str) -> list:
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
        
    c_filename = filename.encode('utf-8')
    json_ptr = _lib.c_parseSymbolsElf(c_filename)
    
    if not json_ptr:
        print("PERINGATAN: c_parseSymbolsElf (Rust) mengembalikan pointer null.")
        return []
        
    try:
        json_str = ctypes.string_at(json_ptr).decode('utf-8')
        hasil_list = json.loads(json_str)
    except Exception as e:
        print(f"Error saat parsing JSON dari c_parseSymbolsElf: {e}")
        hasil_list = []
    finally:
        _lib.c_freeJsonString(json_ptr)
            
    return hasil_list