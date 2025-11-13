import ctypes
from utils.lib_loader import _lib

# Definisi Struct C-ABI
class C_HeaderInfo(ctypes.Structure):
    _fields_ = [
        ("valid", ctypes.c_int32),
        ("format", ctypes.c_char * 64),
        ("arch", ctypes.c_char * 64),
        ("bits", ctypes.c_uint16),
        ("entry_point", ctypes.c_uint64),
        ("machine_id", ctypes.c_uint64),
        ("is_lib", ctypes.c_int32),
        ("file_size", ctypes.c_uint64),
    ]

class C_SectionInfo(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 128),
        ("addr", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("offset", ctypes.c_uint64),
        ("tipe", ctypes.c_uint32),
    ]

class C_SymbolInfo(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 128),
        ("addr", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("symbol_type", ctypes.c_char * 64),
        ("bind", ctypes.c_char * 64),
    ]

# Setup prototype fungsi C
if _lib:
    # int32_t c_getBinaryHeader(const char* filename, C_HeaderInfo* out_header);
    _lib.c_getBinaryHeader.argtypes = [ctypes.c_char_p, ctypes.POINTER(C_HeaderInfo)]
    _lib.c_getBinaryHeader.restype = ctypes.c_int32

    # int32_t c_getDaftarSections(const char* filename, C_SectionInfo* out_buffer, int32_t max_count);
    _lib.c_getDaftarSections.argtypes = [ctypes.c_char_p, ctypes.POINTER(C_SectionInfo), ctypes.c_int32]
    _lib.c_getDaftarSections.restype = ctypes.c_int32

    # int32_t c_getDaftarSimbol(const char* filename, C_SymbolInfo* out_buffer, int32_t max_count);
    _lib.c_getDaftarSimbol.argtypes = [ctypes.c_char_p, ctypes.POINTER(C_SymbolInfo), ctypes.c_int32]
    _lib.c_getDaftarSimbol.restype = ctypes.c_int32


def parseBinaryHeader(filename: str) -> dict:
    """
    Parse header binary (ELF, PE, Mach-O) secara generik.
    Mengembalikan dict hasil parse.
    """
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    c_filename = filename.encode('utf-8')
    c_header = C_HeaderInfo()
    
    result = _lib.c_getBinaryHeader(c_filename, ctypes.byref(c_header))
    
    if result != 0:
        # Gagal parse, kembalikan info invalid
        return {"valid": False, "error": "Gagal parse header di C-level"}

    # Konversi C_HeaderInfo ke dict
    return {
        "valid": bool(c_header.valid),
        "format": c_header.format.decode('utf-8'),
        "arch": c_header.arch.decode('utf-8'),
        "bits": c_header.bits,
        "entry_point": c_header.entry_point,
        "machine_id": c_header.machine_id,
        "is_lib": bool(c_header.is_lib),
        "file_size": c_header.file_size,
    }

def parseSectionsElf(filename: str) -> list:
    """
    Parse ELF Sections.
    Mengembalikan list hasil parse.
    """
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    c_filename = filename.encode('utf-8')
    
    MAX_SECTIONS = 256 # Batas alokasi buffer
    BufferArray = C_SectionInfo * MAX_SECTIONS
    c_buffer = BufferArray()
    
    count = _lib.c_getDaftarSections(c_filename, c_buffer, MAX_SECTIONS)
    
    if count < 0:
        raise RuntimeError(f"Gagal get sections. Buffer (max {MAX_SECTIONS}) mungkin tidak cukup.")
        
    py_list = []
    for i in range(count):
        c_sec = c_buffer[i]
        py_list.append({
            "name": c_sec.name.decode('utf-8'),
            "addr": c_sec.addr,
            "size": c_sec.size,
            "offset": c_sec.offset,
            "tipe": c_sec.tipe,
        })
        
    return py_list

def parseSymbolElf(filename: str) -> list:
    """
    Parse ELF Symbols.
    Mengembalikan list hasil parse.
    """
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
        
    c_filename = filename.encode('utf-8')
    
    MAX_SYMBOLS = 4096 # Batas alokasi buffer
    BufferArray = C_SymbolInfo * MAX_SYMBOLS
    c_buffer = BufferArray()

    count = _lib.c_getDaftarSimbol(c_filename, c_buffer, MAX_SYMBOLS)

    if count < 0:
        raise RuntimeError(f"Gagal get simbol. Buffer (max {MAX_SYMBOLS}) mungkin tidak cukup.")
            
    py_list = []
    for i in range(count):
        c_sym = c_buffer[i]
        py_list.append({
            "name": c_sym.name.decode('utf-8'),
            "addr": c_sym.addr,
            "size": c_sym.size,
            "symbol_type": c_sym.symbol_type.decode('utf-8'),
            "bind": c_sym.bind.decode('utf-8'),
        })
            
    return py_list