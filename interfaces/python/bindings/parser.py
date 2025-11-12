import ctypes
import json
from utils.lib_loader import _lib


# Setup prototype fungsi C
if _lib:

    # char* c_parseBinaryHeader(const char* filename);
    _lib.c_parseBinaryHeader.argtypes = [ctypes.c_char_p]
    _lib.c_parseBinaryHeader.restype = ctypes.c_char_p

    # char* c_parseSectionsElf(const char* filename);
    _lib.c_parseSectionsElf.argtypes = [ctypes.c_char_p]
    _lib.c_parseSectionsElf.restype = ctypes.c_char_p

    # char* c_parseSymbolsElf(const char* filename);
    _lib.c_parseSymbolsElf.argtypes = [ctypes.c_char_p]
    _lib.c_parseSymbolsElf.restype = ctypes.c_char_p

    # void c_freeJsonString(char* s);
    _lib.c_freeJsonString.argtypes = [ctypes.c_char_p]
    _lib.c_freeJsonString.restype = None

def _parse_json_from_c(func_ptr, c_filename) -> dict:
    """Helper internal untuk memanggil C-func yang mengembalikan JSON string."""
    json_ptr = func_ptr(c_filename)
    if not json_ptr:
        print(f"PERINGATAN: {func_ptr.__name__} (Rust) mengembalikan pointer null.")
        return {} # Kembalikan dict kosong
        
    try:
        json_str = ctypes.string_at(json_ptr).decode('utf-8')
        hasil_dict = json.loads(json_str)
    except Exception as e:
        print(f"Error saat parsing JSON dari {func_ptr.__name__}: {e}")
        hasil_dict = {"error": str(e)}
    finally:
        _lib.c_freeJsonString(json_ptr)
            
    return hasil_dict

def parseBinaryHeader(filename: str) -> dict:
    """
    Parse header binary (ELF, PE, Mach-O) secara generik.
    Mengembalikan dict hasil parse JSON.
    """
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    c_filename = filename.encode('utf-8')
    return _parse_json_from_c(_lib.c_parseBinaryHeader, c_filename)

def parseSectionsElf(filename: str) -> list:
    """
    Parse ELF Sections.
    Mengembalikan list hasil parse JSON.
    """
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    c_filename = filename.encode('utf-8')
    # parseSectionsElf mengembalikan list (array JSON)
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
    """
    Parse ELF Symbols.
    Mengembalikan list hasil parse JSON.
    """
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