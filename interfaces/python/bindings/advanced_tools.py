import ctypes
import os
import json


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
        _lib = ctypes.CDLL(LIB_FILE) # Coba load dari path default
    except OSError:
        print(f"Gagal memuat library re-tools dari {FULL_PATH}")
        _lib = None

# Definisi Struktur C untuk ctypes
class C_DiffResult(ctypes.Structure):
    _fields_ = [
        ("functionName", ctypes.c_char * 128),
        ("addressFile1", ctypes.c_uint64),
        ("addressFile2", ctypes.c_uint64),
        ("status", ctypes.c_int) # 0=Matched, 1=Modified, 2=Removed, 3=Added
    ]

# Setup prototype fungsi C
if _lib:
    # int c_diffBinary(const char* file1, const char* file2, C_DiffResult* out_results, int max_results);
    _lib.c_diffBinary.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(C_DiffResult), ctypes.c_int]
    _lib.c_diffBinary.restype = ctypes.c_int

    # int c_generateCFG(const char* filename, char* out_buffer, int out_buffer_size);
    _lib.c_generateCFG.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    _lib.c_generateCFG.restype = ctypes.c_int
    
# Wrapper Python
def diffBinary(file1: str, file2: str) -> list[dict]:
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    c_file1 = file1.encode('utf-8')
    c_file2 = file2.encode('utf-8')
    
    MAX_RESULTS = 1024 # Batas jumlah hasil
    ResultArr = C_DiffResult * MAX_RESULTS
    c_results = ResultArr()
    
    res_count = _lib.c_diffBinary(c_file1, c_file2, c_results, MAX_RESULTS)
    
    if res_count == -1:
        raise RuntimeError(f"Buffer hasil (max {MAX_RESULTS}) tidak cukup untuk menampung semua hasil diff")
    
    # Konversi status int ke string
    status_map = { 0: "Matched", 1: "Modified", 2: "Removed", 3: "Added" }
    
    py_results = []
    for i in range(res_count):
        res = c_results[i]
        py_results.append({
            "functionName": res.functionName.decode('utf-8'),
            "addressFile1": f"0x{res.addressFile1:x}",
            "addressFile2": f"0x{res.addressFile2:x}",
            "status": status_map.get(res.status, "Unknown")
        })
    return py_results

def generateCFG(filename: str) -> str:
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
        
    c_filename = filename.encode('utf-8')
    
    # Alokasi buffer output yang sangat besar (DOT file bisa besar)
    BUFFER_SIZE = 5 * 1024 * 1024 # 5MB
    out_buffer = ctypes.create_string_buffer(BUFFER_SIZE)
    
    res = _lib.c_generateCFG(c_filename, out_buffer, BUFFER_SIZE)
    if res == -1:
        raise RuntimeError("Buffer output C terlalu kecil untuk menampung hasil DOT")
    
    return out_buffer.value.decode('utf-8')