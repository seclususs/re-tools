import ctypes
import json
import sys
from utils.lib_loader import _lib

# Setup prototype fungsi C
if _lib:
    # int c_extractStrings(const char* filename, int minLength, char* out_buffer, int out_buffer_size);
    _lib.c_extractStrings.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    _lib.c_extractStrings.restype = ctypes.c_int

    # int c_hitungEntropy(const char* filename, int blockSize, double* out_entropies, int max_entropies);
    _lib.c_hitungEntropy.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_double), ctypes.c_int]
    _lib.c_hitungEntropy.restype = ctypes.c_int

    # int c_deteksiPattern(const char* filename, const char* regex_str, char* out_buffer, int out_buffer_size);
    _lib.c_deteksiPattern.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    _lib.c_deteksiPattern.restype = ctypes.c_int

# Wrapper Python
def _get_json_from_c_buffer(c_func, *args) -> list:
    BUFFER_SIZE = 10 * 1024 * 1024 # 10MB
    out_buffer = ctypes.create_string_buffer(BUFFER_SIZE)
    all_args = list(args) + [out_buffer, BUFFER_SIZE]
    res = c_func(*all_args)
    if res == -1:
        raise RuntimeError("Buffer output C terlalu kecil untuk menampung hasil JSON")
    json_str = out_buffer.value.decode('utf-8')
    return json.loads(json_str)

def extractStrings(filename: str, minLength: int = 4) -> list[str]:
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    c_filename = filename.encode('utf-8')
    
    try:
        data_objek = _get_json_from_c_buffer(
            _lib.c_extractStrings, 
            c_filename, 
            minLength
        )
        
        # Ekstrak hanya 'content'
        list_string_polos = [item.get("content", "") for item in data_objek]
        return list_string_polos
        
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from c_extractStrings: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Error in extractStrings: {e}", file=sys.stderr)
        return []


def deteksiPattern(filename: str, regex: str) -> list[str]:
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
        
    c_filename = filename.encode('utf-8')
    c_regex = regex.encode('utf-8')
    return _get_json_from_c_buffer(_lib.c_deteksiPattern, c_filename, c_regex)

def hitungEntropy(filename: str, blockSize: int) -> list[float]:
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    c_filename = filename.encode('utf-8')
    
    # Alokasi buffer
    MAX_BLOCKS = 10000 # Asumsi batas atas
    ResultArr = ctypes.c_double * MAX_BLOCKS
    c_results = ResultArr()
    
    res_count = _lib.c_hitungEntropy(c_filename, blockSize, c_results, MAX_BLOCKS)
    
    if res_count == -1:
        raise RuntimeError(f"Buffer hasil (max {MAX_BLOCKS}) tidak cukup untuk menampung semua hasil entropy")
        
    return [c_results[i] for i in range(res_count)]