import ctypes
from utils.lib_loader import _lib

# Setup prototype fungsi C
if _lib:
    # int c_lihatBytes(const char* filename, int offset, int length, char* out_buffer, int out_buffer_size);
    _lib.c_lihatBytes.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    _lib.c_lihatBytes.restype = ctypes.c_int

    # int c_ubahBytes(const char* filename, int offset, const uint8_t* data, int data_len);
    _lib.c_ubahBytes.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    _lib.c_ubahBytes.restype = ctypes.c_int

    # int c_cariPattern(const char* filename, const uint8_t* pattern, int pattern_len, int* out_offsets, int max_offsets);
    _lib.c_cariPattern.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_int]
    _lib.c_cariPattern.restype = ctypes.c_int

# Wrapper Python
def lihatBytes(filename: str, offset: int, length: int) -> str:
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    # Alokasi buffer output yang besar (semoga cukup)
    # (length * 3) karena "XX " per byte
    buffer_size = (length * 3) + 100 # buffer ekstra
    out_buffer = ctypes.create_string_buffer(buffer_size)
    c_filename = filename.encode('utf-8')

    res = _lib.c_lihatBytes(c_filename, offset, length, out_buffer, buffer_size)
    if res == -1:
        raise RuntimeError("Buffer output terlalu kecil atau error saat baca file")
    
    return out_buffer.value.decode('utf-8')

def ubahBytes(filename: str, offset: int, data: bytes) -> bool:
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
        
    c_filename = filename.encode('utf-8')
    data_len = len(data)
    # Konversi bytes Python ke array C uint8_t
    ByteArr = ctypes.c_ubyte * data_len
    c_data = ByteArr.from_buffer_copy(data)

    res = _lib.c_ubahBytes(c_filename, offset, c_data, data_len)
    return res == 1

def cariPattern(filename: str, pattern: bytes) -> list[int]:
    if not _lib:
        raise RuntimeError("Library re-tools core tidak termuat")
    
    c_filename = filename.encode('utf-8')
    pattern_len = len(pattern)
    PatternArr = ctypes.c_ubyte * pattern_len
    c_pattern = PatternArr.from_buffer_copy(pattern)

    # Siapkan buffer untuk hasil
    MAX_RESULTS = 1024 # Batas jumlah hasil (bisa disesuaikan)
    OffsetArr = ctypes.c_int * MAX_RESULTS
    c_offsets = OffsetArr()

    res_count = _lib.c_cariPattern(c_filename, c_pattern, pattern_len, c_offsets, MAX_RESULTS)
    
    if res_count == -1:
        raise RuntimeError(f"Buffer hasil (max {MAX_RESULTS}) tidak cukup untuk menampung semua offset")
    
    return [c_offsets[i] for i in range(res_count)]