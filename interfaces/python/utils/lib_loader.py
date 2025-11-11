import ctypes
import os
import sys

def _load_library():
    if os.name == 'nt':
        LIB_FILE = 'libretools_core.dll'
    else:
        LIB_FILE = 'libretools_core.so'

    _lib = None
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
    LIB_PATH = os.path.join(project_root, 'build', 'lib')
    FULL_PATH = os.path.join(LIB_PATH, LIB_FILE)

    try:
        _lib = ctypes.CDLL(LIB_FILE)
        return _lib
    except OSError as e1:
        try:
            if os.path.exists(FULL_PATH):
                if sys.version_info >= (3, 8) and os.name == 'nt':
                    os.add_dll_directory(LIB_PATH)
                    _lib = ctypes.CDLL(LIB_FILE)
                else:
                    _lib = ctypes.CDLL(FULL_PATH)
                return _lib
            else:
                raise FileNotFoundError(f"File tidak ditemukan di path yang dihitung: {FULL_PATH}")
        except OSError as e2:
            print(f"--- FATAL ERROR (Python Bindings) ---", file=sys.stderr)
            print(f"Gagal memuat library re-tools: '{LIB_FILE}'", file=sys.stderr)
            print(f"  Percobaan 1 (Nama Saja): {e1}", file=sys.stderr)
            print(f"  Percobaan 2 (Path Lengkap): {e2}", file=sys.stderr)
            print("\nPastikan:", file=sys.stderr)
            print(f"1. Anda sudah build project (cmake --build build).", file=sys.stderr)
            print(f"2. File library ada di: '{FULL_PATH}'", file=sys.stderr)
            print(f"3. (Windows/MinGW) Dependensi (libstdc++-*.dll, dll.) ada di '{LIB_PATH}'.", file=sys.stderr)
            print(f"----------------------------------------", file=sys.stderr)
            return None

_lib = _load_library()