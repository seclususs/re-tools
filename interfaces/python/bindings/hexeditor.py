import sys

try:
    import re_tools
except ImportError:
    print("Error: Gagal mengimpor modul 're_tools' (PyO3).", file=sys.stderr)
    re_tools = None

def lihatBytes(filename: str, offset: int, length: int) -> str:
    if not re_tools:
        raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat")
    
    try:
        return re_tools.lihatBytes(filename, offset, length)
    except Exception as e:
        return f"ERROR: {e}"

def ubahBytes(filename: str, offset: int, data: bytes) -> bool:
    if not re_tools:
        raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat")
        
    try:
        return re_tools.ubahBytes(filename, offset, data)
    except Exception:
        return False

def cariPattern(filename: str, pattern: bytes) -> list[int]:
    if not re_tools:
        raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat")
    
    try:
        return [int(offset) for offset in re_tools.cariPattern(filename, pattern)]
    except Exception:
        return []