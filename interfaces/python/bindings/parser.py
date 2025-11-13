import ctypes
import sys

try:
    import re_tools
except ImportError:
    print("Error: Gagal mengimpor modul 're_tools' (PyO3).", file=sys.stderr)
    re_tools = None

def parseBinaryHeader(filename: str) -> dict:
    if not re_tools:
        raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat.")
    
    try:
        return re_tools.parseHeaderInfo(filename)
    except Exception as e:
        return {"valid": False, "error": f"PyO3 call failed: {e}"}

def parseSectionsElf(filename: str) -> list:
    raise NotImplementedError("Fungsi parseSectionsElf belum dimigrasikan ke PyO3.")

def parseSymbolElf(filename: str) -> list:
    raise NotImplementedError("Fungsi parseSymbolElf belum dimigrasikan ke PyO3.")