import sys

try:
    import re_tools
except ImportError:
    print("Error: Gagal mengimpor modul 're_tools' (PyO3).", file=sys.stderr)
    re_tools = None

def diffBinary(file1: str, file2: str) -> list[dict]:
    if not re_tools:
        raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat")
    
    try:
        return re_tools.diffBinary(file1, file2)
    except Exception as e:
        print(f"Error saat memanggil re_tools.diffBinary: {e}", file=sys.stderr)
        return [{"error": str(e)}]

def generateCFG(filename: str) -> str:
    if not re_tools:
        raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat")

    try:
        return re_tools.generateCFG(filename)
    except Exception as e:
        print(f"Error saat memanggil re_tools.generateCFG: {e}", file=sys.stderr)
        return f"digraph G {{ error [label=\"PyO3 Error: {e}\"]; }}"