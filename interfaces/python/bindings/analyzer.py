import sys

try:
    import re_tools
except ImportError:
    print("Error: Gagal mengimpor modul 're_tools' (PyO3).", file=sys.stderr)
    re_tools = None

def extractStrings(filename: str, minLength: int = 4) -> list[str]:
    if not re_tools:
        raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat. Fungsi extractStrings gagal.")
    
    try:
        return re_tools.ekstrakStrings(filename, minLength)
    except Exception as e:
        print(f"Error in extractStrings (PyO3 call): {e}", file=sys.stderr)
        return []

def deteksiPattern(filename: str, regex: str) -> list[str]:
    if not re_tools:
        raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat. Fungsi deteksiPattern gagal.")
        
    try:
        return re_tools.deteksiPattern(filename, regex)
    except Exception as e:
        print(f"Error in deteksiPattern (PyO3 call): {e}", file=sys.stderr)
        return []

def hitungEntropy(filename: str, blockSize: int) -> list[float]:
    if not re_tools:
        raise RuntimeError("Modul 're_tools' (PyO3) tidak termuat. Fungsi hitungEntropy gagal.")
    
    try:
        return re_tools.hitungEntropy(filename, blockSize)
    except Exception as e:
        print(f"Error in hitungEntropy (PyO3 call): {e}", file=sys.stderr)
        return []