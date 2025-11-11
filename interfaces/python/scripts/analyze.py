import sys
import os

# Setup Path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root_level = os.path.abspath(os.path.join(script_dir, '..'))
if project_root_level not in sys.path:
    sys.path.append(project_root_level)

try:
    from bindings import parser, disasm, analyzer
except ImportError as e:
    print(f"Gagal impor bindings: {e}. Pastikan library core sudah di-build.", file=sys.stderr)
    # Jika gagal, buat mock objects agar file setidaknya bisa diimpor
    class MockBinding:
        def __getattr__(self, name):
            def mock_func(*args, **kwargs):
                print(f"Mock {name} dipanggil (binding tidak ter-load)")
                if name == 'parseHeaderElf':
                    return {'valid': False}
                return []
            return mock_func
    parser = MockBinding()
    disasm = MockBinding()
    analyzer = MockBinding()

def lakukanAnalisisLengkap(file_path):
    """
    Workflow: parse -> disasm -> extract -> analyze.
    """
    
    hasil_analisis = {
        "file": file_path,
        "header": None,
        "disassembly_awal": [],
        "strings": [],
        "entropy": [],
        "patterns": []
    }

    print("  [1] Menjalankan Parse...")
    # Parse
    try:
        hdr = parser.parseHeaderElf(file_path)
        if hdr.valid:
            hasil_analisis["header"] = {
                "magic": hdr.magic,
                "entry_point": hex(hdr.entry_point),
                "machine": hdr.machine,
                "section_count": hdr.section_count
            }
        else:
            hasil_analisis["header"] = {"error": "Bukan file ELF yang valid"}
    except Exception as e:
        hasil_analisis["header"] = {"error": f"Gagal parse: {e}"}

    print("  [2] Menjalankan Disassembly...")
    # Disasm
    # Note: Binding disasm saat ini hanya menerima bytes.
    try:
        with open(file_path, 'rb') as f:
            bytes_awal = f.read(20)
        
        offset = 0
        while offset < len(bytes_awal):
            mnemonic, operands, size = disasm.decodeInstruksi(bytes_awal, offset)
            if size == 0:
                break # Gagal decode
            hasil_analisis["disassembly_awal"].append({
                "offset": hex(offset),
                "mnemonic": mnemonic,
                "operands": operands,
                "size": size
            })
            offset += size
    except Exception as e:
        hasil_analisis["disassembly_awal"] = [{"error": f"Gagal disasm: {e}"}]

    print("  [3] Menjalankan Extract...")
    # Extract (Strings)
    try:
        hasil_analisis["strings"] = analyzer.extractStrings(file_path, minLength=4)
    except Exception as e:
        hasil_analisis["strings"] = [{"error": f"Gagal extract strings: {e}"}]

    print("  [4] Menjalankan Analyze (Entropy & Patterns)...")
    # Analyze (Entropy)
    try:
        # Hitung entropy per 1024 byte
        hasil_analisis["entropy"] = analyzer.hitungEntropy(file_path, 1024)
    except Exception as e:
        hasil_analisis["entropy"] = [{"error": f"Gagal hitung entropy: {e}"}]
        
    # Analyze (Pattern)
    try:
        # Cari pattern "kernel"
        hasil_analisis["patterns"] = analyzer.deteksiPattern(file_path, r"(?i)kernel")
    except Exception as e:
        hasil_analisis["patterns"] = [{"error": f"Gagal deteksi pattern: {e}"}]

    return hasil_analisis

if __name__ == "__main__":
    print("Menjalankan test cepat modul analyze.py...")
    # Anda perlu mengganti ini dengan path ke file binary yang valid
    # dummy_file = "/bin/bash" # Contoh di Linux
    # dummy_file = "C:\\Windows\\System32\\kernel32.dll" # Contoh di Windows
    
    # Buat dummy file jika tidak ada
    dummy_file = "dummy_test_file.bin"
    if not os.path.exists(dummy_file):
        with open(dummy_file, "wb") as f:
            f.write(b"\x7FELF\x02\x01\x01\x00" + b"\x00"*8 + b"\x90\x90\x90\xC3")
            f.write(b"Ini adalah string tes... kernel32... dan string lain.")
    
    if os.path.exists(dummy_file):
        hasil = lakukanAnalisisLengkap(dummy_file)
        import json
        print(json.dumps(hasil, indent=2))
        os.remove(dummy_file)
    else:
        print("File tes tidak ditemukan, test dibatalkan.")