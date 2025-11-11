import sys
import os
import json

# Setup Path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(project_root, 'interfaces', 'python'))

try:
    from bindings import parser, analyzer, advanced_tools, hexeditor
except ImportError as e:
    print(f"Error: Gagal impor bindings. Pastikan Anda sudah build di folder 'build/'.")
    print(f"Detail: {e}")
    print(f"Pastikan file library ada di {project_root}/build/lib/")
    sys.exit(1)

def buat_file_dummy(nama_file="dummy_example.bin"):
    print(f"[+] Membuat file dummy: {nama_file}")
    # Header ELF 64-bit palsu
    konten = b"\x7FELF\x02\x01\x01\x00" + (b"\x00" * 8)
    # Beberapa instruksi (PUSH RBP, MOV RBP,RSP, NOP, RET)
    konten += b"\x55\x48\x89\xE5\x90\xC3"
    # String yang bisa diekstrak
    konten += b"\x00" * 10
    konten += b"IniStringContohSatu\x00"
    konten += b"IniStringContohDua\x00"
    
    with open(nama_file, "wb") as f:
        f.write(konten)
    return nama_file

def jalankan_demo(file_target):
    print("\n--- 1. Memulai Modul Parser ---")
    try:
        hasil_header = parser.parseHeaderElf(file_target)
        if hasil_header.valid:
            print(f"  [+] Header OK. Magic: {hasil_header.magic}, Entry: {hex(hasil_header.entry_point)}")
        else:
            print("  [-] Gagal parse header ELF.")
    except Exception as e:
        print(f"  [!] Error di Parser: {e}")

    print("\n--- 2. Memulai Modul Analyzer (Strings) ---")
    try:
        list_strings = analyzer.extractStrings(file_target, minLength=5)
        print(f"  [+] Ditemukan {len(list_strings)} string:")
        for s in list_strings:
            print(f"    - {s}")
    except Exception as e:
        print(f"  [!] Error di Analyzer: {e}")
        
    print("\n--- 3. Memulai Modul HexEditor ---")
    try:
        # Baca 16 bytes pertama
        data_hex = hexeditor.lihatBytes(file_target, 0, 16)
        print(f"  [+] Hex 16 bytes pertama: {data_hex}")
    except Exception as e:
        print(f"  [!] Error di HexEditor: {e}")

    print("\n--- 4. Memulai Modul Advanced (CFG) ---")
    try:
        # CFG generator saat ini sangat sederhana
        dot_graph = advanced_tools.generateCFG(file_target)
        print(f"  [+] Sukses generate CFG (DOT format). Ukuran: {len(dot_graph)} bytes.")
        # print(dot_graph[:200] + "...") # Uncomment untuk lihat output
    except Exception as e:
        print(f"  [!] Error di Advanced/CFG: {e}")

def main():
    nama_file_demo = "dummy_example.bin"
    try:
        target = buat_file_dummy(nama_file_demo)
        jalankan_demo(target)
    finally:
        if os.path.exists(nama_file_demo):
            os.remove(nama_file_demo)
            print(f"\n[+] File dummy '{nama_file_demo}' telah dihapus.")

if __name__ == "__main__":
    main()