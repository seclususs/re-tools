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
    raise e

# Konstanta Machine ID
# ELF (e_machine)
EM_X86_64 = 62
EM_AARCH64 = 183
EM_ARM = 40
EM_386 = 3
# PE (IMAGE_FILE_MACHINE_...)
PE_AMD64 = 0x8664 # 34404
PE_I386 = 0x014c  # 332
PE_ARM64 = 0xAA64 # 43620
PE_ARMNT = 0x01c4 # 452
# Mach-O (cputype)
# (Nilai 64-bit mask adalah 0x01000000)
MACHO_X86_64 = 7 | 0x01000000
MACHO_X86 = 7
MACHO_ARM64 = 12 | 0x01000000
MACHO_ARM = 12


def tentukanArsitektur(machine_id: int) -> int:
    """Konversi nilai machine ID dari ELF/PE/Mach-O header ke enum ArsitekturDisasm."""
    if machine_id in (EM_X86_64, PE_AMD64, MACHO_X86_64):
        return disasm.ARCH_X86_64
    elif machine_id in (EM_AARCH64, PE_ARM64, MACHO_ARM64):
        return disasm.ARCH_ARM_64
    elif machine_id in (EM_ARM, PE_ARMNT, MACHO_ARM):
        return disasm.ARCH_ARM_32
    elif machine_id in (EM_386, PE_I386, MACHO_X86):
        return disasm.ARCH_X86_32
    else:
        return disasm.ARCH_UNKNOWN

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
    
    arch_id_disasm = disasm.ARCH_UNKNOWN
    base_va = 0 # Base VA dari file (entry point sering dipakai)

    print("  [1] Menjalankan Parse...")
    # Parse
    try:
        # Panggil fungsi BARU, dapat dict
        hdr_dict = parser.parseBinaryHeader(file_path)
        hasil_analisis["header"] = hdr_dict # Simpan semua info
        
        if hdr_dict.get("valid"):
            machine_id = hdr_dict.get("machine_id", 0)
            base_va = hdr_dict.get("entry_point", 0)
            # Tentukan arsitektur dari header
            arch_id_disasm = tentukanArsitektur(machine_id)
            print(f"    [Info] Format: {hdr_dict.get('format')}, Arch: {hdr_dict.get('arch')}, (ID: {machine_id})")
            print(f"    [Info] Mode disasm diatur ke: {arch_id_disasm}")
        else:
            hasil_analisis["header"] = {"valid": False, "error": "Format file tidak dikenal"}
            # Fallback jika bukan ELF (mungkin raw binary)
            arch_id_disasm = disasm.ARCH_X86_64
            print("    [Warning] Gagal parse header, fallback ke disasm X86-64")
    except Exception as e:
        hasil_analisis["header"] = {"valid": False, "error": f"Gagal parse: {e}"}
        arch_id_disasm = disasm.ARCH_X86_64
        print(f"    [Error] Gagal parse: {e}, fallback ke disasm X86-64")

    print("  [2] Menjalankan Disassembly...")
    # Disasm
    try:
        with open(file_path, 'rb') as f:
            bytes_awal = f.read(100) 
        
        offset = 0
        # Coba skip header jika format diketahui
        if hdr_dict.get("format") == "ELF" and hdr_dict.get("bits") == 64:
             offset = 0x40 # Ukuran header ELF64
             if base_va > offset:
                 offset = 64
        elif hdr_dict.get("format") == "PE":
             offset = 0 
             pass # TODO: Cari offset .text
        
        file_base_va = 0
        
        max_offset = offset + 30 # Batasi disasm 30 bytes dari offset
        
        while offset < max_offset and offset < len(bytes_awal):
            mnemonic, operands, size = disasm.decodeInstruksi(bytes_awal, offset, arch_id_disasm, file_base_va)
            if size == 0:
                break # Gagal decode
            hasil_analisis["disassembly_awal"].append({
                "offset": hex(offset),
                "va": hex(file_base_va + offset), # Tampilkan VA
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
        hasil_analisis["entropy"] = analyzer.hitungEntropy(file_path, 1024)
    except Exception as e:
        hasil_analisis["entropy"] = [{"error": f"Gagal hitung entropy: {e}"}]
        
    # Analyze (Pattern)
    try:
        hasil_analisis["patterns"] = analyzer.deteksiPattern(file_path, r"(?i)kernel")
    except Exception as e:
        hasil_analisis["patterns"] = [{"error": f"Gagal deteksi pattern: {e}"}]

    return hasil_analisis

if __name__ == "__main__":
    print("Menjalankan test cepat modul analyze.py...")
    # Buat dummy file jika tidak ada
    dummy_file = "dummy_test_file.bin"
    if not os.path.exists(dummy_file):
        with open(dummy_file, "wb") as f:
            # ELF 64-bit (Machine 62), 64 bytes
            elf_header = (
                b"\x7FELF\x02\x01\x01\x00" + b"\x00" * 8 +  # 16 bytes
                b"\x02\x00" +  # e_type (EXEC)
                b"\x3E\x00" +  # e_machine (X86_64 / 62)
                b"\x01\x00\x00\x00" +  # e_version
                b"\x40\x00\x00\x00\x00\x00\x00\x00" +  # e_entry (0x40)
                b"\x00" * (64 - 32) # Pad sisanya sampai 64 bytes
            )
            f.write(elf_header) 
            f.write(b"\x90\x90\x90\xC3") # NOPs, RET (di offset 64)
            f.write(b"Ini adalah string tes... kernel32... dan string lain.")
    
    if os.path.exists(dummy_file):
        hasil = lakukanAnalisisLengkap(dummy_file)
        import json
        print(json.dumps(hasil, indent=2))
        os.remove(dummy_file)
    else:
        print("File tes tidak ditemukan, test dibatalkan.")