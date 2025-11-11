import json
import csv
import sys
import os

def buatLaporanJSON(data, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
    except IOError as e:
        print(f"Error: Gagal menulis file JSON {output_file}: {e}", file=sys.stderr)
    except TypeError as e:
        print(f"Error: Data tidak bisa di-serialize ke JSON: {e}", file=sys.stderr)

def buatLaporanCSV(data, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            
            # Baris Header
            writer.writerow(["File", data.get("file", "N/A")])
            writer.writerow([]) # Baris kosong
            
            # Info Header
            writer.writerow(["Header", "Value"])
            header_data = data.get("header", {})
            if header_data:
                for key, val in header_data.items():
                    writer.writerow([f"Header_{key}", val])
            writer.writerow([])
            
            # Strings
            writer.writerow(["Found Strings (max 100)"])
            strings = data.get("strings", [])
            for s in strings[:100]:
                writer.writerow([s])
            if len(strings) > 100:
                 writer.writerow([f"... dan {len(strings) - 100} string lainnya."])
            writer.writerow([])

            # Entropy
            writer.writerow(["Block", "Entropy"])
            entropy = data.get("entropy", [])
            for i, e_val in enumerate(entropy):
                 writer.writerow([i, e_val])
            writer.writerow([])
            
            # Disassembly
            writer.writerow(["Offset", "Mnemonic", "Operands"])
            disasm = data.get("disassembly_awal", [])
            for instr in disasm:
                if "error" in instr:
                    writer.writerow(["ERROR", instr['error'], ""])
                else:
                    ops = ", ".join(instr.get("operands", []))
                    writer.writerow([instr.get("offset"), instr.get("mnemonic"), ops])
            
    except IOError as e:
        print(f"Error: Gagal menulis file CSV {output_file}: {e}", file=sys.stderr)

def buatLaporan(data, format_laporan, file_output):
    if format_laporan == "json":
        buatLaporanJSON(data, file_output)
    elif format_laporan == "csv":
        buatLaporanCSV(data, file_output)
    else:
        print(f"Error: Format laporan '{format_laporan}' tidak dikenal.", file=sys.stderr)