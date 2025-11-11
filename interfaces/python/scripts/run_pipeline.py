"""
Contoh Penggunaan:
python run_pipeline.py /path/to/binary --format json --output hasil.json
"""

import argparse
import sys
import os

# Setup Path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root_level = os.path.abspath(os.path.join(script_dir, '..'))
sys.path.append(project_root_level)
sys.path.append(script_dir)

try:
    import analyze
    import report
except ImportError as e:
    print(f"Error: Gagal mengimpor modul. Pastikan script ini dijalankan dari direktorinya.", file=sys.stderr)
    print(f"Detail error: {e}", file=sys.stderr)
    print(f"Sys.path saat ini: {sys.path}", file=sys.stderr)
    sys.exit(1)

def jalankanPipeline(file_path, format_laporan, file_output):
    print(f"[*] Memulai pipeline untuk: {file_path}")
    
    # Parse, Disasm, Extract, Analyze
    try:
        data_analisis = analyze.lakukanAnalisisLengkap(file_path)
        print("[+] Analisis selesai.")
    except Exception as e:
        print(f"[!] Gagal saat tahap analisis: {e}", file=sys.stderr)
        return

    # Report
    try:
        report.buatLaporan(data_analisis, format_laporan, file_output)
        print(f"[+] Laporan berhasil dibuat: {file_output}")
    except Exception as e:
        print(f"[!] Gagal saat tahap pelaporan: {e}", file=sys.stderr)
        return

def main():
    parser = argparse.ArgumentParser(description="re-tools Python Pipeline Script")
    parser.add_argument("file_path", help="Path ke file binary yang akan dianalisis.")
    parser.add_argument("--format", 
                        choices=["json", "csv"], 
                        default="json", 
                        help="Format output laporan (default: json).")
    parser.add_argument("--output", 
                        "-o", 
                        default="retools_report", 
                        help="Nama file output (tanpa ekstensi).")

    args = parser.parse_args()

    # Buat nama file output lengkap
    output_filename = f"{args.output}.{args.format}"
    
    if not os.path.exists(args.file_path):
        print(f"Error: File tidak ditemukan di {args.file_path}", file=sys.stderr)
        sys.exit(1)

    jalankanPipeline(args.file_path, args.format, output_filename)

if __name__ == "__main__":
    main()