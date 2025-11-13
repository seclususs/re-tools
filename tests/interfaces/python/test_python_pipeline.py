import unittest
import os
import sys
import subprocess
import json

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_CURRENT_DIR, '..', '..', '..'))
_PACKAGE_ROOT = os.path.join(_PROJECT_ROOT, 'interfaces', 'python')

if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)

PIPELINE_SCRIPT = os.path.join(_PACKAGE_ROOT, 'scripts', 'run_pipeline.py')

VENV_PYTHON = None
if 'VIRTUAL_ENV' in os.environ:
    if os.name == 'nt':
        VENV_PYTHON = os.path.join(os.environ['VIRTUAL_ENV'], 'Scripts', 'python.exe')
    else:
        VENV_PYTHON = os.path.join(os.environ['VIRTUAL_ENV'], 'bin', 'python')

PYTHON_EXECUTABLE_TO_USE = VENV_PYTHON if VENV_PYTHON and os.path.exists(VENV_PYTHON) else sys.executable
print(f"INFO: Menggunakan Python executable untuk tes: {PYTHON_EXECUTABLE_TO_USE}", file=sys.stderr)

try:
    from scripts import analyze
    from scripts import report
except ImportError as e:
    print(f"Gagal impor modul tes. Pastikan path sudah benar. {e}", file=sys.stderr)
    print(f"SYS.PATH: {sys.path}", file=sys.stderr)
    print(f"PYTHONPATH: {os.environ.get('PYTHONPATH')}", file=sys.stderr)
    print("FATAL: Tes tidak dapat dilanjutkan tanpa modul.", file=sys.stderr)
    analyze = None
    report = None
except Exception as e_gen:
    print(f"Error tak terduga saat impor: {e_gen}", file=sys.stderr)
    analyze = None
    report = None


class TestPythonPipeline(unittest.TestCase):

    dummy_file = "test_dummy_binary.bin"
    report_json = "test_report.json"
    report_csv = "test_report.csv"
    hasil_analisis = {}

    @classmethod
    def setUpClass(cls):
        if not analyze or not report:
            cls.hasil_analisis = {"error": "Gagal impor modul 'analyze' atau 'report' di awal."}
            print("ERROR: Modul 'analyze' atau 'report' tidak ditemukan.", file=sys.stderr)
            return

        elf_header = (
            b"\x7FELF\x02\x01\x01\x00" + b"\x00" * 8 +
            b"\x02\x00" +
            b"\x3E\x00" +
            b"\x01\x00\x00\x00" +
            b"\x80\x00\x00\x00\x00\x00\x00\x00" +
            b"\x00" * (64 - 32)
        )

        dummy_content = (
            elf_header +
            b"\x90\x90\x90" +
            b"\xC3" +
            b"\x00" * 20 +
            b"Ini string pertama (test1)\x00" +
            b"Ini string kedua (test2)\x00" +
            b"test_pattern_xyz\x00"
        )
        with open(cls.dummy_file, "wb") as f:
            f.write(dummy_content)
            
        try:
            cls.hasil_analisis = analyze.lakukanAnalisisLengkap(cls.dummy_file)
        except ImportError as e:
             cls.hasil_analisis = {"error": f"Gagal di setUpClass (ImportError): {e}. Kemungkinan modul PyO3 're_tools' tidak ter-build."}
        except Exception as e:
            cls.hasil_analisis = {"error": f"Gagal di setUpClass (Exception): {e}"}

    @classmethod
    def tearDownClass(cls):
        files_to_remove = [cls.dummy_file, cls.report_json, cls.report_csv]
        for f in files_to_remove:
            if os.path.exists(f):
                os.remove(f)

    def test_01_analyze_module(self):
        hasil = self.hasil_analisis
        
        self.assertNotIn("error", hasil, f"Analisis gagal di setUpClass: {hasil.get('error')}")
        self.assertIn("file", hasil)
        self.assertEqual(hasil["file"], self.dummy_file)
        self.assertIn("header", hasil)
        self.assertIsNone(hasil["header"].get("error"), 
                          f"Analisis header gagal: {hasil['header'].get('error')}")
        self.assertTrue(hasil["header"].get("valid"), "Header seharusnya valid")
        self.assertEqual(hasil["header"].get("format"), "ELF")
        self.assertEqual(hasil["header"].get("machine_id"), 62)
        self.assertIn("strings", hasil)
        self.assertIsInstance(hasil["strings"], list, "Hasil strings seharusnya berupa list")
        string_list = " ".join(hasil.get("strings", []))
        self.assertIn("Ini string pertama (test1)", string_list)
        self.assertIn("Ini string kedua (test2)", string_list)
        self.assertIn("disassembly_awal", hasil)
        self.assertGreater(len(hasil["disassembly_awal"]), 0)
        found_nop = any(instr.get("mnemonic") == "NOP" for instr in hasil["disassembly_awal"])
        self.assertTrue(found_nop, "Seharusnya menemukan instruksi NOP setelah header")

    def test_02_report_module_json(self):
        if not report:
            self.skipTest("Modul 'report' gagal diimpor")
            
        dummy_data = {"file": "test", "header": {"entry_point": "0x123"}, "strings": ["abc"]}
        report.buatLaporan(dummy_data, "json", self.report_json)
        self.assertTrue(os.path.exists(self.report_json))
        with open(self.report_json, 'r') as f:
            data = json.load(f)
        self.assertEqual(data["file"], "test")
        self.assertEqual(data["header"]["entry_point"], "0x123")

    def test_03_report_module_csv(self):
        if not report:
            self.skipTest("Modul 'report' gagal diimpor")
            
        dummy_data = {"file": "test_csv", "header": {"valid": True}, "strings": ["csv_string"]}
        report.buatLaporan(dummy_data, "csv", self.report_csv)
        self.assertTrue(os.path.exists(self.report_csv))
        with open(self.report_csv, 'r') as f:
            content = f.read()
        self.assertIn("test_csv", content)
        self.assertIn("csv_string", content)

    def test_04_pipeline_script_execution(self):
        if not report or not analyze:
            self.skipTest("Modul 'report' atau 'analyze' gagal diimpor")

        output_filename = "pipeline_test_output.json"
        if os.path.exists(output_filename):
            os.remove(output_filename)

        command = [
            PYTHON_EXECUTABLE_TO_USE,
            PIPELINE_SCRIPT,
            self.dummy_file,
            "--format", "json",
            "--output", "pipeline_test_output"
        ]
        
        test_env = os.environ.copy()
        cwd_path = os.getcwd()
        
        print(f"INFO: Menjalankan tes pipeline di CWD: {cwd_path}", file=sys.stderr)
        print(f"INFO: Perintah: {' '.join(command)}", file=sys.stderr)
        py_path = test_env.get('PYTHONPATH', '')
        norm_pkg_path = os.path.normpath(_PACKAGE_ROOT)
        py_path_parts = [os.path.normpath(p) for p in py_path.split(os.pathsep) if p]
        if norm_pkg_path not in py_path_parts:
            test_env['PYTHONPATH'] = f"{_PACKAGE_ROOT}{os.pathsep}{py_path}"
        
        print(f"INFO: PYTHONPATH untuk tes: {test_env['PYTHONPATH']}", file=sys.stderr)
        try:
            result = subprocess.run(command, 
                                    capture_output=True, 
                                    text=True, 
                                    check=True, 
                                    encoding='utf-8',
                                    env=test_env,
                                    cwd=cwd_path)
        except subprocess.CalledProcessError as e:
            print("\n--- STDOUT (Subproses Gagal) ---", file=sys.stderr)
            print(e.stdout, file=sys.stderr)
            print("\n--- STDERR (Subproses Gagal) ---", file=sys.stderr)
            print(e.stderr, file=sys.stderr)
            print("----------------------------------", file=sys.stderr)
            self.fail(f"Eksekusi pipeline script gagal: {e.stderr}")
            return
        
        self.assertIn("[+] Analisis selesai.", result.stdout)
        self.assertIn(f"[+] Laporan berhasil dibuat: {output_filename}", result.stdout)
        output_file_path = os.path.join(cwd_path, output_filename)
        self.assertTrue(os.path.exists(output_file_path), f"File output {output_file_path} tidak ditemukan")
        if os.path.exists(output_file_path):
            os.remove(output_file_path)

if __name__ == "__main__":
    unittest.main()