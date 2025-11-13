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

try:
    from scripts import analyze
    from scripts import report
except ImportError as e:
    print(f"Gagal impor modul tes. Pastikan path sudah benar. {e}", file=sys.stderr)
    print(f"SYS.PATH: {sys.path}", file=sys.stderr)
    print(f"PYTHONPATH: {os.environ.get('PYTHONPATH')}", file=sys.stderr)
    sys.exit(1)

class TestPythonPipeline(unittest.TestCase):

    dummy_file = "test_dummy_binary.bin"
    report_json = "test_report.json"
    report_csv = "test_report.csv"
    hasil_analisis = {}

    @classmethod
    def setUpClass(cls):
        elf_header = (
            b"\x7FELF\x02\x01\x01\x00" + b"\x00" * 8 +  # 16 bytes
            b"\x02\x00" +  # e_type (EXEC)
            b"\x3E\x00" +  # e_machine (X86_64 / 62)
            b"\x01\x00\x00\x00" +  # e_version
            b"\x80\x00\x00\x00\x00\x00\x00\x00" +  # e_entry (asal 0x80)
            b"\x00" * (64 - 32) # Pad sisanya sampai 64 bytes
        )

        # Data palsu: Header ELF, 3 NOP, 1 RET, dan beberapa string
        dummy_content = (
            elf_header +  # 64 bytes header
            b"\x90\x90\x90" +  # NOP (di offset 64)
            b"\xC3" +  # RET
            b"\x00" * 20 +
            b"Ini string pertama (test1)\x00" +
            b"Ini string kedua (test2)\x00" +
            b"test_pattern_xyz\x00"
        )
        with open(cls.dummy_file, "wb") as f:
            f.write(dummy_content)
            
        try:
            cls.hasil_analisis = analyze.lakukanAnalisisLengkap(cls.dummy_file)
        except Exception as e:
            cls.hasil_analisis = {"error": f"Gagal di setUpClass: {e}"}

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
        
        # Cek header
        self.assertIn("header", hasil)
        self.assertIsNone(hasil["header"].get("error"), 
                          f"Analisis header gagal: {hasil['header'].get('error')}")
        self.assertTrue(hasil["header"].get("valid"), "Header seharusnya valid")
        self.assertEqual(hasil["header"].get("format"), "ELF") # Diubah dari 'magic'
        self.assertEqual(hasil["header"].get("machine_id"), 62) # Cek machine_id x86-64
        
        # Cek strings
        self.assertIn("strings", hasil)
        string_list = " ".join(hasil["strings"])
        self.assertIn("Ini string pertama (test1)", string_list)
        self.assertIn("Ini string kedua (test2)", string_list)

        # Cek disasm
        self.assertIn("disassembly_awal", hasil)
        self.assertGreater(len(hasil["disassembly_awal"]), 0) 
        
        # Cari NOP (setelah 64 byte header)
        found_nop = any(instr.get("mnemonic") == "NOP" for instr in hasil["disassembly_awal"])
        self.assertTrue(found_nop, "Seharusnya menemukan instruksi NOP setelah header")

    def test_02_report_module_json(self):
        dummy_data = {"file": "test", "header": {"entry_point": "0x123"}, "strings": ["abc"]}
        report.buatLaporan(dummy_data, "json", self.report_json)
        
        self.assertTrue(os.path.exists(self.report_json))
        
        with open(self.report_json, 'r') as f:
            data = json.load(f)
        self.assertEqual(data["file"], "test")
        self.assertEqual(data["header"]["entry_point"], "0x123")

    def test_03_report_module_csv(self):
        dummy_data = {"file": "test_csv", "header": {"valid": True}, "strings": ["csv_string"]}
        report.buatLaporan(dummy_data, "csv", self.report_csv)
        
        self.assertTrue(os.path.exists(self.report_csv))
        
        with open(self.report_csv, 'r') as f:
            content = f.read()
        self.assertIn("test_csv", content)
        self.assertIn("csv_string", content)

    def test_04_pipeline_script_execution(self):
        if os.path.exists("pipeline_test_output.json"):
            os.remove("pipeline_test_output.json")

        command = [
            sys.executable,
            PIPELINE_SCRIPT,
            self.dummy_file,
            "--format", "json",
            "--output", "pipeline_test_output"
        ]
        
        test_env = os.environ.copy()
        # Path ke build/lib
        lib_path = os.path.join(_PROJECT_ROOT, 'build', 'lib')
        
        # Pastikan lib_path ada di Path (Windows) atau LD_LIBRARY_PATH (Linux)
        path_var_name = 'Path' if os.name == 'nt' else 'LD_LIBRARY_PATH'
        current_path = test_env.get(path_var_name, '')
        
        norm_lib_path = os.path.normpath(lib_path)
        path_parts = [os.path.normpath(p) for p in current_path.split(os.pathsep)]

        if norm_lib_path not in path_parts:
            test_env[path_var_name] = f"{lib_path}{os.pathsep}{current_path}"
            
        # Pastikan PYTHONPATH menyertakan 'interfaces/python'
        py_path = test_env.get('PYTHONPATH', '')
        norm_pkg_path = os.path.normpath(_PACKAGE_ROOT)
        py_path_parts = [os.path.normpath(p) for p in py_path.split(os.pathsep)]
        
        if norm_pkg_path not in py_path_parts:
            test_env['PYTHONPATH'] = f"{_PACKAGE_ROOT}{os.pathsep}{py_path}"
        
        # CWD harus di 'build/lib' agar lib_loader.py menemukan DLL
        cwd_path = lib_path

        result = subprocess.run(command, 
                                capture_output=True, 
                                text=True, 
                                check=True, 
                                encoding='utf-8',
                                env=test_env,
                                cwd=cwd_path)
        
        # Cek stdout
        self.assertIn("[+] Analisis selesai.", result.stdout)
        self.assertIn("[+] Laporan berhasil dibuat: pipeline_test_output.json", result.stdout)
        
        # Cek file output
        output_file_path = os.path.join(cwd_path, "pipeline_test_output.json")
        self.assertTrue(os.path.exists(output_file_path))
        
        if os.path.exists(output_file_path):
            os.remove(output_file_path)

if __name__ == "__main__":
    unittest.main()