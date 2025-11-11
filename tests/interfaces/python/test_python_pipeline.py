import unittest
import os
import sys
import subprocess
import json

# Setup Path
script_dir = os.path.dirname(os.path.abspath(__file__))
interfaces_python_dir = os.path.abspath(os.path.join(script_dir, '..', '..', 'interfaces', 'python'))
scripts_dir = os.path.join(interfaces_python_dir, 'scripts')

sys.path.insert(0, interfaces_python_dir)
sys.path.insert(0, scripts_dir)

try:
    import analyze
    import report
    PIPELINE_SCRIPT = os.path.join(scripts_dir, "run_pipeline.py")
except ImportError as e:
    print(f"Gagal impor modul tes. Pastikan path sudah benar. {e}")
    sys.exit(1)

class TestPythonPipeline(unittest.TestCase):

    dummy_file = "test_dummy_binary.bin"
    report_json = "test_report.json"
    report_csv = "test_report.csv"

    @classmethod
    def setUpClass(cls):
        # Data palsu: Magic ELF, 3 NOP, 1 RET, dan beberapa string
        dummy_content = (
            b"\x7FELF\x02\x01\x01\x00" + b"\x00" * 8 +  # ELF Header
            b"\x90\x90\x90" +  # NOP
            b"\xC3" +  # RET
            b"\x00" * 20 +
            b"Ini string pertama (test1)\x00" +
            b"Ini string kedua (test2)\x00" +
            b"test_pattern_xyz\x00"
        )
        with open(cls.dummy_file, "wb") as f:
            f.write(dummy_content)

    @classmethod
    def tearDownClass(cls):
        files_to_remove = [cls.dummy_file, cls.report_json, cls.report_csv]
        for f in files_to_remove:
            if os.path.exists(f):
                os.remove(f)

    def test_01_analyze_module(self):
        hasil = analyze.lakukanAnalisisLengkap(self.dummy_file)
        
        self.assertIn("file", hasil)
        self.assertEqual(hasil["file"], self.dummy_file)
        
        # Cek header
        self.assertIn("header", hasil)
        self.assertTrue(hasil["header"].get("magic") == "ELF" or hasil["header"].get("valid") is False)
        
        # Cek strings
        self.assertIn("strings", hasil)
        # Cek apakah string kita ditemukan
        string_list = " ".join(hasil["strings"])
        self.assertIn("Ini string pertama (test1)", string_list)
        self.assertIn("Ini string kedua (test2)", string_list)

        # Cek disasm
        self.assertIn("disassembly_awal", hasil)
        self.assertGreater(len(hasil["disassembly_awal"]), 0)
        # Cek NOP
        self.assertEqual(hasil["disassembly_awal"][0]["mnemonic"], "NOP")

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

        # Panggil script
        command = [
            sys.executable,
            PIPELINE_SCRIPT,
            self.dummy_file,
            "--format", "json",
            "--output", "pipeline_test_output"
        ]
        
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Cek stdout
        self.assertIn("[+] Analisis selesai.", result.stdout)
        self.assertIn("[+] Laporan berhasil dibuat: pipeline_test_output.json", result.stdout)
        
        # Cek file output
        self.assertTrue(os.path.exists("pipeline_test_output.json"))
        
        if os.path.exists("pipeline_test_output.json"):
            os.remove("pipeline_test_output.json")

if __name__ == "__main__":
    unittest.main()