import unittest
import os
import sys
import json

# Setup Path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
bindings_path = os.path.join(project_root, 'interfaces', 'python')
sys.path.append(bindings_path)

try:
    from bindings import parser, disasm, analyzer, hexeditor, advanced_tools
except ImportError as e:
    print(f"GAGAL impor bindings. Pastikan 'build' direktori ada di {project_root}/build")
    print(f"Error: {e}")
    sys.exit(1)
    
class TestFullPythonIntegration(unittest.TestCase):

    nama_file_test = "integration_test_binary.bin"

    @classmethod
    def setUpClass(cls):
        print("\n[Integration Test] Membuat file dummy...")
        # Header ELF 64-bit palsu (Machine 62 / 0x3E)
        konten = b"\x7FELF\x02\x01\x01\x00" + (b"\x00" * 8) + b"\x02\x00\x3E\x00" + (b"\x00" * 4)
        # Instruksi: PUSH RBP (0x55), MOV RBP,RSP (0x48 0x89 0xE5), NOP (0x90), RET (0xC3)
        konten_instruksi = b"\x55\x48\x89\xE5\x90\xC3"
        # Total header 32 bytes
        konten = konten.ljust(32, b"\x00") 
        konten += konten_instruksi
        # String
        konten += b"\x00" * 5 # Padding
        konten += b"IniStringSatuUntukTes\x00"
        konten += b"IniStringDuaXYZ\x00"
        
        with open(cls.nama_file_test, "wb") as f:
            f.write(konten)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.nama_file_test):
            os.remove(cls.nama_file_test)
            print("[Integration Test] File dummy dihapus.")

    def test_01_parser_dan_hexeditor(self):
        file_path = self.nama_file_test
        
        # Test: Parser
        hasil_header_dict = parser.parseBinaryHeader(file_path)
        self.assertTrue(hasil_header_dict.get("valid"))
        self.assertEqual(hasil_header_dict.get("format"), "ELF")
        self.assertEqual(hasil_header_dict.get("machine_id"), 62) # EM_X86_64

        # Test: HexEditor
        sixteen_bytes = hexeditor.lihatBytes(file_path, 0, 16)
        # Cek 4 bytes pertama (ELF Magic)
        self.assertTrue(sixteen_bytes.startswith("7F 45 4C 46"))
    
    def test_02_analyzer_dan_disasm(self):
        file_path = self.nama_file_test
        
        # Test: Analyzer (Strings)
        list_strings = analyzer.extractStrings(file_path, minLength=5)
        self.assertEqual(len(list_strings), 2)
        self.assertIn("IniStringSatuUntukTes", list_strings)
        self.assertIn("IniStringDuaXYZ", list_strings)
        
        # Test: Analyzer (Entropy)
        list_entropy = analyzer.hitungEntropy(file_path, 1024)
        self.assertEqual(len(list_entropy), 1)
        self.assertGreater(list_entropy[0], 2.0) # Pasti tidak 0
        
        # Test: Disassembler
        with open(file_path, "rb") as f:
            data_binary = f.read(64)
            
        # Cari offset instruksi (setelah 32 bytes header palsu)
        offset_code = 32
        arch = disasm.ARCH_X86_64
        
        # PUSH RBP (0x55)
        mn, ops, sz = disasm.decodeInstruksi(data_binary, offset_code, arch)
        self.assertEqual(mn, "PUSH")
        self.assertEqual(sz, 1)
        offset_code += sz
        
        # MOV RBP, RSP (0x48 0x89 0xE5)
        mn, ops, sz = disasm.decodeInstruksi(data_binary, offset_code, arch)
        self.assertEqual(mn, "MOV")
        self.assertEqual(sz, 3)
        offset_code += sz

        # NOP (0x90)
        mn, ops, sz = disasm.decodeInstruksi(data_binary, offset_code, arch)
        self.assertEqual(mn, "NOP")
        self.assertEqual(sz, 1)
        
    def test_03_advanced_tools_integration(self):
        file_path = self.nama_file_test
        
        # Test: Generate CFG
        dot_graph = advanced_tools.generateCFG(file_path)
        self.assertIn("digraph G", dot_graph)
        self.assertIn("File tidak valid", dot_graph)
        
        # Test: Binary Diff (diff dengan diri sendiri)
        diff_results = advanced_tools.diffBinary(file_path, file_path)
        self.assertIsNotNone(diff_results)

if __name__ == "__main__":
    unittest.main()