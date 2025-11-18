import unittest
import os
import sys
import struct

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../interfaces/python')))
import retools

class TestIntegration(unittest.TestCase):
    TEMP_FILE = "py_test_dummy.bin"

    @classmethod
    def setUpClass(cls):
        with open(cls.TEMP_FILE, 'wb') as f:
            f.write(b'\x7FELF\x02\x01\x01\x00' + b'\x00'*56)
            f.write(b'TestStringInBinary')

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.TEMP_FILE):
            os.remove(cls.TEMP_FILE)

    def test_basic_pipeline(self):
        try:
            retools._check()
        except RuntimeError:
            self.skipTest("Native module unavailable")
        hdr = retools.parse_header(self.TEMP_FILE)
        self.assertTrue(hdr.get('valid', False))
        self.assertEqual(hdr.get('format'), 'ELF')
        strs = retools.extract_strings(self.TEMP_FILE, 5)
        self.assertIn('TestStringInBinary', strs)
        data = retools.view_bytes(self.TEMP_FILE, 0, 4)
        self.assertEqual(data.strip(), "7F 45 4C 46")

if __name__ == '__main__':
    unittest.main()