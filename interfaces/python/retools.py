import sys
import json
import os

try:
    import re_tools as _rt
except ImportError:
    _rt = None
    print("Warning: re_tools native module not found.", file=sys.stderr)

def _check():
    if not _rt:
        raise RuntimeError("Native module not loaded")

def parse_header(path: str) -> dict:
    _check()
    res = _rt.parseHeaderInfo(path)
    return res

def extract_strings(path: str, min_len: int = 4) -> list:
    _check()
    return _rt.ekstrakStrings(path, min_len)

def entropy(path: str, block_size: int) -> list:
    _check()
    return _rt.hitungEntropy(path, block_size)

def scan_yara(path: str, rule: str) -> list:
    _check()
    res = _rt.scanYara(path, rule)
    if isinstance(res, str):
        return json.loads(res)
    return res

def view_bytes(path: str, offset: int, length: int) -> str:
    _check()
    return _rt.lihatBytes(path, offset, length)

def generate_cfg(path: str) -> str:
    _check()
    return _rt.buatCFG(path)

def diff_binary(p1: str, p2: str) -> list:
    _check()
    res = _rt.diffBinary(p1, p2)
    if isinstance(res, str):
        return json.loads(res)
    return res