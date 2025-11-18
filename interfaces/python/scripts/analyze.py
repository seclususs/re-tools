import sys
import os
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import retools

def analyze_file(path):
    report = {}
    try:
        report['header'] = retools.parse_header(path)
        report['strings'] = retools.extract_strings(path, 5)[:50]
        report['entropy'] = retools.entropy(path, 1024)
        report['bytes_head'] = retools.view_bytes(path, 0, 16)
    except Exception as e:
        report['error'] = str(e)
    return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    res = analyze_file(sys.argv[1])
    print(json.dumps(res, indent=2))