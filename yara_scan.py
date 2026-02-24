# yara_scan.py
import os
import yara

YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), "yara")

def scan_with_yara(filepath):
    rule_files = [os.path.join(YARA_RULES_DIR, f) for f in os.listdir(YARA_RULES_DIR) if f.endswith('.yar')]
    if not rule_files:
        return None
 
    try:
        rules = yara.compile(filepaths={f: f for f in rule_files})
        matches = rules.match(filepath)
        return [m.rule for m in matches] if matches else []
    except Exception as e:
        print(f"[!] YARA error: {e}")
        return None
