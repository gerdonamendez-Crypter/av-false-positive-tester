# yara_scan.py
import os

YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), "yara")
RULES_PATH = os.path.join(YARA_RULES_DIR, "suspicious_files.yar")

def scan_with_yara(filepath):
    if not os.path.exists(RULES_PATH):
        return None

    try:
        import yara
        rules = yara.compile(filepath=RULES_PATH)
        matches = rules.match(filepath)
        return [match.rule for match in matches] if matches else []
    except ImportError:
        # yara-python not installed
        return None
    except Exception as e:
        # Rule syntax error or file issue
        print(f"[!] YARA error: {e}")
        return None 
