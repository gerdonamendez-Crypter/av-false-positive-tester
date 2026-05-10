# capa_scan.py
import subprocess
import json
from typing import Dict, Any

def scan_with_capa(filepath: str) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            ["capa", "-j", filepath],
            capture_output=True,
            text=True,
            check=True 
        )
        data = json.loads(result.stdout)
        capabilities = []
        for rule in data.get("rules", {}):
            if data["rules"][rule].get("matches"):
                capabilities.append({
                    "name": rule,
                    "namespace": data["rules"][rule]["meta"].get("namespace"),
                    "description": data["rules"][rule]["meta"].get("description")
                })
        return {"capabilities": capabilities, "attck": data.get("attck", {})}
    except FileNotFoundError:
        print("[!] capa not installed. Run: pip install mandiant-capa")
        return None
    except Exception as e:
        print(f"[!] CAPA error: {e}")
        return None
