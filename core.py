# core.py
import os
import hashlib
from typing import Dict
import pefile

def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def get_file_info(filepath: str) -> Dict:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    abs_path = os.path.abspath(filepath)
    size = os.path.getsize(filepath)
    sha256 = sha256_file(filepath)

    pe_info = {}
    try:
        pe = pefile.PE(filepath)
        pe_info = {
            "is_pe": True,
            "sections": [s.Name.decode().strip('\x00') for s in pe.sections],
            "imports": list(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else [],
            "entropy": sum(s.get_entropy() for s in pe.sections) / len(pe.sections) if pe.sections else 0
        }
    except:
        pe_info = {"is_pe": False}

    return {
        "file": os.path.basename(filepath),
        "path": abs_path,
        "size_bytes": size,
        "sha256": sha256,
        "pe": pe_info
    }
