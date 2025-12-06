# core.py
import os
import hashlib

def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def get_file_info(filepath):
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    return {
        "file": os.path.basename(filepath),
        "path": os.path.abspath(filepath),
        "size_bytes": os.path.getsize(filepath),
        "sha256": sha256_file(filepath)
    }
