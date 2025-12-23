# core.py
import os
import hashlib
from typing import Dict
 
def sha256_file(filepath: str) -> str:
    """Compute the SHA-256 hash of a file in chunks to minimize memory usage."""
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            # Read file in 4 KiB chunks
            while chunk := f.read(4096):
                h.update(chunk)
    except OSError as e:
        raise OSError(f"Unable to read file '{filepath}': {e}") from e
    return h.hexdigest()

def get_file_info(filepath: str) -> Dict[str, str | int]:
    """Return metadata about a file, including name, absolute path, size, and SHA-256 hash."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    abs_path = os.path.abspath(filepath)
    size = os.path.getsize(filepath)
    sha256 = sha256_file(filepath)

    return {
        "file": os.path.basename(filepath),
        "path": abs_path,
        "size_bytes": size,
        "sha256": sha256
    }
