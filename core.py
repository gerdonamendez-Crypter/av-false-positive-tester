# core.py
import os
import hashlib
import time
from typing import Dict, Any, List, Optional
import pefile
from pefile import PE


def sha256_file(filepath: str) -> str:
    """Compute SHA-256 hash efficiently."""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def get_pe_info(pe: PE) -> Dict[str, Any]:
    """Extract richer PE metadata."""
    info: Dict[str, Any] = {
        "is_pe": True,
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "compile_time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(pe.FILE_HEADER.TimeDateStamp))
            if pe.FILE_HEADER.TimeDateStamp else None,
        "number_of_sections": pe.FILE_HEADER.NumberOfSections,
        "characteristics": hex(pe.FILE_HEADER.Characteristics),
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        "sections": [],
        "imports": [],
        "imphash": None,
        "average_entropy": 0.0,
        "has_overlay": False,
        "is_signed": False,
        "signer": None,
    }

    # Sections
    if pe.sections:
        info["sections"] = [
            {
                "name": s.Name.decode(errors='ignore').strip('\x00'),
                "virtual_size": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData,
                "entropy": round(s.get_entropy(), 3),
                "characteristics": hex(s.Characteristics)
            }
            for s in pe.sections
        ]
        info["average_entropy"] = round(
            sum(s.get_entropy() for s in pe.sections) / len(pe.sections), 3
        )

    # Imports (DLL names only for brevity)
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        info["imports"] = [
            entry.dll.decode(errors='ignore').lower().rstrip('.dll')
            for entry in pe.DIRECTORY_ENTRY_IMPORT
        ]

    # Imphash (very useful for FP analysis)
    try:
        info["imphash"] = pe.get_imphash()
    except AttributeError:
        pass  # older pefile versions may not have it

    # Overlay detection
    if pe.sections:
        last_section = pe.sections[-1]
        overlay_offset = last_section.PointerToRawData + last_section.SizeOfRawData
        if overlay_offset < pe.FILE_HEADER.SizeOfOptionalHeader + pe.sections[-1].Misc_VirtualSize:
            info["has_overlay"] = True

    # Digital signature check
    if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.DIRECTORY_ENTRY_SECURITY:
        info["is_signed"] = True
        # Optional: try to get signer name (requires more parsing or signtool.exe)
        # For simplicity we just mark as signed here

    return info


def get_file_info(filepath: str) -> Dict[str, Any]:
    """
    Collect comprehensive file metadata for false-positive analysis.
    Returns dict suitable for JSON/HTML reports.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    abs_path = os.path.abspath(filepath)
    size = os.path.getsize(filepath)
    sha256 = sha256_file(filepath)

    result: Dict[str, Any] = {
        "file": os.path.basename(filepath),
        "full_path": abs_path,
        "size_bytes": size,
        "sha256": sha256,
        "pe": {"is_pe": False},
        "static_warnings": []   # can be filled later by YARA/CAPA/risk logic
    }

    try:
        pe = pefile.PE(filepath, fast_load=False)
        result["pe"] = get_pe_info(pe)
    except pefile.PEFormatError:
        pass  # not a PE → keep is_pe=False
    except Exception as e:
        result["pe"]["parse_error"] = str(e)

    return result
