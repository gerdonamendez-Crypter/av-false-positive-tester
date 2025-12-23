// yara/suspicious_files.yar

import "pe"

rule UPX_Packer
{
    meta:
        description = "Detects UPX-packed executables by signature and PE characteristics"
        author = "vt-analyzer"
        date = "2025-12-14"

    strings:
        $upx_signature1 = "UPX!" fullword ascii
        $upx_signature2 = "UPX compressed" fullword ascii

    condition:
        uint16(0) == 0x5A4D and  // MZ header
        pe.number_of_sections < 4 and  // UPX often reduces section count
        any of ($upx_signature*)
}
 
rule Suspicious_AutoRun
{
    meta:
        description = "Detects potential autorun.inf or scripts referencing AutoRun/Autorun (case-insensitive)"
        author = "vt-analyzer"
        date = "2025-12-14"

    strings:
        $autorun1 = "AutoRun" nocase wide ascii
        $autorun2 = "Autorun" nocase wide ascii

    condition:
        filesize < 10 * 1024 * 1024 and  // 10 MB limit (YARA uses bytes)
        any of ($autorun*)
}

rule Known_Malware_Sample
{
    meta:
        description = "Detects test or proof-of-concept malware strings often used in samples"
        author = "vt-analyzer"
        date = "2025-12-14"
        severity = "low"  // often used in labs, not real-world

    strings:
        $str1 = "malicious_payload" ascii
        $hex1 = { 6D 61 6C 77 61 72 65 }  // "malware"

    condition:
        any of them
}
