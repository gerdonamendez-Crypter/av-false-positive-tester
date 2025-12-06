// yara/suspicious_files.yar
rule UPX_Packer {
    meta:
        description = "Detects UPX-packed executables"
        author = "vt-analyzer"
    strings:
        $upx1 = "UPX!" fullword
        $upx2 = "UPX compressed" fullword ascii
    condition:
        uint16(0) == 0x5A4D and (any of them)
}

rule Suspicious_AutoRun {
    strings:
        $ = "AutoRun" nocase wide ascii
        $ = "Autorun" nocase wide ascii
    condition:
        filesize < 10MB and all of them
}

rule Known_Malware_Sample {
    strings:
        $ = "malicious_payload" ascii
        $ = { 6D 61 6C 77 61 72 65 } // "malware" in hex
    condition:
        any of them
}
