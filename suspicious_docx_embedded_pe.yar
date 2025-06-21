rule Suspicious_DOCX_Embedded_PE {
    meta:
        description = "Detects DOCX files containing embedded PE executables or suspicious macros"
        author = "Laiba Imran"
        date = "2025-05-01"
        severity = "High"

    strings:
        $docx_magic = { 50 4B 03 04 }
        $mz_magic = { 4D 5A }
        $vba_macro = "AutoOpen" nocase
        $ps1 = "powershell" nocase
        $cmd = "cmd.exe" nocase

    condition:
        ($docx_magic at 0 and $mz_magic in (0..100)) or
        ($docx_magic at 0 and any of ($vba_macro, $ps1, $cmd))
}
