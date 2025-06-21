rule Malicious_PowerShell_Detector {
    meta:
        description = "Detects obfuscated or suspicious PowerShell scripts"
        author = "Laiba Imran"
        date = "2025-05-01"
        severity = "High"

    strings:
        $invoke_expr = "Invoke-Expression" nocase
        $iex = "IEX" nocase
        $download_str = "DownloadString" nocase
        $webclient = "New-Object Net.WebClient" nocase
        $encoded_cmd = "-EncodedCommand" nocase
        $hidden_exec = "-WindowStyle Hidden" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $noprofile = "-NoProfile" nocase
        $reflect = "[Reflection.Assembly]::Load" nocase

        $base64 = "FromBase64String" nocase
        $char_obfusc = /\[char\]\s*(0x[0-9a-f]+|\d+)/ nocase
        $concat_str = /\".+\"\s*\+\s*\".+\"/ nocase
        $random_vars = /\$[a-z0-9]{4,}\s*=/ 

        $common_c2 = /(http|https):\/\/[^\s\"']+/ nocase
        $common_ips = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/

    condition:
        (
            (any of ($invoke_expr, $iex, $download_str, $webclient, $encoded_cmd)) and
            (any of ($hidden_exec, $bypass, $noprofile, $reflect))
        ) or
        (
            (any of ($base64, $char_obfusc, $concat_str, $random_vars)) and
            (filesize < 500KB)
        ) or
        (
            (any of ($common_c2, $common_ips)) and
            (2 of ($invoke_expr, $iex, $download_str))
        )
}
