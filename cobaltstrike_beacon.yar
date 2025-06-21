import "pe"
import "math"

rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon and shellcode"
        author = "Laiba Imran"
        date = "2025-05-01"
        version = "1.2"
        malware_family = "Cobalt Strike"

    strings:
        $s1 = "ReflectiveLoader" wide ascii nocase
        $s2 = "This program cannot be run in DOS mode" ascii
        $s3 = "http://" ascii
        $s4 = "GET /profile" ascii
        $s5 = "MZ" ascii
        $s6 = "CobaltStrike" ascii wide nocase
        $s7 = "/submit.php" ascii

        $sc1 = { FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51 56 48 31 D2 }
        $sc2 = { 48 31 C9 64 8B 71 30 8B 76 0C 8B 76 1C 8B 6E 08 8B 36 }
        $xor_decode = { 80 30 ?? 48 FF C0 48 39 D8 75 F6 }

    condition:
        uint16(0) == 0x5A4D and pe.is_pe and (
            2 of ($s*) or
            any of ($sc*) or
            $xor_decode or
            (
                math.entropy(0, filesize) > 6.7 and
                filesize < 500000 and
                pe.number_of_sections <= 6
            )
        )
}
