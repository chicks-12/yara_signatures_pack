import "pe"

rule UPX_Packed_Binary {
    meta:
        description = "Detects executables packed with UPX"
        author = "Laiba Imran"
        date = "2025-05-01"

    strings:
        $upx_magic = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 }
        $upx_section = "UPX0" wide ascii
        $upx_section2 = "UPX1" wide ascii

    condition:
        $upx_magic at pe.entry_point or any of ($upx_section, $upx_section2)
}
