# YARA Malware Detection Rules

This repository contains YARA rules written by **Laiba Imran** for detecting various forms of malware and suspicious binaries.

## Rules

- `cobaltstrike_beacon.yar`: Detects Cobalt Strike loaders and shellcode
- `pe_old_timestamp.yar`: Flags PE files with outdated compile timestamps
- `malicious_powershell.yar`: Detects obfuscated or malicious PowerShell scripts
- `suspicious_docx_embedded_pe.yar`: Identifies DOCX files that may contain embedded executables or macros
- `upx_packed_binary.yar`: Flags executables packed using the UPX packer

## Author

**Laiba Imran**  
Cybersecurity Student  
Date: May 01, 2025
