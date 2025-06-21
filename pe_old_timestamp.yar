import "pe"
import "time"

rule PE_Old_Compile_Timestamp {
    meta:
        description = "Detects PE files with compile timestamps older than 1 year"
        author = "Laiba Imran"
        date = "2025-05-01"

    condition:
        time.now() - pe.timestamp > 31536000
}
