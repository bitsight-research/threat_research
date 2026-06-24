rule win_amadey {
    meta:
        author        = "Bitsight"
        description   = "Detects Amadey v5.55+ payload (x86 and x64): RC4 stream cipher implementation"
        creation_date = "2026-04-22"
        license       = "CC BY-NC-SA 4.0"

    strings:
        // RC4 KSA/PRGA loop body (x86), verified against v5.55 and v5.78.
        $rc4_32 = { 8a 96 ?? ?? ?? ?? 0f b6 86 ?? ?? ?? ?? 03 f8 0f b6 ca 03 f9
                    81 e7 ff 00 00 80 79 ?? 4f 81 cf 00 ff ff ff 47
                    8a 87 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 46
                    88 97 ?? ?? ?? ?? 81 fe 00 01 00 00 7c }

        // RC4 PRGA S-box swap loop body (x64), verified against v5.80.
        $rc4_64 = { 46 0f b6 04 22 41 03 f8 81 e7 ff 00 00 80 7d ?? ff cf
                    81 cf 00 ff ff ff ff c7 48 63 cf 42 0f b6 04 21
                    42 88 04 22 46 88 04 21 42 0f b6 0c 22 49 03 c8 0f b6 c1 }

    condition:
        uint16(0) == 0x5a4d and ($rc4_32 or $rc4_64)
}
