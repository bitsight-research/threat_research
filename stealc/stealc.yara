import "pe"

rule win_stealc {
    meta:
        description = "StealC infostealer: RC4/Base64 C2 and Chrome ABE v20 bypass"
        author      = "Bitsight"
        date        = "2026-05-04"
        family      = "StealC"
        hash_000    = "f4584140becea8907edb22c8a99d5e9e9157931aa1e2ab29522adbc9ba684f07"
        hash_001    = "bf24277400cc453d530e4277d3bd24e96c5e409adef6970518bdc59205aa0241"
        hash_002    = "9735cb203175e5b77ea68f665d81aed39a7e85b6f484a0948c81ac85d9a5f3d4"
        license     = "CC BY-NC-SA 4.0"

    strings:
        $abe         = "\"app_bound_encrypted_key\":\"" ascii
        $selfdel     = "/c timeout /t 5 & del /f /q \"" ascii
        $proto_total = "\"total_parts\": " ascii
        $proto_index = "\"part_index\": " ascii
        $nlohmann    = "json_abi_v3_11_3@nlohmann" ascii
        $builder     = "C:\\builder_v2\\stealc\\json.h" wide
        $hwid        = "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX" ascii
        $cis_ks      = { 0F B7 C?
                         [1-2] 19 04 00 00
                         74 14
                         83 E? 09
                         74 0F
                         83 E? 01
                         74 0A
                         83 E? 1C
                         74 05
                         83 ?? 04
                         75 08 }

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        filesize < 2MB and
        $abe and $selfdel and $proto_total and $proto_index and
        $cis_ks and
        2 of ($nlohmann, $builder, $hwid)
}
