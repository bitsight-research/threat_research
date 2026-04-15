rule iot_rondodox_binary {
    meta:
        description = "Detects the rondodox binary"
        author = "jcfg"
        date = "2026-01-14"
        hash = "7f28d9922662307156b5d5cd1c217e724a23466bab5bb03bd29f098b7e8251b0"
    strings:
        // Strings that format the commands are not yet encrypted
        $s0 = "%s %s %s %d %d %d %d %d" ascii nocase
        $s1 = "%s %s %s %d %d %d %d" ascii nocase
        $s2 = "%s %s %s %d %d %d" ascii nocase
        $s3 = "%s %s %s %d %d" ascii nocase
        $s4 = "%s %s %s %d %d %d %s %d %d %d" ascii nocase
        $s5 = "%s %s %d %s %d %d %d" ascii nocase
        $s6 = "%s %s %d %d %s %d %d %d" ascii nocase
        $s7 = "%s %s %d %s %d %d %s %d %d %d" ascii nocase

        // Older samples still contain plain strings
        $t0 = "/tmp/contact.txt" ascii nocase
        $t1 = "SSH-2.0-MoTTY_Release_0.82" ascii nocase
        $t2 = "SNOEN" ascii // rondo
        $t3 = "@reboot %s %s.persisted" ascii nocase
        $t4 = "rondo" ascii nocase

        // From string decryption sub 5 to even bytes
        $asm0 = { 80 6c 18 ff 05 4? ff c0 4? ff c2 4? 39 c4 74 ?? f6 c2 01 74 ?? 80 44 18 ff 05 4? ff c0 4? ff c2 4? 39 c4 75 ??  }
        // Rotate Left 5
        $asm1 = { 0f b6 44 19 ff 89 c2 c1 e0 05 c1 fa 03 09 c2 88 54 19 ff 4? ff c1 4? 39 cc 75 ??  }
        // Subtract 9 to all bytes
        $asm2 = { b8 01 00 00 00 80 6c 18 ff 09 4? ff c0 4? 39 c4 75 ??  }

    condition:
        filesize < 500KB and
        uint32(0) == 0x464c457f and
        3 of them
}
