def decrypt(enc_str, key1, key2):
    out = []
    for i in range(len(enc_str)):
        out.append(key1 ^ enc_str[i])
        if i % 2:
            key1 = (key1 + key2 - 1) & 0xFF
        else:
            key1 = (key1 + key2 + 1) & 0xFF
    return bytes(out)

enc_str = bytes.fromhex('B1FE316F549FDB1B6DA1F17D')
key1 = 0xE4
key2 = 0xC8
print(decrypt(enc_str, key1, key2))
# >>> b'USERPROFILE\x00'