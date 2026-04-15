import sys

def op_sub_5_to_even_bytes(input_bytes: bytes) -> bytes:
    out = bytearray(input_bytes)
    for i in range(len(input_bytes)):
        if i % 2 != 0:
            out[i] = (out[i] + 5) & 0xFF
        else:
            out[i] = (out[i] - 5) & 0xFF
    return out

def op_rotate_left_5_bits(input_bytes: bytes) -> bytes:
    out = bytearray(input_bytes)
    for i, b in enumerate(input_bytes):
        out[i] = ((b << 5) & 0xFF) | ((b >> 3) & 0xFF)
    return out

def op_swap_bytes(input_bytes: bytes) -> bytes:
    if len(input_bytes) >> 1 == 0:
        return input_bytes
    out = bytearray(input_bytes)[::-1]
    if len(out) >> 2 == 0:
        return out
    idx = (len(input_bytes) >> 1)
    out_1 = out[:idx]
    out_2 = out[idx:]

    out_1 = out_1[::-1]
    return out_1 + out_2

def op_xor_with_key(input_bytes: bytes, key_pre: bytes, xor_key: int = 0x9d) -> bytes:
    key = bytearray(len(key_pre))
    for i in range(len(key_pre)):
        key[i] = key_pre[i] ^ xor_key

    out = bytearray(input_bytes)
    for i, b in enumerate(input_bytes):
        out[i] = b ^ key[i % len(key)]
    return out

def op_sub_9(input_bytes: bytes) -> bytes:
    out = bytearray(input_bytes)
    for i, b in enumerate(input_bytes):
        out[i] = (b - 9) & 0xFF
    return out

def op_transform_bytes(input_bytes: bytes) -> bytes:
    out = bytearray(input_bytes)
    for i, b in enumerate(input_bytes):
        if (b + 0x9f) & 0xFF < 0x1a:
            out[i] = (((b - 0x54) % 0x1a) & 0xFF) + ord('a')
        else:
            if (b + 0xbf) & 0xFF < 0x1a:
                out[i] = (((b - 0x34) % 0x1a) & 0xFF) + ord('A')
            elif (b - 0x30) & 0xFF < 10:
                out[i] = (((b - 0x2b) % 10) & 0xFF) + ord('0')
    return out

def op_transform_bytes2(input_bytes: bytes) -> bytes:
    out = bytearray(input_bytes)
    for i, b in enumerate(input_bytes):
        if (b - 0x61) & 0xFF <= 0x19:
            out[i] = (((b - 0x54) % 0x1a) & 0xFF) + ord('a')
        else:
            if (b - 0x41) & 0xFF <= 0x19:
                out[i] = (((b - 0x34) % 0x1a) & 0xFF) + ord('A')
            if (b - 0x30) & 0xFF <= 9:
                out[i] = (((b - 0x2b) % 10) & 0xFF) + ord('0')
    return out

def op_add_1(input_bytes: bytes) -> bytes:
    out = bytearray(input_bytes)
    for i, b in enumerate(input_bytes):
        out[i] = (b + 1) & 0xFF
    return out


# def decrypt(input_bytes: bytes) -> bytes:
#     out = input_bytes
#     out = op_sub_5_to_even_bytes(out)
#     out = op_rotate_left_5_bits(out)
#     out = op_swap_bytes(out)
#     out = op_xor_with_key(out)
#     out = op_sub_9(out)
#     out = op_transform_bytes(out)
#     out = op_add_1(out)
#     return out

# 2025-12-17
def decrypt(input_bytes: bytes) -> bytes:
    out = input_bytes
    out = op_sub_5_to_even_bytes(out)
    out = op_rotate_left_5_bits(out)
    out = op_swap_bytes(out)
    out = op_xor_with_key(out, bytes.fromhex('a7e1bbb7b8c8fab8e1f9d1a5d6f9baa6adb5f5d1a7b5b7c1afc3abcca6a2e5e3'), 0x91)
    out = op_sub_9(out)
    out = op_transform_bytes(out)
    out = op_add_1(out)
    return out

# def decrypt(input_bytes: bytes) -> bytes:
#     out = input_bytes
#     out = op_sub_5_to_even_bytes(out)
#     out = op_xor_with_key(out, bytes.fromhex('defcb6e7deaaaea4f0acfff6d7eadad8cfe4a1afaacbcea9fffaaba8dec6a7abdad0c5d6d8b7d7e4fac3ced5e8cbc6d9d8e4faa2efabacaadea5a9f7f5cfc8d0'), 0x9d)
#     out = op_rotate_left_5_bits(out)
#     out = op_swap_bytes(out)
#     out = op_xor_with_key(out, bytes.fromhex('a7e1bbb7b8c8fab8e1f9d1a5d6f9baa6adb5f5d1a7b5b7c1afc3abcca6a2e5e3'), 0x91)
#     out = op_sub_9(out)
#     out = op_transform_bytes2(out)
#     out = op_add_1(out)
#     return out

def decrypt_xor(input_bytes: bytes) -> bytes:
    return bytes([c ^ 0x21 for c in input_bytes])


if __name__ == "__main__":
    args = sys.argv[1]
    temp = bytes.fromhex(args)
    decrypted = decrypt(temp)
    # decrypted = decrypt(bytes.fromhex('dfde0b6db030'))
    print(decrypted.decode('latin-1'))
