import sys

def decrypt_dat_file(filename):
    b = bytearray(open(filename, "rb").read())

    fake_size = int.from_bytes(b[0:4], 'little')
    end = fake_size - 0xc8372a
    b = bytearray(b[4:4 + end])

    for i in range(len(b)):
        if i % 2:
            b[i] ^= 0x6a
        else:
            b[i] ^= 0xa7

    b[len(b)-1] ^= b[0]
    for i in range(len(b) - 2, 0, -1):
        b[i] ^= b[i+1]

    b[0] ^= b[1]
    
    return b

decrypt_dat_file(sys.argv[1])
