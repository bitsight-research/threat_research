import hashlib

def generate_full_list(init):
    all_domains = set()
    while True:
        init = compute_next(init, api)
        if init in all_domains:
            break
        else:
            all_domains.add(init)
    return all_domains

def convert(a):
    if a.isdigit():
        return chr(ord(a) + 0x31)
    elif a.isupper():
        return chr(ord(a) + 0x2c)
    else:
        0/0

def compute_next(url, api):
    url += "," + api
    urlb = url.encode('utf-16')[2:]

    md5sum = hashlib.md5(urlb).digest()[4:12].hex().upper()

    res = ""

    for i in range(10):
        res += convert(md5sum[i])

    return res + ".com"
    

init = "toa.mygametoa.com"
key = "apikey"
for i in range(20):
    init = compute_next(init, key)
    print(init)
