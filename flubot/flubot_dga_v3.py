# https://twitter.com/pr3wtd/status/1478010795011235841?s=20&t=0gVK7iYbJYpZxUY4VRM8BA
# https://www.bitsight.com/blog/flubot-malware-persists-most-prevalent-germany-and-spain

import argparse
from datetime import datetime
# https://github.com/MostAwesomeDude/java-random/blob/master/javarandom.py
from javarandom import Random


def get_seed(init, year, month):
    month = month - 1
    j = ((year ^ month) ^ 0)
    j2 = j * 2
    j3 = j2 * (year ^ j2)
    j4 = j3 * (month ^ j3)
    j5 = (j4 * j4) % 2 ** 64
    seed = j5 + init
    return seed


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='FluBot DGA v3')
    parser.add_argument(
        '-s', '--seed', choices=[1949, 1945, 1813, 1136, 2931, 1642, 1905], type=int, required=True)
    parser.add_argument(
        '-y', '--year', help='default current year (YYYY)', type=int, required=False)
    parser.add_argument(
        '-m', '--month', help='default current month (MM)', type=int, required=False)

    args = parser.parse_args()
    seedinit = args.seed
    now = datetime.utcnow()
    if args.year:
        year = args.year
    else:
        year = now.year
    if args.month:
        month = args.month
    else:
        month = now.month

    r = Random(seed=get_seed(seedinit, year, month))
    tlds = ['ru', 'cn', 'com', 'org',
            'pw', 'net', 'bar', 'host',
            'online', 'space', 'site',
            'xyz', 'website', 'shop',
            'kz', 'md', 'tj', 'pw', 'gdn',
            'am', 'com.ua', 'news', 'email',
            'icu', 'biz', 'kim', 'work',
            'top', 'info', 'br']

    for i in range(2500):
        domain = ''
        for _ in range(15):
            domain += chr(r.nextInt(25) + 97)
        domain = f'{domain}.{tlds[i % len(tlds)]}'
        print(domain)
