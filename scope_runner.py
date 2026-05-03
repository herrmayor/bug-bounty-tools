#!/usr/bin/env python3
"""Run safe per-target commands only against an explicit in-scope list.

This helper normalizes target URLs, removes duplicates, and writes a clean target list.
It does not scan by itself; use it to prepare authorized scope for other tools.
"""
import argparse
from urllib.parse import urlparse


def norm(x: str) -> str | None:
    x = x.strip()
    if not x or x.startswith('#'):
        return None
    if not x.startswith(('http://', 'https://')):
        x = 'https://' + x
    p = urlparse(x)
    if not p.netloc:
        return None
    return f'{p.scheme}://{p.netloc}{p.path}'.rstrip('/')


def main():
    ap = argparse.ArgumentParser(description='Normalize and deduplicate authorized scope targets.')
    ap.add_argument('input', help='File with one in-scope target per line')
    ap.add_argument('-o', '--output', default='clean-scope.txt')
    args = ap.parse_args()

    out = []
    for line in open(args.input, encoding='utf-8'):
        v = norm(line)
        if v:
            out.append(v)
    out = sorted(set(out))
    with open(args.output, 'w', encoding='utf-8') as f:
        for v in out:
            f.write(v + '\n')
    print(f'Saved {len(out)} unique targets to {args.output}')


if __name__ == '__main__':
    main()
