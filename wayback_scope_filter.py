#!/usr/bin/env python3
"""Filter URL lists so only authorized in-scope hosts remain.

Input can be Wayback, katana, gau, or any plain URL list. This tool does not fetch URLs;
it only filters local text files against an allowed scope file.
"""
import argparse
from urllib.parse import urlparse


def host(x):
    if not x.startswith(('http://','https://')):
        x = 'https://' + x
    return urlparse(x).netloc.lower().split(':')[0]


def in_scope(url, allowed):
    h = host(url)
    return any(h == a or h.endswith('.' + a) for a in allowed)


def main():
    ap = argparse.ArgumentParser(description='Filter URL list to in-scope hosts only.')
    ap.add_argument('urls')
    ap.add_argument('scope', help='File with allowed root hosts, e.g. example.com')
    ap.add_argument('-o','--output',default='in-scope-urls.txt')
    args = ap.parse_args()

    allowed = {host(x.strip()) for x in open(args.scope, encoding='utf-8') if x.strip() and not x.startswith('#')}
    kept=[]
    for line in open(args.urls, encoding='utf-8'):
        u=line.strip()
        if u and not u.startswith('#') and in_scope(u, allowed):
            kept.append(u)
    kept=sorted(set(kept))
    with open(args.output,'w',encoding='utf-8') as f:
        for u in kept:
            f.write(u+'\n')
    print(f'Saved {len(kept)} in-scope URLs to {args.output}')

if __name__ == '__main__':
    main()
