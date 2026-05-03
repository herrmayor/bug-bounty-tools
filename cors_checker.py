#!/usr/bin/env python3
"""Safe CORS configuration checker for authorized bug bounty targets.

Checks a small set of Origin headers against URLs supplied by the user.
It does not exploit anything; it only records response headers and highlights risky hints.
"""
import argparse
import csv
import json
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ORIGINS = [
    'https://example.com',
    'https://evil.example',
    'null',
]


def check(url: str, origin: str, timeout: int):
    req = Request(url, headers={'Origin': origin, 'User-Agent': 'cors-checker/1.0'})
    try:
        with urlopen(req, timeout=timeout) as r:
            h = {k.lower(): v for k, v in r.headers.items()}
            return {'url': url, 'origin': origin, 'status': r.status, 'acao': h.get('access-control-allow-origin'), 'acac': h.get('access-control-allow-credentials'), 'error': ''}
    except HTTPError as e:
        h = {k.lower(): v for k, v in e.headers.items()}
        return {'url': url, 'origin': origin, 'status': e.code, 'acao': h.get('access-control-allow-origin'), 'acac': h.get('access-control-allow-credentials'), 'error': ''}
    except URLError as e:
        return {'url': url, 'origin': origin, 'status': '', 'acao': '', 'acac': '', 'error': str(e.reason)}


def risk(row):
    acao = row.get('acao')
    acac = str(row.get('acac')).lower()
    origin = row.get('origin')
    if acao == origin and acac == 'true':
        return 'HIGH-HINT: reflected Origin + credentials; verify sensitive authenticated data manually'
    if acao == '*' and acac == 'true':
        return 'MEDIUM-HINT: wildcard + credentials; verify browser behavior manually'
    if acao == 'null' and acac == 'true':
        return 'MEDIUM-HINT: null Origin + credentials; verify sandbox/file-origin scenarios manually'
    return 'info'


def main():
    ap = argparse.ArgumentParser(description='Check CORS headers on authorized URLs.')
    ap.add_argument('targets')
    ap.add_argument('-o', '--output', default='cors-results.csv')
    ap.add_argument('--timeout', type=int, default=10)
    args = ap.parse_args()

    urls = [x.strip() for x in open(args.targets, encoding='utf-8') if x.strip() and not x.startswith('#')]
    rows = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        for origin in ORIGINS:
            row = check(url, origin, args.timeout)
            row['risk'] = risk(row)
            rows.append(row)
            print(json.dumps(row, ensure_ascii=False))

    with open(args.output, 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['url', 'origin', 'status', 'acao', 'acac', 'risk', 'error'])
        w.writeheader(); w.writerows(rows)
    print(f'Saved {args.output}')


if __name__ == '__main__':
    main()
