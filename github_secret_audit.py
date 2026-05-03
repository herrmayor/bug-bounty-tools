#!/usr/bin/env python3
"""Local secret-pattern audit for repositories you own or are authorized to test.

Scans local files for common token/key patterns. This is a defensive helper; always
verify findings manually because regex-based secret detection has false positives.
"""
import argparse
import os
import re
import csv

PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'github-token': re.compile(r'gh[pousr]_[A-Za-z0-9_]{20,}'),
    'slack-token': re.compile(r'xox[baprs]-[A-Za-z0-9-]{20,}'),
    'aws-access-key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'generic-api-key': re.compile(r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["\']?[A-Za-z0-9_./+=-]{16,}'),
}

SKIP_DIRS = {'.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__'}


def scan_file(path):
    rows=[]
    try:
        text=open(path, encoding='utf-8', errors='ignore').read()
    except Exception:
        return rows
    for i,line in enumerate(text.splitlines(), start=1):
        for name, rx in PATTERNS.items():
            if rx.search(line):
                rows.append({'file':path,'line':i,'type':name,'sample':line.strip()[:160]})
    return rows


def main():
    ap=argparse.ArgumentParser(description='Scan a local authorized repository for common secret patterns.')
    ap.add_argument('path')
    ap.add_argument('-o','--output',default='secret-audit.csv')
    args=ap.parse_args()

    findings=[]
    for root, dirs, files in os.walk(args.path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            full=os.path.join(root,fn)
            findings.extend(scan_file(full))

    with open(args.output,'w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['file','line','type','sample'])
        w.writeheader(); w.writerows(findings)
    print(f'Saved {len(findings)} potential findings to {args.output}')

if __name__ == '__main__':
    main()
