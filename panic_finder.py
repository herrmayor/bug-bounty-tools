#!/usr/bin/env python3
"""Find crash-prone patterns in authorized local source code.

Useful for manual review of Rust/Go/Java projects. It only scans local files and
prints suspicious lines such as panic!, unwrap(), expect(), and NullPointerException hints.
"""
import argparse
import os
import re
import csv

RULES = {
    'rust-panic': re.compile(r'\bpanic!\s*\('),
    'rust-unwrap': re.compile(r'\.unwrap\s*\('),
    'rust-expect': re.compile(r'\.expect\s*\('),
    'go-panic': re.compile(r'\bpanic\s*\('),
    'java-null-risk': re.compile(r'NullPointerException|\.get\(.*\)|Objects\.requireNonNull'),
    'todo-security': re.compile(r'(?i)TODO.*(security|auth|validate|panic|error)'),
}

EXTS = {'.rs', '.go', '.java', '.kt', '.scala'}
SKIP_DIRS = {'.git', 'target', 'build', 'node_modules', 'vendor'}


def main():
    ap = argparse.ArgumentParser(description='Scan local authorized code for crash-prone patterns.')
    ap.add_argument('path')
    ap.add_argument('-o', '--output', default='panic-findings.csv')
    args = ap.parse_args()

    rows=[]
    for root, dirs, files in os.walk(args.path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            if os.path.splitext(fn)[1] not in EXTS:
                continue
            full=os.path.join(root, fn)
            try:
                lines=open(full, encoding='utf-8', errors='ignore').read().splitlines()
            except Exception:
                continue
            for i,line in enumerate(lines, start=1):
                for name, rx in RULES.items():
                    if rx.search(line):
                        rows.append({'file':full,'line':i,'type':name,'sample':line.strip()[:180]})

    with open(args.output,'w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['file','line','type','sample'])
        w.writeheader(); w.writerows(rows)
    print(f'Saved {len(rows)} findings to {args.output}')

if __name__ == '__main__':
    main()
