#!/usr/bin/env python3
"""Create a Markdown report from safe_scope_recon.py JSONL output."""
import argparse
import json


def main():
    ap = argparse.ArgumentParser(description='Build a Markdown security headers report from recon-results.jsonl.')
    ap.add_argument('jsonl')
    ap.add_argument('-o', '--output', default='security-headers-report.md')
    args = ap.parse_args()

    rows = [json.loads(x) for x in open(args.jsonl, encoding='utf-8') if x.strip()]
    lines = ['# Security Headers Report', '', '| Target | Status | Missing Headers | Findings |', '|---|---:|---|---|']
    for r in rows:
        missing = ', '.join(r.get('missing_security_headers') or [])
        findings = '<br>'.join(f.get('title', '') for f in r.get('findings') or [])
        lines.append(f"| {r.get('target')} | {r.get('status')} | {missing} | {findings} |")

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f'Saved {args.output}')


if __name__ == '__main__':
    main()
