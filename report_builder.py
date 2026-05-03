#!/usr/bin/env python3
"""Build a simple bug bounty report draft from evidence text/JSON files."""
import argparse
from pathlib import Path

TEMPLATE = """# {title}

## Summary

{summary}

## Steps To Reproduce

1. Confirm the asset is in scope.
2. Run the attached safe helper command.
3. Review the evidence below.
4. Manually verify exploitability and impact before submission.

## Evidence

```text
{evidence}
```

## Impact

{impact}

## Suggested Severity

{severity}

## Notes

This draft is generated from local evidence. Edit it before submitting to any bug bounty program.
"""


def main():
    ap = argparse.ArgumentParser(description='Generate a Markdown bug bounty report draft.')
    ap.add_argument('--title', required=True)
    ap.add_argument('--summary', default='Describe the vulnerability in one or two sentences.')
    ap.add_argument('--impact', default='Describe what an attacker can access, modify, or disrupt.')
    ap.add_argument('--severity', default='Needs manual assessment')
    ap.add_argument('--evidence-file', required=True)
    ap.add_argument('-o', '--output', default='report-draft.md')
    args = ap.parse_args()

    evidence = Path(args.evidence_file).read_text(encoding='utf-8', errors='replace')[:20000]
    report = TEMPLATE.format(title=args.title, summary=args.summary, impact=args.impact, severity=args.severity, evidence=evidence)
    Path(args.output).write_text(report, encoding='utf-8')
    print(f'Saved {args.output}')

if __name__ == '__main__':
    main()
