# bug-bounty-tools

Safe helper scripts for authorized bug bounty research.

## Tool: safe_scope_recon.py

`safe_scope_recon.py` is a low-noise HTTP reconnaissance helper for **in-scope bug bounty targets only**.

It checks only the URLs you explicitly provide and reports:

- HTTP status and final URL
- redirect chain
- common security headers
- potentially interesting information-disclosure headers
- basic CORS reflection hints
- `/.well-known/security.txt` availability
- JSONL and CSV output for later notes or report drafting

It does **not** brute-force paths, exploit vulnerabilities, bypass authentication, attack login forms, or scan random IP ranges.

## Usage

Create a file with one authorized target per line:

```txt
https://example.com
api.example.com
```

Run:

```bash
python3 safe_scope_recon.py targets.txt
```

Optional flags:

```bash
python3 safe_scope_recon.py targets.txt --timeout 15 --delay 1 --jsonl out.jsonl --csv out.csv
```

## Output

The script creates two files by default:

- `recon-results.jsonl` - full structured output
- `recon-results.csv` - compact table for quick review

## Responsible use

Use only on assets where you have permission, such as bug bounty program scope, your own lab, or systems you are authorized to test.
