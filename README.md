# bug-bounty-tools

Safe helper scripts for authorized bug bounty research.

These tools are designed for assets where you have permission: bug bounty scope, your own lab, or systems you are explicitly authorized to test. They avoid brute force, exploit chains, auth bypass, credential attacks, and random internet scanning.

## Tools

| Script | Purpose |
|---|---|
| `safe_scope_recon.py` | Basic HTTP recon: status, redirects, security headers, CORS hints, `security.txt` |
| `scope_runner.py` | Normalize and deduplicate an authorized scope list |
| `cors_checker.py` | Check CORS headers with a few controlled Origin values |
| `rpc_method_probe.py` | Probe a small allowlisted set of read-only JSON-RPC methods |
| `jsonrpc_diff.py` | Compare JSON-RPC behavior between two authorized endpoints |
| `security_headers_report.py` | Build a Markdown report from `safe_scope_recon.py` JSONL output |
| `wayback_scope_filter.py` | Filter URL lists so only in-scope hosts remain |
| `endpoint_classifier.py` | Label URLs as auth/admin/upload/billing/graphql/API/etc. |
| `report_builder.py` | Generate a simple Markdown bug bounty report draft from evidence |
| `github_secret_audit.py` | Locally scan authorized repositories for common secret patterns |
| `panic_finder.py` | Locally find crash-prone Rust/Go/Java patterns for manual review |

## Quick start

```bash
git clone https://github.com/herrmayor/bug-bounty-tools.git
cd bug-bounty-tools

cat > targets.txt << 'EOF'
https://example.com
api.example.com
EOF

python3 safe_scope_recon.py targets.txt
python3 cors_checker.py targets.txt
```

## JSON-RPC helpers

Use these only on RPC endpoints that are in scope:

```bash
cat > rpc.txt << 'EOF'
https://rpc.example.com
EOF

python3 rpc_method_probe.py rpc.txt
python3 jsonrpc_diff.py https://rpc1.example.com https://rpc2.example.com
```

## URL filtering and classification

```bash
python3 wayback_scope_filter.py all-urls.txt scope.txt
python3 endpoint_classifier.py in-scope-urls.txt
```

## Report drafting

```bash
python3 security_headers_report.py recon-results.jsonl
python3 report_builder.py \
  --title "Potential CORS Misconfiguration" \
  --summary "The endpoint appears to reflect arbitrary Origin with credentials enabled." \
  --impact "If sensitive authenticated data is readable cross-origin, an attacker-controlled site may access victim data." \
  --severity "Medium/High after manual verification" \
  --evidence-file cors-results.csv
```

## Responsible use

Use only on assets where you have permission. Always verify scope and program rules before running tools. Most findings produced by these scripts are hints and need manual validation before submitting a report.
