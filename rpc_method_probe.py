#!/usr/bin/env python3
"""Safe JSON-RPC method probe for authorized RPC endpoints.

The tool sends a small allowlisted set of read-only JSON-RPC calls to endpoints you provide.
It is useful for finding exposed namespaces such as debug/trace/txpool on in-scope RPC services.
"""
import argparse
import json
import csv
import urllib.request
import urllib.error

METHODS = [
    ("web3_clientVersion", []),
    ("net_version", []),
    ("eth_chainId", []),
    ("eth_blockNumber", []),
    ("eth_syncing", []),
    ("txpool_status", []),
    ("trace_block", ["latest"]),
    ("debug_traceBlockByNumber", ["latest", {"tracer": "callTracer", "timeout": "1s"}]),
]

SENSITIVE_PREFIXES = ("debug_", "trace_", "txpool_")


def call_rpc(url, method, params, timeout):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "rpc-method-probe/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read(20000).decode("utf-8", errors="replace")
            data = json.loads(text)
            return {"http_status": r.status, "ok": "result" in data, "error_code": data.get("error", {}).get("code"), "error_message": data.get("error", {}).get("message"), "sample": text[:500]}
    except urllib.error.HTTPError as e:
        return {"http_status": e.code, "ok": False, "error_code": "HTTP", "error_message": str(e), "sample": ""}
    except Exception as e:
        return {"http_status": "", "ok": False, "error_code": "ERR", "error_message": str(e), "sample": ""}


def main():
    ap = argparse.ArgumentParser(description="Probe read-only JSON-RPC methods on authorized endpoints.")
    ap.add_argument("endpoints", help="File with one RPC URL per line")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("-o", "--output", default="rpc-probe-results.csv")
    args = ap.parse_args()

    endpoints = [x.strip() for x in open(args.endpoints, encoding="utf-8") if x.strip() and not x.startswith("#")]
    rows = []
    for url in endpoints:
        for method, params in METHODS:
            r = call_rpc(url, method, params, args.timeout)
            hint = "SENSITIVE_NAMESPACE_EXPOSED" if r["ok"] and method.startswith(SENSITIVE_PREFIXES) else ""
            row = {"url": url, "method": method, "ok": r["ok"], "http_status": r["http_status"], "error_code": r["error_code"], "error_message": r["error_message"], "hint": hint}
            rows.append(row)
            print(json.dumps(row, ensure_ascii=False))

    with open(args.output, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["url"])
        w.writeheader(); w.writerows(rows)
    print(f"Saved {args.output}")


if __name__ == "__main__":
    main()
