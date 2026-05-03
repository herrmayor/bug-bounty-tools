#!/usr/bin/env python3
"""Compare JSON-RPC responses from two authorized endpoints.

Useful for bug bounty research on EVM-compatible or blockchain RPC services.
It sends read-only calls and highlights differences in result/error behavior.
"""
import argparse
import json
import csv
import urllib.request

CALLS = [
    ("web3_clientVersion", []),
    ("net_version", []),
    ("eth_chainId", []),
    ("eth_blockNumber", []),
    ("eth_syncing", []),
    ("txpool_status", []),
    ("trace_block", ["latest"]),
]


def rpc(url, method, params, timeout):
    body = json.dumps({"jsonrpc":"2.0","method":method,"params":params,"id":1}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type":"application/json","User-Agent":"jsonrpc-diff/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read(50000).decode("utf-8", errors="replace"))
            if "error" in data:
                return {"kind":"error", "code": data["error"].get("code"), "message": data["error"].get("message"), "result_type":""}
            return {"kind":"result", "code":"", "message":"", "result_type": type(data.get("result")).__name__}
    except Exception as e:
        return {"kind":"exception", "code":"ERR", "message":str(e), "result_type":""}


def main():
    ap = argparse.ArgumentParser(description="Diff JSON-RPC behavior between two authorized endpoints.")
    ap.add_argument("left")
    ap.add_argument("right")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("-o", "--output", default="jsonrpc-diff.csv")
    args = ap.parse_args()

    rows=[]
    for method, params in CALLS:
        a = rpc(args.left, method, params, args.timeout)
        b = rpc(args.right, method, params, args.timeout)
        diff = a != b
        row={"method":method,"different":diff,"left_kind":a["kind"],"left_code":a["code"],"left_message":a["message"],"left_result_type":a["result_type"],"right_kind":b["kind"],"right_code":b["code"],"right_message":b["message"],"right_result_type":b["result_type"]}
        rows.append(row)
        print(json.dumps(row, ensure_ascii=False))

    with open(args.output,"w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"Saved {args.output}")

if __name__ == "__main__":
    main()
