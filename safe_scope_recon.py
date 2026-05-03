#!/usr/bin/env python3
"""
safe_scope_recon.py

Safe, low-noise reconnaissance helper for authorized bug bounty research.

It only checks URLs explicitly supplied by the user and performs basic HTTP checks:
- status code and final URL
- redirect chain
- common security headers
- information-disclosure headers
- simple CORS reflection hints
- /.well-known/security.txt availability

This tool is intended for in-scope targets only. It does not brute-force paths,
exploit vulnerabilities, bypass authentication, or scan random IP ranges.
"""

from __future__ import annotations

import argparse
import csv
import json
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


DEFAULT_TIMEOUT = 10
TEST_ORIGIN = "https://example.com"
USER_AGENT = "safe-scope-recon/1.0 (+authorized-bug-bounty-research)"

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

INFORMATION_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
]


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass
class Finding:
    target: str
    final_url: Optional[str]
    status: Optional[int]
    title: str
    severity_hint: str
    detail: str


@dataclass
class Result:
    target: str
    checked_at: str
    ok: bool
    error: Optional[str]
    status: Optional[int]
    final_url: Optional[str]
    redirect_chain: List[str]
    content_type: Optional[str]
    content_length: Optional[str]
    information_headers: Dict[str, str]
    missing_security_headers: List[str]
    present_security_headers: Dict[str, str]
    cors: Dict[str, Optional[str]]
    security_txt: Dict[str, Optional[str]]
    findings: List[Finding]


def normalize_url(raw: str) -> Optional[str]:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        return None
    return raw


def read_targets(path: str) -> List[str]:
    targets: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            url = normalize_url(line)
            if url:
                targets.append(url)
    return sorted(set(targets))


def make_request(
    url: str,
    method: str = "GET",
    timeout: int = DEFAULT_TIMEOUT,
    extra_headers: Optional[Dict[str, str]] = None,
    follow_redirects: bool = True,
) -> Tuple[Optional[int], Dict[str, str], Optional[bytes], Optional[str], Optional[str]]:
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)

    request = Request(url, headers=headers, method=method)
    context = ssl.create_default_context()
    redirect_handler = HTTPRedirectHandler() if follow_redirects else NoRedirectHandler()
    opener = build_opener(HTTPSHandler(context=context), redirect_handler)

    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(4096) if method != "HEAD" else b""
            return response.status, dict(response.headers.items()), body, response.geturl(), None
    except HTTPError as exc:
        body = exc.read(4096) if method != "HEAD" else b""
        return exc.code, dict(exc.headers.items()), body, exc.geturl(), None
    except URLError as exc:
        return None, {}, None, None, str(exc.reason)
    except Exception as exc:  # noqa: BLE001 - keep scanning remaining authorized targets
        return None, {}, None, None, str(exc)


def lower_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def get_redirect_chain(url: str, timeout: int, max_redirects: int = 8) -> List[str]:
    chain = [url]
    current = url

    for _ in range(max_redirects):
        status, headers, _, _, error = make_request(
            current,
            method="GET",
            timeout=timeout,
            follow_redirects=False,
        )
        if error or status not in {301, 302, 303, 307, 308}:
            break
        location = headers.get("Location") or headers.get("location")
        if not location:
            break
        current = urljoin(current, location)
        if current in chain:
            break
        chain.append(current)

    return chain


def check_security_txt(final_url: str, timeout: int) -> Dict[str, Optional[str]]:
    parsed = urlparse(final_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    security_txt_url = urljoin(base, "/.well-known/security.txt")
    status, _, body, resolved, error = make_request(security_txt_url, timeout=timeout)
    body_text = body.decode("utf-8", errors="replace")[:500] if body else ""
    has_contact = "contact:" in body_text.lower()
    return {
        "url": security_txt_url,
        "status": str(status) if status is not None else None,
        "final_url": resolved,
        "error": error,
        "has_contact_field": str(has_contact),
    }


def analyze_target(url: str, timeout: int, delay: float) -> Result:
    if delay > 0:
        time.sleep(delay)

    checked_at = datetime.now(timezone.utc).isoformat()
    redirect_chain = get_redirect_chain(url, timeout=timeout)

    status, headers, _, final_url, error = make_request(
        url,
        method="GET",
        timeout=timeout,
        extra_headers={"Origin": TEST_ORIGIN},
        follow_redirects=True,
    )

    headers_l = lower_headers(headers)
    findings: List[Finding] = []

    information_headers = {
        header: headers_l[header]
        for header in INFORMATION_HEADERS
        if header in headers_l
    }

    present_security_headers = {
        header: headers_l[header]
        for header in SECURITY_HEADERS
        if header in headers_l
    }
    missing_security_headers = [header for header in SECURITY_HEADERS if header not in headers_l]

    if "strict-transport-security" not in headers_l and final_url and final_url.startswith("https://"):
        findings.append(Finding(
            target=url,
            final_url=final_url,
            status=status,
            title="Missing HSTS header on HTTPS response",
            severity_hint="Info/Low",
            detail="Strict-Transport-Security is absent. Usually not a standalone bounty issue, but useful for hardening notes.",
        ))

    if "content-security-policy" not in headers_l:
        findings.append(Finding(
            target=url,
            final_url=final_url,
            status=status,
            title="Missing Content-Security-Policy header",
            severity_hint="Info/Low",
            detail="CSP is absent. This can support impact if you later find XSS, but usually is not enough alone.",
        ))

    cors = {
        "access-control-allow-origin": headers_l.get("access-control-allow-origin"),
        "access-control-allow-credentials": headers_l.get("access-control-allow-credentials"),
        "tested_origin": TEST_ORIGIN,
    }

    if cors["access-control-allow-origin"] == TEST_ORIGIN and cors["access-control-allow-credentials"] == "true":
        findings.append(Finding(
            target=url,
            final_url=final_url,
            status=status,
            title="Potential reflected CORS with credentials",
            severity_hint="Medium/High if sensitive authenticated data is readable",
            detail="The response reflected the supplied Origin and allowed credentials. Manually verify on an authenticated sensitive endpoint before reporting.",
        ))
    elif cors["access-control-allow-origin"] == "*" and cors["access-control-allow-credentials"] == "true":
        findings.append(Finding(
            target=url,
            final_url=final_url,
            status=status,
            title="Suspicious wildcard CORS with credentials",
            severity_hint="Low/Medium depending on browser behavior and endpoint sensitivity",
            detail="Wildcard ACAO with credentials is suspicious. Manually verify exploitability and browser enforcement.",
        ))

    security_txt = check_security_txt(final_url or url, timeout=timeout) if not error else {
        "url": None,
        "status": None,
        "final_url": None,
        "error": "skipped because target request failed",
        "has_contact_field": None,
    }

    return Result(
        target=url,
        checked_at=checked_at,
        ok=error is None,
        error=error,
        status=status,
        final_url=final_url,
        redirect_chain=redirect_chain,
        content_type=headers_l.get("content-type"),
        content_length=headers_l.get("content-length"),
        information_headers=information_headers,
        missing_security_headers=missing_security_headers,
        present_security_headers=present_security_headers,
        cors=cors,
        security_txt=security_txt,
        findings=findings,
    )


def write_jsonl(path: str, results: Iterable[Result]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(asdict(result), ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: str, results: Iterable[Result]) -> None:
    rows = []
    for result in results:
        rows.append({
            "target": result.target,
            "ok": result.ok,
            "status": result.status,
            "final_url": result.final_url,
            "error": result.error,
            "missing_security_headers": ",".join(result.missing_security_headers),
            "information_headers": json.dumps(result.information_headers, ensure_ascii=False),
            "cors_acao": result.cors.get("access-control-allow-origin"),
            "cors_acac": result.cors.get("access-control-allow-credentials"),
            "security_txt_status": result.security_txt.get("status"),
            "finding_titles": " | ".join(finding.title for finding in result.findings),
        })

    fieldnames = list(rows[0].keys()) if rows else ["target"]
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def print_summary(results: List[Result]) -> None:
    print("\nSummary")
    print("=======")
    print(f"Targets checked: {len(results)}")
    print(f"Successful: {sum(1 for r in results if r.ok)}")
    print(f"Failed: {sum(1 for r in results if not r.ok)}")
    print(f"Potential findings: {sum(len(r.findings) for r in results)}")

    for result in results:
        print(f"\n[{result.status or 'ERR'}] {result.target}")
        if result.final_url and result.final_url != result.target:
            print(f"  final: {result.final_url}")
        if result.error:
            print(f"  error: {result.error}")
        for finding in result.findings:
            print(f"  - {finding.severity_hint}: {finding.title}")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safe HTTP recon helper for in-scope bug bounty targets.")
    parser.add_argument("targets", help="Text file with one in-scope URL or domain per line")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between targets in seconds")
    parser.add_argument("--jsonl", default="recon-results.jsonl", help="JSONL output path")
    parser.add_argument("--csv", default="recon-results.csv", help="CSV output path")
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    targets = read_targets(args.targets)

    if not targets:
        print("No valid targets found. Add in-scope URLs to the target file.", file=sys.stderr)
        return 2

    results: List[Result] = []
    for index, target in enumerate(targets, start=1):
        print(f"[{index}/{len(targets)}] Checking {target}")
        results.append(analyze_target(target, timeout=args.timeout, delay=args.delay))

    write_jsonl(args.jsonl, results)
    write_csv(args.csv, results)
    print_summary(results)
    print(f"\nSaved: {args.jsonl}")
    print(f"Saved: {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
