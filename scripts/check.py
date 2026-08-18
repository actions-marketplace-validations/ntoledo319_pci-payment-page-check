#!/usr/bin/env python3
"""Check a payment page's scripts against the list you authorized.

Standard library only, on purpose. An action that pip-installs is an action
that breaks in somebody's locked-down runner, and a compliance check that
fails to run is worse than no check — it produces a green tick nobody earned.

The analysis runs as a hosted service rather than in the runner. That is not
only a distribution choice: the check has to fetch the scripts a page
references to see whether their contents changed, and doing that from inside
somebody's CI network is a thing a security tool should not do casually.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 60
MAX_HTML_BYTES = 2_000_000

# Ordered, so "fail on medium" also fails on high.
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _in(name: str, default: str = "") -> str:
    return (os.environ.get(f"INPUT_{name}") or default).strip()


def _out(key: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    # Multi-line values need the delimiter form or the runner truncates them.
    with open(path, "a", encoding="utf-8") as handle:
        if "\n" in value:
            handle.write(f"{key}<<__EOF__\n{value}\n__EOF__\n")
        else:
            handle.write(f"{key}={value}\n")


def _summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(markdown + "\n")


def _fail(message: str) -> "None":
    print(f"::error::{message}")
    sys.exit(1)


def build_request_body() -> dict:
    url = _in("URL")
    html_file = _in("HTML_FILE")
    if not url and not html_file:
        _fail("Provide either `url` or `html-file`.")
    if url and html_file:
        _fail("Provide `url` or `html-file`, not both.")

    body: dict = {}
    if html_file:
        if not os.path.isfile(html_file):
            _fail(f"html-file not found: {html_file}")
        size = os.path.getsize(html_file)
        if size > MAX_HTML_BYTES:
            _fail(f"html-file is {size} bytes; the limit is {MAX_HTML_BYTES}.")
        with open(html_file, "r", encoding="utf-8", errors="replace") as handle:
            body["html"] = handle.read()
        # The service attributes relative script URLs against this.
        body["url"] = url or "https://example.invalid/checkout"
    else:
        if not url.startswith("https://"):
            _fail("`url` must be an https URL. A payment page served over http "
                  "cannot satisfy PCI DSS regardless of what this check reports.")
        body["url"] = url

    allowed = [d.strip() for d in _in("ALLOWED_DOMAINS").split(",") if d.strip()]
    if allowed:
        body["allowed_domains"] = allowed
    return body


def call_service(body: dict) -> dict:
    base = _in("API_BASE", "https://qi.toledotechnologies.com").rstrip("/")
    request = urllib.request.Request(
        f"{base}/api/v1/scan/pci",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "pci-payment-page-check-action/1",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        _fail(f"The check service returned HTTP {exc.code}: {detail}")
    except Exception as exc:  # noqa: BLE001
        _fail(f"Could not reach the check service: {type(exc).__name__}: {exc}")
    return {}


def main() -> int:
    result = call_service(build_request_body())
    if result.get("error"):
        _fail(str(result["error"]))

    gaps = result.get("proven_gaps") or []
    total = int(result.get("total_findings") or 0)
    headline = result.get("headline") or "Check complete."

    threshold = _in("FAIL_ON", "high").lower()
    if threshold not in SEVERITY_RANK and threshold != "never":
        _fail(f"fail-on must be high, medium, low or never (got {threshold!r}).")

    blocking = []
    if threshold != "never":
        floor = SEVERITY_RANK[threshold]
        blocking = [
            g for g in gaps
            if SEVERITY_RANK.get(str(g.get("severity", "")).lower(), 0) >= floor
        ]

    lines = ["## PCI payment page script check", "", headline, ""]
    if gaps:
        lines += ["| Severity | Finding |", "| --- | --- |"]
        for gap in gaps:
            message = str(gap.get("message", "")).replace("|", "\\|")
            lines.append(f"| {gap.get('severity', '?')} | {message} |")
    else:
        lines.append("No blocking finding was returned for the checks performed.")
    lines += [
        "",
        "<sub>Software-generated evidence for qualified human review. It does not "
        "determine PCI DSS compliance and does not replace a QSA assessment. The "
        "check reads the served HTML and the referenced script contents; it does "
        "not execute the page, and it cannot decide whether a script is "
        "authorized — only you can. "
        "[What 6.4.3 and 11.6.1 ask for]"
        "(https://qi.toledotechnologies.com/pci)</sub>",
    ]
    _summary("\n".join(lines))

    passed = not blocking
    _out("passed", "true" if passed else "false")
    _out("findings", str(total))
    _out("report", json.dumps(result))

    print(headline)
    for gap in gaps:
        print(f"  [{gap.get('severity')}] {gap.get('message')}")

    if not passed:
        print(f"::error::{len(blocking)} finding(s) at or above '{threshold}'.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
