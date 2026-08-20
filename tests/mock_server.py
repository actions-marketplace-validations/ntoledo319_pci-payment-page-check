#!/usr/bin/env python3
"""Local contract double for the composite Action self-test."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        if self.path != "/api/v1/scan/pci":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)
            return
        expected = (
            "unknown-vendor.example" in str(body.get("html", ""))
            and body.get("url") == "https://shop.example/checkout"
            and body.get("allowed_domains") == ["js.stripe.com"]
            and body.get("payment_page_scope") == "direct"
        )
        if not expected:
            self.send_error(422)
            return

        finding = {
            "code": "SCRIPT_DOMAIN_UNAUTHORIZED",
            "severity": "high",
            "message": "An observed script host was absent from the supplied list.",
            "evidence": "unknown-vendor.example",
        }
        payload = json.dumps(
            {
                "headline": "One bounded observation needs review.",
                "observed_findings": [finding],
                "proven_gaps": [finding],
                "total_findings": 1,
                "remediation_locked": True,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    port = int(os.environ.get("CSI_TEST_PORT", "18765"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
