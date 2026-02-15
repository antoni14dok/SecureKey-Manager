#!/usr/bin/env python3
"""SecureKey Manager: generate and verify license keys for your own software.

This tool is intended for legitimate software licensing workflows.
It does NOT generate keys for third-party software (e.g., Microsoft products).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sys
from datetime import datetime, timezone
from typing import Any, Dict


class LicenseError(Exception):
    """Raised when a license is malformed or invalid."""


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _canonical_json(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def generate_license(secret: str, customer: str, product: str, expires: str | None = None) -> str:
    payload: Dict[str, Any] = {
        "id": secrets.token_hex(8),
        "customer": customer,
        "product": product,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }

    if expires:
        # Validate format and canonicalize to full ISO8601 UTC when provided.
        parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        payload["expires_at"] = parsed.astimezone(timezone.utc).isoformat()

    body = _b64url_encode(_canonical_json(payload))
    signature = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url_encode(signature)}"


def verify_license(secret: str, token: str) -> Dict[str, Any]:
    try:
        body, sig = token.split(".", 1)
    except ValueError as exc:
        raise LicenseError("Token must contain one '.' separator") from exc

    expected_sig = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    got_sig = _b64url_decode(sig)
    if not hmac.compare_digest(expected_sig, got_sig):
        raise LicenseError("Signature mismatch")

    try:
        payload = json.loads(_b64url_decode(body))
    except json.JSONDecodeError as exc:
        raise LicenseError("Payload is not valid JSON") from exc

    expires_at = payload.get("expires_at")
    if expires_at:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expiry.astimezone(timezone.utc):
            raise LicenseError("License expired")

    return payload


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate and verify license keys for your own app")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a signed license token")
    gen.add_argument("--secret", required=True, help="Signing secret (store securely)")
    gen.add_argument("--customer", required=True, help="Customer or company name")
    gen.add_argument("--product", required=True, help="Your product identifier")
    gen.add_argument("--expires", help="Expiry datetime in ISO8601, e.g. 2027-01-01T00:00:00Z")

    ver = sub.add_parser("verify", help="Verify a signed license token")
    ver.add_argument("--secret", required=True, help="Signing secret")
    ver.add_argument("--token", required=True, help="License token to verify")

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        if args.command == "generate":
            token = generate_license(
                secret=args.secret,
                customer=args.customer,
                product=args.product,
                expires=args.expires,
            )
            print(token)
            return 0

        payload = verify_license(secret=args.secret, token=args.token)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0
    except (LicenseError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
