#!/usr/bin/env python3
"""
verify_signature.py — Prove that a VulnScope verdict is authentic.

Reconstructs the exact bytes that were signed, then verifies the Ed25519
signature without contacting VulnScope at all.  A valid result means the
payload arrived unaltered from the key that signed it.

Usage
-----
  # Save a response and grab the public key
  curl -s "http://localhost:8000/v1/evaluate?packages=requests" -o resp.json
  PUB=$(curl -s http://localhost:8000/v1/pubkey | python3 -c \
        "import sys, json; print(json.load(sys.stdin)['public_key_hex'])")

  # Verify
  python3 verify_signature.py resp.json "$PUB"

  # Or rely on the public key embedded in the payload itself
  python3 verify_signature.py resp.json
"""

from __future__ import annotations

import base64
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify(response_path: str, pubkey_hex: str | None = None) -> None:
    with open(response_path) as f:
        response = json.load(f)

    payload       = response["payload"]
    signature_b64 = response["signature"]

    # Prefer the explicit argument; fall back to the key embedded in the payload.
    hex_key = pubkey_hex or payload.get("public_key_hex")
    if not hex_key:
        print("✗  No public key provided and none embedded in payload.", file=sys.stderr)
        sys.exit(1)

    # Reconstruct the EXACT bytes that were signed (same canonical form as main.py)
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    message   = canonical.encode()

    # Load the public key and verify
    pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key))
    sig     = base64.b64decode(signature_b64)

    try:
        pub_key.verify(sig, message)
    except InvalidSignature:
        print("✗  Signature INVALID — payload may have been tampered with.", file=sys.stderr)
        sys.exit(1)

    # Success — print a human-friendly summary
    verdict = payload.get("verdict", "?")
    icon    = "✓" if verdict == "APPROVED" else "✗"
    print(f"✓  Signature VALID  |  Overall verdict: {icon} {verdict}")
    print(f"   Signed at : {payload.get('queried_at', '?')}")
    print(f"   Public key: {hex_key[:16]}…")
    print()
    for pkg in payload.get("packages", []):
        ver    = f"=={pkg['version']}" if pkg.get("version") else " (latest)"
        status = "✓ APPROVED" if pkg["verdict"] == "APPROVED" else "✗ DENIED"
        print(f"   {pkg['name']}{ver}  →  {status}")
        for r in pkg.get("reasons", []):
            print(f"       reason: {r}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    _path    = sys.argv[1]
    _pub_hex = sys.argv[2] if len(sys.argv) > 2 else None
    verify(_path, _pub_hex)
