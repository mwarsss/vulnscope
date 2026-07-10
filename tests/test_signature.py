# SPDX-License-Identifier: Apache-2.0
"""Signature failure-mode tests for VulnScope Ed25519 verdicts.

Tests the four failure modes for the same canonical-serialisation +
Ed25519 scheme used by main.py (_sign_payload) and verify_signature.py:

  (a) Modified payload, original signature          → must reject
  (b) Original payload, modified signature          → must reject
  (c) Correct payload + signature, wrong public key → must reject
  (d) Truncated / malformed signature bytes         → must reject

One baseline "valid" test is also included so the reject tests are
meaningful (they would be vacuous if even valid signatures failed).

No network required, no running server required.
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# ---------------------------------------------------------------------------
# Helpers that mirror main.py's _sign_payload / verify_signature.py's verify
# ---------------------------------------------------------------------------


def _pub_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _canonical(payload: dict) -> bytes:
    """Same serialisation as main.py: compact JSON, sort_keys=True."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


def _sign(priv: Ed25519PrivateKey, payload: dict) -> str:
    return base64.b64encode(priv.sign(_canonical(payload))).decode()


def _verify(pub_hex: str, payload: dict, sig_b64: str) -> bool:
    """Return True iff signature is valid; False on any verification failure."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(base64.b64decode(sig_b64), _canonical(payload))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    return priv, _pub_hex(priv)


@pytest.fixture()
def valid_response(keypair: tuple[Ed25519PrivateKey, str]) -> tuple[dict, str, str]:
    """Return (payload, signature_b64, pub_hex) for a well-formed APPROVED verdict."""
    priv, pub_hex = keypair
    payload: dict = {
        "verdict": "APPROVED",
        "ecosystem": "PyPI",
        "queried_at": "2026-01-01T00:00:00+00:00",
        "public_key_hex": pub_hex,
        "thresholds": {
            "epss_deny_percentile": 0.9,
            "severity_deny_set": ["CRITICAL", "HIGH"],
        },
        "packages": [
            {
                "name": "requests",
                "version": "2.31.0",
                "version_checked": True,
                "verdict": "APPROVED",
                "reasons": [],
                "vulnerabilities": [],
            }
        ],
    }
    sig = _sign(priv, payload)
    return payload, sig, pub_hex


# ---------------------------------------------------------------------------
# Baseline: valid signature must verify
# ---------------------------------------------------------------------------


class TestValidSignature:
    def test_unmodified_response_verifies(
        self, valid_response: tuple[dict, str, str]
    ) -> None:
        payload, sig, pub_hex = valid_response
        assert _verify(pub_hex, payload, sig) is True


# ---------------------------------------------------------------------------
# Four failure modes
# ---------------------------------------------------------------------------


class TestSignatureFailureModes:
    def test_a_modified_payload_original_signature(
        self, valid_response: tuple[dict, str, str]
    ) -> None:
        """(a) Attacker flips the verdict field — original signature no longer matches."""
        payload, sig, pub_hex = valid_response
        tampered = {**payload, "verdict": "DENIED"}
        assert _verify(pub_hex, tampered, sig) is False, (
            "signature must NOT verify after payload is modified"
        )

    def test_b_original_payload_modified_signature(
        self, valid_response: tuple[dict, str, str]
    ) -> None:
        """(b) Single byte flipped in signature — must be rejected."""
        payload, sig, pub_hex = valid_response
        raw = bytearray(base64.b64decode(sig))
        raw[0] ^= 0xFF          # flip the first byte
        corrupted = base64.b64encode(bytes(raw)).decode()
        assert _verify(pub_hex, payload, corrupted) is False, (
            "signature must NOT verify after one byte is flipped"
        )

    def test_c_wrong_public_key(
        self, valid_response: tuple[dict, str, str]
    ) -> None:
        """(c) Verify against a different key — must be rejected."""
        payload, sig, _ = valid_response
        wrong_priv = Ed25519PrivateKey.generate()
        wrong_pub_hex = _pub_hex(wrong_priv)
        assert _verify(wrong_pub_hex, payload, sig) is False, (
            "signature must NOT verify against an unrelated public key"
        )

    def test_d_truncated_signature(
        self, valid_response: tuple[dict, str, str]
    ) -> None:
        """(d) Truncated to 32 bytes (half of a valid 64-byte Ed25519 sig) — must fail."""
        payload, sig, pub_hex = valid_response
        raw = base64.b64decode(sig)
        assert len(raw) == 64, f"expected 64-byte Ed25519 signature, got {len(raw)}"
        truncated = base64.b64encode(raw[:32]).decode()
        assert _verify(pub_hex, payload, truncated) is False, (
            "truncated signature must NOT verify"
        )

    def test_d_malformed_signature_not_base64(
        self, valid_response: tuple[dict, str, str]
    ) -> None:
        """(d) Completely malformed/non-base64 signature bytes — must fail."""
        payload, _, pub_hex = valid_response
        assert _verify(pub_hex, payload, "!!!NOT_VALID_BASE64!!!") is False, (
            "malformed signature must NOT verify"
        )

    def test_a_adding_extra_field_to_payload_breaks_signature(
        self, valid_response: tuple[dict, str, str]
    ) -> None:
        """(a) Adding an unsigned field to payload — canonical hash changes, sig invalid."""
        payload, sig, pub_hex = valid_response
        augmented = {**payload, "injected_field": "malicious"}
        assert _verify(pub_hex, augmented, sig) is False, (
            "signature must NOT verify after an extra field is injected into payload"
        )
