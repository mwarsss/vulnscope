# VulnScope — Dependency Risk Guardrail Skill

VulnScope is a zero-trust dependency risk guardrail that autonomous coding
agents should call **before installing any package**.  It cross-references the
package against OSV.dev (which aggregates CVE, GitHub Advisory, and ecosystem
security databases), the EPSS exploit-prediction service, and optionally GitHub
repo metadata, then returns a cryptographically signed **APPROVED** or **DENIED**
verdict.  Because the verdict is Ed25519-signed, the agent can verify
independently that the response has not been altered in transit — VulnScope does
not need to be on a trusted network path.

---

## Base URL

```
https://vulnscope-production-3986.up.railway.app
```

---

## Endpoints

### `GET /health`

Liveness probe.  Returns `200 OK` when the service is up.

**Request**
```
GET /health
```

**Response**
```json
{"status": "ok"}
```

---

### `GET /v1/pubkey`

Returns the Ed25519 public key for this instance.  Agents should cache this
key and use it to verify all subsequent verdicts offline.  If the key changes
(new deployment without `PRIVATE_KEY_SEED`), re-fetch it.

**Request**
```
GET /v1/pubkey
```

**Response**
```json
{
  "public_key_hex": "a1b2c3d4e5f6…64-hex-chars…",
  "curve": "Ed25519"
}
```

---

### `GET /v1/evaluate`

Evaluate one or more packages for vulnerability risk.

**Query parameters**

| Parameter   | Required | Type   | Description |
|-------------|----------|--------|-------------|
| `packages`  | **Yes**  | string | Comma-separated package specs.  Pin a version with `==` for PyPI or `@` for npm.  Examples: `pyyaml==5.3.1`, `requests`, `lodash@4.17.20,express`. |
| `ecosystem` | No       | string | `PyPI` (default) or `npm`. |

**Sample request — known DENIED case**
```
GET https://vulnscope-production-3986.up.railway.app/v1/evaluate?packages=pyyaml==5.3.1&ecosystem=PyPI
```

**Sample response — DENIED**
```json
{
  "payload": {
    "verdict": "DENIED",
    "ecosystem": "PyPI",
    "queried_at": "2024-06-01T12:00:00+00:00",
    "public_key_hex": "a1b2c3…",
    "thresholds": {
      "epss_deny_percentile": 0.9,
      "severity_deny_set": ["CRITICAL", "HIGH"]
    },
    "packages": [
      {
        "name": "pyyaml",
        "version": "5.3.1",
        "ecosystem": "PyPI",
        "verdict": "DENIED",
        "reasons": [
          "EPSS percentile 0.9780 exceeds threshold 0.9 (CVEs: ['CVE-2020-14343'])"
        ],
        "vulnerabilities": [
          {
            "id": "GHSA-6757-jp84-gxfx",
            "aliases": ["CVE-2020-14343"],
            "summary": "Arbitrary code execution in PyYAML",
            "severity": "CRITICAL",
            "has_fixed_version": true,
            "epss": [
              {
                "cve": "CVE-2020-14343",
                "percentile": 0.9780,
                "epss_score": 0.71671,
                "date": "2024-06-01"
              }
            ]
          }
        ],
        "github": {
          "url": "https://github.com/yaml/pyyaml",
          "stars": 2100,
          "open_issues": 87,
          "last_commit": "2024-05-15T10:00:00Z"
        }
      }
    ]
  },
  "signature": "base64-encoded-ed25519-signature…"
}
```

**Sample request — known APPROVED case**
```
GET https://vulnscope-production-3986.up.railway.app/v1/evaluate?packages=requests&ecosystem=PyPI
```

**Sample response — APPROVED** (abbreviated)
```json
{
  "payload": {
    "verdict": "APPROVED",
    "packages": [
      {
        "name": "requests",
        "version": null,
        "verdict": "APPROVED",
        "reasons": [],
        "vulnerabilities": []
      }
    ],
    "queried_at": "2024-06-01T12:00:00+00:00",
    "public_key_hex": "a1b2c3…"
  },
  "signature": "base64…"
}
```

---

## How to interpret the response

### `payload.verdict`

| Value      | Meaning |
|------------|---------|
| `APPROVED` | No denial criterion was triggered.  The package is safe to install based on OSV/EPSS data at query time.  Findings and warnings may still be present in `vulnerabilities`. |
| `DENIED`   | At least one criterion was triggered (see `packages[].reasons`).  **Do not install.  Surface the reasons to the human supervisor.** |

### `packages[].verdict`

Per-package decision.  Overall verdict is `DENIED` if any single package is denied.

### `packages[].reasons`

Human-readable list of the specific denial triggers.  Present and non-empty only
when `verdict = "DENIED"`.  Always surface these to the human — they explain
*why* the package was blocked, which the human needs to make an informed
override decision.

### What to do on DENIED

1. **Do not install the package.**
2. Surface the `reasons` array and the `vulnerabilities` array to the human.
3. If the human decides to override, they should do so explicitly (not the agent unilaterally).
4. Consider whether a different version or alternative package is available.

### `packages[].vulnerabilities[].epss`

EPSS fields:

| Field          | Meaning |
|----------------|---------|
| `epss_score`   | Raw probability (0–1) that the CVE is exploited in the wild in the next 30 days. |
| `percentile`   | Fraction of all scored CVEs this CVE ranks above.  **This is what the threshold applies to.** |

A percentile of `0.978` means this CVE is more actively exploited than 97.8% of
all CVEs in the EPSS dataset — a strong signal to block.

---

## Verifying the signature

The signature proves VulnScope issued this exact verdict unaltered.  It does
**not** guarantee the verdict is correct — it reflects OSV/EPSS data at the
moment of the query.  Stale or incomplete upstream data may cause a
false-negative (APPROVED for a genuinely dangerous package).

### How to verify (Python)

```python
import base64, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def verify_vulnscope_response(response: dict, public_key_hex: str) -> bool:
    """
    Returns True if the signature is valid, False otherwise.
    
    `response`        — parsed JSON from /v1/evaluate
    `public_key_hex`  — hex string from /v1/pubkey (cache this)
    """
    payload   = response["payload"]
    signature = base64.b64decode(response["signature"])

    # Reconstruct the EXACT canonical bytes that were signed
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    message   = canonical.encode()

    pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    try:
        pub_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
```

### Key points for implementors

- The canonical form is `json.dumps(payload, separators=(",", ":"), sort_keys=True)`.
  Any whitespace difference or key reordering will cause verification to fail.
- Use `payload.public_key_hex` as a fallback if you haven't cached the key, but
  always cross-check it against a separately obtained `/v1/pubkey` response at
  least once.
- The signed bytes are the *payload object only* — not the outer wrapper that
  contains `signature`.

---

## Notes for agents

- Set a reasonable timeout on calls to `/v1/evaluate` (10–15 s recommended,
  since VulnScope itself makes several upstream calls with 5 s timeouts each).
- Cache `/v1/pubkey` per session or per deployment — it changes only if the
  service restarts without `PRIVATE_KEY_SEED`.
- CORS is open; browser-based agents may call this endpoint directly.
- The service does not persist any data about what was queried.
