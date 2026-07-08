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

## When to Use This Skill

Call VulnScope **before** running any package installation command.  This
includes, but is not limited to:

| Ecosystem | Package managers |
|-----------|-----------------|
| PyPI      | `pip install`, `uv add`, `poetry add`, `pip-compile` |
| npm       | `npm install`, `pnpm add`, `yarn add` |

**Rules:**

1. **Always call before installing** — not after.  The purpose of VulnScope is
   to gate the installation decision.  Calling it on a package that is already
   installed serves no operational purpose.
2. **Call for every install** — even packages you consider well-known.  EPSS
   scores and vulnerability disclosures change daily.
3. **Pin versions when possible** — include the exact version you intend to
   install (e.g. `requests==2.32.3`, `lodash@4.17.20`).  An unpinned query
   returns historical CVEs across all versions of the package, which can produce
   false DENIED verdicts for old, patched vulns.
4. **Batch packages in one call** — if you need to install multiple packages at
   once, pass them all as a comma-separated list in a single `/v1/evaluate`
   request rather than making one request per package.
5. **If DENIED, stop and escalate** — do not install the package, do not
   silently retry with a different version, and do not bypass the check.  Surface
   the denial reasons to the human and wait for explicit human approval.

---

## Typical Agent Workflow

Follow these steps every time you need to install one or more packages:

```
1. Determine the package(s) and version(s) to install.
   └─ Pin versions where possible (== for PyPI, @ for npm).

2. Fetch /v1/pubkey if not already cached for this session.
   └─ Cache the public_key_hex — it is stable across requests until the
      service restarts without PRIVATE_KEY_SEED.

3. Call GET /v1/evaluate?packages=<specs>&ecosystem=<PyPI|npm>
   └─ Set a 10–15 s timeout (VulnScope itself makes upstream calls with
      5 s timeouts each).

4. Verify the Ed25519 signature on the response.
   └─ If the signature is INVALID → treat as DENIED, report to the human
      as a potential integrity issue, and do not install.

5. Read payload.verdict.

   APPROVED ──► Proceed with installation.
   DENIED   ──► Stop. Do NOT install.
                Surface packages[].reasons and packages[].vulnerabilities
                to the human.
                Wait for explicit human approval before doing anything else.
```

**Do not skip step 4.**  Verifying the signature is what makes the zero-trust
model work — it proves the response was issued by VulnScope and has not been
modified in transit.

---

## When Not to Call This Skill

Do **not** call VulnScope for any of the following:

- **Removing packages** — `pip uninstall`, `npm uninstall`, etc.
- **Listing installed packages** — `pip list`, `npm ls`, etc.
- **Importing or using an already-installed package** — VulnScope gates
  installation decisions, not runtime usage.
- **Private or internal packages** — VulnScope queries OSV.dev and public
  registries (PyPI, npm).  Packages not published there will return no
  vulnerability data, making the verdict meaningless.
- **Unsupported ecosystems** — currently only `PyPI` and `npm` are supported.
  Do not call VulnScope for Cargo, Maven, Go modules, RubyGems, etc.
- **Operations unrelated to dependency installation** — file operations, API
  calls, code generation, test execution, and similar tasks do not require a
  VulnScope check.

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
GET https://vulnscope-production-3986.up.railway.app/v1/evaluate?packages=requests==2.32.3&ecosystem=PyPI
```

**Sample response — APPROVED** (abbreviated)
```json
{
  "payload": {
    "verdict": "APPROVED",
    "packages": [
      {
        "name": "requests",
        "version": "2.32.3",
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

## How to Interpret the Response

### `payload.verdict`

| Value      | Meaning |
|------------|---------|
| `APPROVED` | No denial criterion was triggered based on OSV and EPSS data available at query time.  **This is not a guarantee that the package is vulnerability-free.**  It means no known CVE met the configured EPSS percentile threshold or the unpatched severity threshold at the moment of the query.  Newly disclosed vulnerabilities, CVEs not yet scored by EPSS, and ecosystem-specific advisories not indexed by OSV may not be captured. |
| `DENIED`   | At least one criterion was triggered (see `packages[].reasons`).  **Do not install.  Surface the reasons to the human supervisor and wait for explicit approval.** |

### `packages[].verdict`

Per-package decision.  The top-level `payload.verdict` is `DENIED` if any
single package in the batch is denied.  Always check the per-package verdict to
identify which specific packages triggered the denial.

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

## Error Handling

VulnScope makes several upstream calls (OSV.dev, EPSS, GitHub) with individual
5-second timeouts.  A complete `/v1/evaluate` response may therefore take up to
approximately 10–15 seconds under load.

| Situation | Action |
|-----------|--------|
| Request times out or returns HTTP 5xx | Wait 3 seconds, retry the request once. |
| Retry also fails | Inform the human that VulnScope is unavailable.  **Do not proceed with installation automatically.**  The human must decide whether to bypass the check. |
| HTTP 4xx (bad request) | Check the `packages` parameter format (comma-separated specs, `==` for PyPI, `@` for npm).  Fix the request; do not retry the malformed one. |
| Signature verification fails | Do not install.  Report to the human as a potential integrity issue — the response may have been tampered with in transit. |
| `payload.verdict` is neither `APPROVED` nor `DENIED` | Treat as an error.  Do not install.  Report the unexpected response to the human. |

**Never bypass the VulnScope check silently.**  If the service is unavailable
and you cannot reach the human, prefer blocking the installation over proceeding
without a verdict.

---

## Verifying the Signature

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

## Notes for Agents

- Set a 10–15 s timeout on calls to `/v1/evaluate` — VulnScope itself makes
  several upstream calls with 5 s timeouts each, so end-to-end latency varies.
- Cache `/v1/pubkey` per session or per deployment — it changes only if the
  service restarts without `PRIVATE_KEY_SEED`.
- CORS is open; browser-based agents may call this endpoint directly.
- The service does not persist any data about what was queried.
- A package with `vulnerabilities` present but `verdict = "APPROVED"` means
  vulnerabilities were found but none met the denial thresholds — the
  `thresholds` object in the response shows the exact criteria applied.
