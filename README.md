# VulnScope

Zero-trust dependency risk guardrail for autonomous coding agents.  Before an
agent installs a package it calls VulnScope; the service queries
[OSV.dev](https://osv.dev), [EPSS](https://www.first.org/epss/), and GitHub,
then returns a cryptographically signed **APPROVED / DENIED** verdict the agent
can trust even if the network path between them is untrusted.

---

## How it works

1. **OSV.dev** — queries CVE / GHSA vulnerability databases for each package.
2. **EPSS** — fetches exploit-prediction percentiles for every CVE found.
3. **GitHub** — retrieves stars, open-issue count, and last commit date for
   context (gracefully skipped when unavailable or unconfigured).
4. **Denial thresholds** (named constants in `main.py`, not magic numbers):
   - `SEVERITY_DENY_SET = {"CRITICAL", "HIGH"}` — denied when a vuln in this
     set has no fixed version available anywhere.
   - `EPSS_DENY_PERCENTILE = 0.90` — denied when any associated CVE's EPSS
     *percentile* (not raw score) exceeds this value.
5. **Ed25519 signature** — the entire verdict payload is serialised with
   `json.dumps(sort_keys=True)` before signing, so any byte-level tampering is
   detectable offline with `verify_signature.py`.

---

## Local development

### Prerequisites

- Python 3.11+
- pip

### Install and run

```bash
git clone <your-fork>
cd vulnscope

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# First run: prints a PRIVATE_KEY_SEED to stdout — copy it into .env
uvicorn main:app --reload
```

### Persist the signing key

On first startup (when `PRIVATE_KEY_SEED` is not set) a new key is generated
and the base64 seed is printed to stdout.  Copy it:

```bash
cp .env.example .env
# Edit .env and set PRIVATE_KEY_SEED=<the value printed above>
```

Restart — verdicts from this point on will carry a consistent public key.

**Never commit `.env`.** It is in `.gitignore`.

### Generate a seed manually

```bash
python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
```

---

## Endpoints

### `GET /health`

Liveness probe.

```bash
curl http://localhost:8000/health
```

```json
{"status":"ok"}
```

---

### `GET /v1/pubkey`

Returns the Ed25519 public key for this instance.  Clients cache this once
and use it to verify future verdict signatures offline.

```bash
curl http://localhost:8000/v1/pubkey
```

```json
{
  "public_key_hex": "a1b2c3…",
  "curve": "Ed25519"
}
```

---

### `GET /v1/evaluate`

Main endpoint.  Evaluate one or more packages for vulnerability risk.

| Parameter   | Required | Description |
|-------------|----------|-------------|
| `packages`  | yes      | Comma-separated list of package specs. Pin versions with `==` (PyPI) or `@` (npm). |
| `ecosystem` | no       | `PyPI` (default) or `npm`. |

#### Example — DENIED (pyyaml 5.3.1, CVE-2020-14343)

```bash
curl -s "http://localhost:8000/v1/evaluate?packages=pyyaml==5.3.1&ecosystem=PyPI" \
  | python3 -m json.tool
```

Expected result: **DENIED** — CVE-2020-14343 has an EPSS percentile above 0.90.

#### Example — APPROVED (requests 2.32.3, latest stable)

```bash
curl -s "http://localhost:8000/v1/evaluate?packages=requests==2.32.3&ecosystem=PyPI" \
  | python3 -m json.tool
```

Expected result: **APPROVED** — all known CVEs for this version are patched,
and none of their EPSS percentiles breach the 0.90 threshold.

> **Note on version pinning:** Querying without a version (`requests` alone) returns
> *all* historical vulns for the package across every version.  Some old, long-patched
> CVEs (e.g. CVE-2018-18074, fixed in 2.20.0) still carry high EPSS percentiles
> because they remain widely referenced by scanners.  Pin the version you actually
> intend to install for an accurate verdict.

#### Multiple packages in one call

```bash
curl -s "http://localhost:8000/v1/evaluate?packages=requests,flask&ecosystem=PyPI" \
  | python3 -m json.tool
```

---

### Response schema

```json
{
  "payload": {
    "verdict": "DENIED",
    "ecosystem": "PyPI",
    "queried_at": "2024-01-01T12:00:00+00:00",
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
                "date": "2024-01-01"
              }
            ]
          }
        ],
        "github": {
          "url": "https://github.com/yaml/pyyaml",
          "stars": 2100,
          "open_issues": 87,
          "last_commit": "2024-01-01T10:00:00Z"
        }
      }
    ]
  },
  "signature": "base64url…"
}
```

---

## Verifying a signature

```bash
# Save the response
curl -s "http://localhost:8000/v1/evaluate?packages=pyyaml==5.3.1" -o resp_denied.json

# Get the public key
PUB=$(curl -s http://localhost:8000/v1/pubkey \
      | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key_hex'])")

# Verify offline — no network call needed
python3 verify_signature.py resp_denied.json "$PUB"
```

Output on success:
```
✓  Signature VALID  |  Overall verdict: ✗ DENIED
   Signed at : 2024-01-01T12:00:00+00:00
   Public key: a1b2c3d4e5f6…
   pyyaml==5.3.1  →  ✗ DENIED
       reason: EPSS percentile 0.9780 exceeds threshold 0.9 ...
```

---

## Deployment

### Railway

```bash
npm install -g @railway/cli   # if not already installed
railway login
railway init
railway up
```

Set environment variables in the Railway dashboard:

| Variable           | Required | Notes |
|--------------------|----------|-------|
| `PRIVATE_KEY_SEED` | **Yes**  | Copy from first-run stdout or generate manually |
| `GITHUB_TOKEN`     | No       | Increases rate limit to 5 000 req/hr |

### Render

A `render.yaml` is included in the repo.  Connect the repo in the Render
dashboard, then set `PRIVATE_KEY_SEED` (and optionally `GITHUB_TOKEN`) as
environment variables marked **secret** in the Render UI.

```bash
# Or deploy via Render CLI
render deploy
```

---

## Environment variables

| Variable           | Default | Description |
|--------------------|---------|-------------|
| `PRIVATE_KEY_SEED` | (none)  | Base64-encoded 32-byte Ed25519 seed for key persistence |
| `GITHUB_TOKEN`     | (none)  | GitHub PAT; enables repo metadata and higher rate limits |

---

## Architecture notes

- Every external HTTP call is wrapped in a 5-second timeout (`HTTP_TIMEOUT`)
  and swallows its own exceptions — a flaky EPSS or GitHub response degrades
  gracefully rather than crashing the whole request.
- The signing key never touches disk; it lives only in process memory.
- CORS is open (`allow_origins=["*"]`) so browser-based agents can call
  VulnScope cross-origin without a proxy.
