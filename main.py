# SPDX-License-Identifier: Apache-2.0
"""
VulnScope — zero-trust dependency risk guardrail for autonomous coding agents.

Agents call /v1/evaluate before installing a package; the service queries
OSV.dev, EPSS, and (optionally) GitHub, then returns a cryptographically
signed APPROVED / DENIED verdict.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import math
import os
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import httpx
try:
    from packaging.version import InvalidVersion as _InvalidPkgVersion
    from packaging.version import Version as _PkgVersion
    _HAVE_PACKAGING = True
except ImportError:
    _HAVE_PACKAGING = False

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from dotenv import load_dotenv
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

load_dotenv()

log = logging.getLogger("vulnscope")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

# ── Denial thresholds (change here, nowhere else) ─────────────────────────────
EPSS_DENY_PERCENTILE: float = 0.90        # deny when any CVE's percentile > this
SEVERITY_DENY_SET: frozenset[str] = frozenset({"CRITICAL", "HIGH"})  # deny when severity in set AND no fix
HTTP_TIMEOUT: float = 5.0                  # seconds; every external call shares this

# ── External API base URLs ────────────────────────────────────────────────────
_OSV_BATCH   = "https://api.osv.dev/v1/querybatch"
_OSV_VULN    = "https://api.osv.dev/v1/vulns/{id}"
_EPSS_URL    = "https://api.first.org/data/v1/epss"
_PYPI_JSON   = "https://pypi.org/pypi/{name}/json"
_NPM_REG     = "https://registry.npmjs.org/{name}"
_GH_REPO     = "https://api.github.com/repos/{owner}/{repo}"
_GH_COMMITS  = "https://api.github.com/repos/{owner}/{repo}/commits"

# ── Private signing key (set on startup) ─────────────────────────────────────
_priv_key: Ed25519PrivateKey | None = None


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  Key management
# ╚══════════════════════════════════════════════════════════════════════════════

def _boot_key() -> Ed25519PrivateKey:
    """Load key from PRIVATE_KEY_SEED or generate an ephemeral one."""
    seed_b64 = (os.getenv("PRIVATE_KEY_SEED") or "").strip()
    if seed_b64:
        seed = base64.b64decode(seed_b64)
        if len(seed) != 32:
            raise ValueError(
                f"PRIVATE_KEY_SEED must decode to exactly 32 bytes; got {len(seed)}"
            )
        log.info("Ed25519 signing key loaded from PRIVATE_KEY_SEED.")
        return Ed25519PrivateKey.from_private_bytes(seed)

    # Generate a fresh key and warn loudly
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    b64 = base64.b64encode(raw).decode()
    print(
        "\n" + "=" * 70 + "\n"
        "  ⚠️  NEW Ed25519 KEY — EPHEMERAL (this process only)\n"
        "  Clients caching the old public key will reject future verdicts.\n\n"
        "  SAVE THIS TO YOUR .env FILE OR DEPLOY ENVIRONMENT VARS:\n\n"
        f"    PRIVATE_KEY_SEED={b64}\n\n"
        "  Then restart. Signatures will be consistent across restarts.\n"
        + "=" * 70 + "\n",
        flush=True,
    )
    return key


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _priv_key
    _priv_key = _boot_key()
    yield


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  App bootstrap
# ╚══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="VulnScope",
    description="Zero-trust dependency risk guardrail for autonomous coding agents.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
)


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  Signing helpers
# ╚══════════════════════════════════════════════════════════════════════════════

def _pub_hex() -> str:
    assert _priv_key is not None, "Key not initialised"
    raw = _priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw.hex()


def _sign_payload(payload: dict[str, Any]) -> str:
    """Canonically serialise *payload* and sign with Ed25519; return base64."""
    assert _priv_key is not None
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = _priv_key.sign(canonical.encode())
    return base64.b64encode(sig).decode()


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  Package spec parsing
# ╚══════════════════════════════════════════════════════════════════════════════

def _parse_spec(spec: str) -> tuple[str, str | None]:
    """
    'pyyaml==5.3.1' → ('pyyaml', '5.3.1')
    'lodash@4.17.20' → ('lodash', '4.17.20')
    'requests'       → ('requests', None)
    """
    spec = spec.strip()
    if "==" in spec:
        name, ver = spec.split("==", 1)
        return name.strip(), ver.strip()
    if "@" in spec and not spec.startswith("@"):
        name, ver = spec.split("@", 1)
        return name.strip(), ver.strip()
    return spec, None


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  CVSS scoring (no external dependency required)
# ╚══════════════════════════════════════════════════════════════════════════════

# CVSS 3.x metric weights
_W_AV:   dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_W_AC:   dict[str, float] = {"L": 0.77, "H": 0.44}
_W_PR_U: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
_W_PR_C: dict[str, float] = {"N": 0.85, "L": 0.50, "H": 0.50}   # Scope Changed
_W_UI:   dict[str, float] = {"N": 0.85, "R": 0.62}
_W_CIA:  dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.00}


def _roundup(x: float) -> float:
    """CVSS 3.x Roundup function: smallest value ≥ x with 1 decimal place."""
    return math.ceil(x * 10) / 10


def _cvss3_score(vector: str) -> float | None:
    """Compute CVSS 3.x base score; return None if vector is unparseable."""
    m: dict[str, str] = {}
    for seg in vector.split("/"):
        if ":" in seg:
            k, v = seg.split(":", 1)
            m[k] = v
    try:
        av  = _W_AV[m["AV"]]
        ac  = _W_AC[m["AC"]]
        sc  = m.get("S") == "C"
        pr  = (_W_PR_C if sc else _W_PR_U)[m["PR"]]
        ui  = _W_UI[m["UI"]]
        c   = _W_CIA[m["C"]]
        i   = _W_CIA[m["I"]]
        a   = _W_CIA[m["A"]]
    except KeyError:
        return None

    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)

    if sc:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploit = 8.22 * av * ac * pr * ui

    raw = 1.08 * (impact + exploit) if sc else (impact + exploit)
    return _roundup(min(raw, 10.0))


def _score_to_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _severity_of(vuln: dict[str, Any]) -> str:
    """Extract the highest severity from an OSV record."""
    # 1. GitHub Advisory (and many others) store it as a plain string here
    db = vuln.get("database_specific") or {}
    s = (db.get("severity") or "").upper()
    if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return s

    # 2. Per-affected database_specific (NVD entries sometimes use this)
    for aff in vuln.get("affected") or []:
        s = ((aff.get("database_specific") or {}).get("severity") or "").upper()
        if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return s

    # 3. CVSS vector in the severity array
    for entry in vuln.get("severity") or []:
        vec = entry.get("score", "")
        if "CVSS:3" in vec or vec.startswith("AV:"):
            score = _cvss3_score(vec)
            if score is not None:
                return _score_to_label(score)

    return "UNKNOWN"


def _has_fix(vuln: dict[str, Any]) -> bool:
    """True if any affected version range has a 'fixed' event."""
    for aff in vuln.get("affected") or []:
        for r in aff.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    return True
    return False


def _cve_ids(vuln: dict[str, Any]) -> list[str]:
    return [a for a in (vuln.get("aliases") or []) if a.startswith("CVE-")]


def _parse_pep440(v: str) -> "_PkgVersion | None":
    if not _HAVE_PACKAGING:
        return None
    try:
        return _PkgVersion(v)
    except Exception:
        return None


def _version_in_range(version_str: str, vuln: dict[str, Any], ecosystem: str) -> "bool | None":
    """True if version_str falls in any ECOSYSTEM affected range; None when undetermined.

    Returns None (rather than False) when packaging is unavailable or the ecosystem
    is not PyPI, so the caller can fall back to the no-version denial logic.
    """
    if not _HAVE_PACKAGING or ecosystem.upper() != "PYPI":
        return None
    v = _parse_pep440(version_str)
    if v is None:
        return None
    for aff in vuln.get("affected") or []:
        # Fast path: OSV explicit versions list
        if version_str in (aff.get("versions") or []):
            return True
        for r in aff.get("ranges") or []:
            if r.get("type") != "ECOSYSTEM":
                continue
            events: list[dict[str, Any]] = r.get("events") or []
            current_intro: "_PkgVersion | None" = None
            for ev in events:
                if "introduced" in ev:
                    current_intro = _parse_pep440(ev["introduced"]) or _parse_pep440("0")
                elif "fixed" in ev and current_intro is not None:
                    fixed_v = _parse_pep440(ev["fixed"])
                    if fixed_v is not None and current_intro <= v < fixed_v:
                        return True
                    current_intro = None
                elif "last_affected" in ev and current_intro is not None:
                    last_v = _parse_pep440(ev["last_affected"])
                    if last_v is not None and current_intro <= v <= last_v:
                        return True
                    current_intro = None
            # Open range: introduced with no following fixed
            if current_intro is not None and v >= current_intro:
                return True
    return False


def _first_fix_version(version_str: str, vuln: dict[str, Any], ecosystem: str) -> "str | None":
    """Smallest fixed version > version_str from any ECOSYSTEM range, or None."""
    if not _HAVE_PACKAGING or ecosystem.upper() != "PYPI":
        return None
    v = _parse_pep440(version_str)
    if v is None:
        return None
    candidates: list[_PkgVersion] = []
    for aff in vuln.get("affected") or []:
        for r in aff.get("ranges") or []:
            if r.get("type") != "ECOSYSTEM":
                continue
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    fv = _parse_pep440(ev["fixed"])
                    if fv is not None and fv > v:
                        candidates.append(fv)
    return str(min(candidates)) if candidates else None


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  External API calls (each swallows its own timeouts / errors)
# ╚══════════════════════════════════════════════════════════════════════════════

async def _osv_batch(
    client: httpx.AsyncClient,
    queries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    try:
        r = await client.post(_OSV_BATCH, json={"queries": queries})
        r.raise_for_status()
        return r.json().get("results") or [{}] * len(queries)
    except Exception as exc:
        log.warning("OSV batch failed: %s", exc)
        return [{}] * len(queries)


async def _osv_vuln_detail(
    client: httpx.AsyncClient,
    vid: str,
) -> dict[str, Any] | None:
    try:
        r = await client.get(_OSV_VULN.format(id=vid))
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        log.warning("OSV vuln %s failed: %s", vid, exc)
        return None


async def _epss_batch(
    client: httpx.AsyncClient,
    cve_ids: list[str],
) -> dict[str, dict[str, Any]]:
    """Query EPSS for a list of CVE IDs; return {cve: {percentile, epss_score, date}}."""
    if not cve_ids:
        return {}
    try:
        r = await client.get(_EPSS_URL, params={"cve": ",".join(cve_ids)})
        r.raise_for_status()
        return {
            d["cve"]: {
                "percentile": float(d.get("percentile", 0)),
                "epss_score": float(d.get("epss", 0)),
                "date": d.get("date"),
            }
            for d in (r.json().get("data") or [])
        }
    except Exception as exc:
        log.warning("EPSS batch failed: %s", exc)
        return {}


async def _resolve_github_url(
    client: httpx.AsyncClient,
    name: str,
    ecosystem: str,
) -> str | None:
    """Resolve a GitHub repo URL from the package registry."""
    eco = ecosystem.upper()
    try:
        if eco == "PYPI":
            r = await client.get(_PYPI_JSON.format(name=name))
            r.raise_for_status()
            info = r.json().get("info") or {}
            for url in ((info.get("project_urls") or {}).values()):
                if url and "github.com" in url:
                    return url
            if "github.com" in (info.get("home_page") or ""):
                return info["home_page"]
        elif eco == "NPM":
            r = await client.get(_NPM_REG.format(name=name))
            r.raise_for_status()
            repo = r.json().get("repository") or {}
            url  = (repo.get("url") or "") if isinstance(repo, dict) else ""
            if "github.com" in url:
                return url
    except Exception:
        pass
    return None


async def _github_meta(
    client: httpx.AsyncClient,
    name: str,
    ecosystem: str,
) -> dict[str, Any] | None:
    """Fetch GitHub repo metadata; returns None gracefully on any error."""
    try:
        gh_url = await _resolve_github_url(client, name, ecosystem)
        if not gh_url:
            return None

        m = re.search(
            r"github\.com[/:]([^/\s]+)/([^/\s.?#]+?)(?:\.git)?(?:[/?#]|$)",
            gh_url,
        )
        if not m:
            return None
        owner, repo = m.group(1), m.group(2)

        hdrs: dict[str, str] = {"Accept": "application/vnd.github+json"}
        tok = (os.getenv("GITHUB_TOKEN") or "").strip()
        if tok:
            hdrs["Authorization"] = f"Bearer {tok}"

        r = await client.get(_GH_REPO.format(owner=owner, repo=repo), headers=hdrs)
        if r.status_code != 200:
            log.info("GitHub %s/%s returned %d", owner, repo, r.status_code)
            return None
        rd = r.json()

        last_commit: str | None = None
        rc = await client.get(
            _GH_COMMITS.format(owner=owner, repo=repo),
            params={"per_page": 1},
            headers=hdrs,
        )
        if rc.status_code == 200 and rc.json():
            last_commit = (
                rc.json()[0].get("commit", {}).get("committer", {}).get("date")
            )

        return {
            "url": f"https://github.com/{owner}/{repo}",
            "stars": rd.get("stargazers_count"),
            "open_issues": rd.get("open_issues_count"),
            "last_commit": last_commit,
        }
    except Exception as exc:
        log.warning("GitHub meta for %s failed: %s", name, exc)
        return None


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  Endpoints
# ╚══════════════════════════════════════════════════════════════════════════════

@app.get("/health", summary="Liveness probe")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/pubkey", summary="Ed25519 public key for this instance")
async def v1_pubkey() -> dict[str, str]:
    return {"public_key_hex": _pub_hex(), "curve": "Ed25519"}


@app.get("/v1/evaluate", summary="Evaluate packages for vulnerability risk")
async def v1_evaluate(
    packages: str = Query(
        ...,
        description=(
            "Comma-separated package specs. "
            "Pin a version with == (PyPI) or @ (npm): "
            "'pyyaml==5.3.1,requests' or 'lodash@4.17.20'"
        ),
        openapi_examples={
            "denied": {"summary": "Known vulnerable", "value": "pyyaml==5.3.1"},
            "approved": {"summary": "Safe latest", "value": "requests"},
        },
    ),
    ecosystem: str = Query(
        "PyPI",
        description="Package ecosystem: PyPI or npm",
    ),
) -> JSONResponse:
    specs = [s.strip() for s in packages.split(",") if s.strip()]
    if not specs:
        return JSONResponse({"error": "No packages provided"}, status_code=400)

    parsed: list[tuple[str, str | None]] = [_parse_spec(s) for s in specs]

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:

        # ── Step 1: OSV batch query ──────────────────────────────────────────
        osv_queries: list[dict[str, Any]] = []
        for name, version in parsed:
            q: dict[str, Any] = {
                "package": {"name": name, "ecosystem": ecosystem}
            }
            if version:
                q["version"] = version
            osv_queries.append(q)

        osv_results = await _osv_batch(client, osv_queries)

        # ── Step 2: Collect vuln IDs per package ─────────────────────────────
        per_pkg_ids: list[list[str]] = []
        all_ids: set[str] = set()
        for res in osv_results:
            ids = [v["id"] for v in (res.get("vulns") or [])]
            per_pkg_ids.append(ids)
            all_ids.update(ids)

        # ── Step 3: Fetch vuln details in parallel ───────────────────────────
        id_list = list(all_ids)
        raw_details = await asyncio.gather(
            *[_osv_vuln_detail(client, vid) for vid in id_list]
        )
        vuln_map: dict[str, dict[str, Any]] = {
            vid: d
            for vid, d in zip(id_list, raw_details)
            if d is not None
        }

        # ── Step 4: Collect CVE IDs → EPSS + GitHub meta in parallel ─────────
        all_cves: list[str] = list(
            dict.fromkeys(
                cve
                for d in vuln_map.values()
                for cve in _cve_ids(d)
            )
        )

        results = await asyncio.gather(
            _epss_batch(client, all_cves),
            *[_github_meta(client, name, ecosystem) for name, _ in parsed],
        )
        epss_data: dict[str, dict[str, Any]] = results[0]
        gh_results: list[dict[str, Any] | None] = list(results[1:])

    # ── Step 5: Assemble per-package verdicts ─────────────────────────────────
    overall_verdict = "APPROVED"
    pkg_results: list[dict[str, Any]] = []

    for i, (name, version) in enumerate(parsed):
        reasons: list[str] = []
        vuln_entries: list[dict[str, Any]] = []

        for vid in per_pkg_ids[i]:
            d = vuln_map.get(vid)
            if d is None:
                vuln_entries.append({"id": vid, "detail": "unavailable"})
                continue

            sev     = _severity_of(d)
            has_fix = _has_fix(d)
            cves    = _cve_ids(d)

            vuln_epss: list[dict[str, Any]] = []
            max_pct: float | None = None
            for cve in cves:
                ed = epss_data.get(cve)
                if ed:
                    vuln_epss.append({"cve": cve, **ed})
                    p = ed["percentile"]
                    if max_pct is None or p > max_pct:
                        max_pct = p

            # ── Version range check (defense-in-depth; OSV already filters by version) ──
            in_range: bool | None = _version_in_range(version, d, ecosystem) if version else None
            # skip_denial=True only when we can *confirm* the queried version is outside the range
            skip_denial = version is not None and in_range is False

            # ── Denial criteria ──────────────────────────────────────────────
            if not skip_denial:
                if version is not None and in_range is True:
                    # Version confirmed in affected range — deny CRITICAL/HIGH regardless of has_fix,
                    # because the queried version itself is vulnerable.
                    if sev in SEVERITY_DENY_SET:
                        fix_ver = _first_fix_version(version, d, ecosystem)
                        if fix_ver:
                            reasons.append(
                                f"{sev} severity vuln {vid!r} affects version {version!r} "
                                f"(fix available in {fix_ver!r})"
                            )
                        else:
                            reasons.append(
                                f"{sev} severity vuln {vid!r} affects version {version!r} "
                                f"(no fix available)"
                            )
                else:
                    # No version specified, or range undetermined — fall back to global has_fix check.
                    if sev in SEVERITY_DENY_SET and not has_fix:
                        reasons.append(
                            f"{sev} severity vuln {vid!r} has no fixed version available"
                        )
                if max_pct is not None and max_pct > EPSS_DENY_PERCENTILE:
                    reasons.append(
                        f"EPSS percentile {max_pct:.4f} exceeds threshold "
                        f"{EPSS_DENY_PERCENTILE} (CVEs: {cves})"
                    )

            entry: dict[str, Any] = {
                "id": vid,
                "aliases": cves,
                "summary": d.get("summary", ""),
                "severity": sev,
                "has_fixed_version": has_fix,
                "epss": vuln_epss or None,
            }
            if version is not None:
                entry["in_affected_range"] = in_range
            vuln_entries.append(entry)

        deduped_reasons = list(dict.fromkeys(reasons))
        pkg_verdict = "DENIED" if deduped_reasons else "APPROVED"
        if pkg_verdict == "DENIED":
            overall_verdict = "DENIED"

        pkg_results.append({
            "name": name,
            "version": version,
            "version_checked": version is not None,
            "ecosystem": ecosystem,
            "verdict": pkg_verdict,
            "reasons": deduped_reasons,
            "vulnerabilities": vuln_entries,
            "github": gh_results[i],
        })

    # ── Step 6: Build payload, sign, and respond ──────────────────────────────
    payload: dict[str, Any] = {
        "verdict": overall_verdict,
        "ecosystem": ecosystem,
        "queried_at": datetime.now(UTC).isoformat(),
        "public_key_hex": _pub_hex(),
        "thresholds": {
            "epss_deny_percentile": EPSS_DENY_PERCENTILE,
            "severity_deny_set": sorted(SEVERITY_DENY_SET),
        },
        "packages": pkg_results,
    }

    sig = _sign_payload(payload)
    return JSONResponse({"payload": payload, "signature": sig})
