# SPDX-License-Identifier: Apache-2.0
"""Tests for version-aware vulnerability matching.

Checks that _version_in_range / _first_fix_version drive the per-vuln
denial logic correctly: a pinned version inside an affected range generates
a severity-based denial reason; a patched version is skipped.

No network required — all tests use in-process fixture data shaped like
real OSV records.
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from main import (
    SEVERITY_DENY_SET,
    _first_fix_version,
    _has_fix,
    _severity_of,
    _version_in_range,
)

# ---------------------------------------------------------------------------
# Fixtures: OSV-shaped vuln records (no network needed)
# ---------------------------------------------------------------------------

# CVE-2020-14343: PyYAML arbitrary-code-execution via unsafe_load.
# Affects [0, 5.4); fixed in 5.4.  CRITICAL, has a fix.
PYYAML_CVE_2020_14343 = {
    "id": "GHSA-rprw-h62v-c2w7",
    "summary": "PyYAML allows arbitrary code execution via unsafe_load",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [
        {
            "package": {"name": "PyYAML", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "5.4"}],
                }
            ],
            "versions": ["3.13", "5.1", "5.2", "5.3", "5.3.1", "5.4b1"],
        }
    ],
}

# A separate historical vuln that only affected old versions [1.0, 2.0).
# PyYAML 5.3.1 must NOT be detected as in range here.
PYYAML_OLD_RANGE = {
    "id": "GHSA-old-0001",
    "summary": "Old PyYAML issue fixed years ago",
    "database_specific": {"severity": "MEDIUM"},
    "affected": [
        {
            "package": {"name": "PyYAML", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0"}, {"fixed": "2.0"}],
                }
            ],
            "versions": ["1.0", "1.1"],
        }
    ],
}

# Multi-range vuln: two separate affected windows.
MULTI_RANGE_VULN = {
    "id": "MULTI-0001",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.0"},
                        {"introduced": "3.0"},
                        {"fixed": "3.5"},
                    ],
                }
            ]
        }
    ],
}

# Open-ended range: introduced with no fixed event.
OPEN_RANGE_VULN = {
    "id": "OPEN-0001",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "3.0"}],
                }
            ]
        }
    ],
}


# ---------------------------------------------------------------------------
# _version_in_range
# ---------------------------------------------------------------------------


class TestVersionInRange:
    def test_vulnerable_version_in_range(self) -> None:
        """pyyaml==5.3.1 is in [0, 5.4) → in range."""
        assert _version_in_range("5.3.1", PYYAML_CVE_2020_14343, "PyPI") is True

    def test_exact_boundary_version_is_in_range(self) -> None:
        """5.4b1 is a pre-release listed in explicit versions → in range."""
        assert _version_in_range("5.4b1", PYYAML_CVE_2020_14343, "PyPI") is True

    def test_fix_boundary_not_in_range(self) -> None:
        """pyyaml==5.4 is the fixed version itself → NOT in [0, 5.4)."""
        assert _version_in_range("5.4", PYYAML_CVE_2020_14343, "PyPI") is False

    def test_patched_version_not_in_range(self) -> None:
        """pyyaml==6.0.1 is well past the fix → not in range."""
        assert _version_in_range("6.0.1", PYYAML_CVE_2020_14343, "PyPI") is False

    def test_version_not_in_unrelated_old_range(self) -> None:
        """pyyaml==5.3.1 is NOT in the historical [1.0, 2.0) window."""
        assert _version_in_range("5.3.1", PYYAML_OLD_RANGE, "PyPI") is False

    def test_npm_ecosystem_returns_none(self) -> None:
        """npm ecosystem is not supported for range checking → None."""
        assert _version_in_range("5.3.1", PYYAML_CVE_2020_14343, "npm") is None

    def test_open_range_includes_version_above_introduced(self) -> None:
        """Open-ended range (no fixed event): 5.0 >= 3.0 → in range."""
        assert _version_in_range("5.0", OPEN_RANGE_VULN, "PyPI") is True

    def test_open_range_excludes_version_below_introduced(self) -> None:
        """Open-ended range: 2.9 < 3.0 → not in range."""
        assert _version_in_range("2.9", OPEN_RANGE_VULN, "PyPI") is False

    def test_multi_range_first_window(self) -> None:
        """1.5 is in first window [0, 2.0)."""
        assert _version_in_range("1.5", MULTI_RANGE_VULN, "PyPI") is True

    def test_multi_range_gap_between_windows(self) -> None:
        """2.5 is in gap between [0, 2.0) and [3.0, 3.5) → not in range."""
        assert _version_in_range("2.5", MULTI_RANGE_VULN, "PyPI") is False

    def test_multi_range_second_window(self) -> None:
        """3.2 is in second window [3.0, 3.5)."""
        assert _version_in_range("3.2", MULTI_RANGE_VULN, "PyPI") is True

    def test_multi_range_after_both_windows(self) -> None:
        """4.0 is past both windows → not in range."""
        assert _version_in_range("4.0", MULTI_RANGE_VULN, "PyPI") is False


# ---------------------------------------------------------------------------
# _first_fix_version
# ---------------------------------------------------------------------------


class TestFirstFixVersion:
    def test_returns_fix_for_vulnerable_version(self) -> None:
        """5.3.1 is affected; smallest fix > 5.3.1 is 5.4."""
        assert _first_fix_version("5.3.1", PYYAML_CVE_2020_14343, "PyPI") == "5.4"

    def test_returns_none_for_already_patched_version(self) -> None:
        """6.0.1 > 5.4; no fixed version candidate is newer → None."""
        assert _first_fix_version("6.0.1", PYYAML_CVE_2020_14343, "PyPI") is None

    def test_picks_smallest_candidate_from_multi_range(self) -> None:
        """1.5 is in first window; candidates are 2.0 and 3.5; min is 2.0."""
        assert _first_fix_version("1.5", MULTI_RANGE_VULN, "PyPI") == "2.0"

    def test_npm_ecosystem_returns_none(self) -> None:
        assert _first_fix_version("5.3.1", PYYAML_CVE_2020_14343, "npm") is None


# ---------------------------------------------------------------------------
# Denial logic integration: vulnerable vs patched version of the same package
# ---------------------------------------------------------------------------


def _simulate_denial(version: str, vuln: dict, vid: str) -> list[str]:
    """Replicate main.py's per-vuln denial logic for a single vuln record.

    Returns the reasons[] entries that would be appended for this vuln
    (EPSS omitted — not relevant to severity-based version testing).
    """
    sev = _severity_of(vuln)
    in_range = _version_in_range(version, vuln, "PyPI") if version else None
    skip_denial = version is not None and in_range is False

    reasons: list[str] = []
    if not skip_denial:
        if version is not None and in_range is True:
            if sev in SEVERITY_DENY_SET:
                fix_ver = _first_fix_version(version, vuln, "PyPI")
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
            if sev in SEVERITY_DENY_SET and not _has_fix(vuln):
                reasons.append(
                    f"{sev} severity vuln {vid!r} has no fixed version available"
                )
    return reasons


class TestDenialLogicVersionAware:
    def test_vulnerable_pyyaml_531_denied_with_severity_reason(self) -> None:
        """pyyaml==5.3.1: CRITICAL vuln in range → severity-based denial reason."""
        vid = "GHSA-rprw-h62v-c2w7"
        reasons = _simulate_denial("5.3.1", PYYAML_CVE_2020_14343, vid)

        assert len(reasons) == 1
        assert "CRITICAL" in reasons[0]
        assert "5.3.1" in reasons[0]
        assert "fix available in '5.4'" in reasons[0]

    def test_patched_pyyaml_601_generates_no_severity_reason(self) -> None:
        """pyyaml==6.0.1: CRITICAL vuln NOT in range → skip_denial → no reasons."""
        vid = "GHSA-rprw-h62v-c2w7"
        reasons = _simulate_denial("6.0.1", PYYAML_CVE_2020_14343, vid)

        assert reasons == []

    def test_no_version_pin_falls_back_to_global_has_fix(self) -> None:
        """No version specified: CRITICAL vuln with has_fix=True → no severity denial (old behaviour)."""
        # Without a version pin we can't confirm the queried version is in range,
        # so we fall back to the pre-range-check logic: deny only when has_fix=False.
        sev = _severity_of(PYYAML_CVE_2020_14343)
        has_fix = _has_fix(PYYAML_CVE_2020_14343)
        assert sev == "CRITICAL"
        assert has_fix is True  # fix exists at 5.4
        # No-version path: sev in SEVERITY_DENY_SET and not has_fix → False
        assert not (sev in SEVERITY_DENY_SET and not has_fix)

    def test_denial_reason_mentions_fix_version(self) -> None:
        """Denial reason for 5.3.1 must include the specific fix version '5.4'."""
        vid = "GHSA-rprw-h62v-c2w7"
        reasons = _simulate_denial("5.3.1", PYYAML_CVE_2020_14343, vid)
        assert any("'5.4'" in r for r in reasons)

    def test_verdict_denied_for_vulnerable_approved_for_patched(self) -> None:
        """End-to-end: pyyaml==5.3.1 → DENIED; pyyaml==6.0.1 → APPROVED."""
        vid = "GHSA-rprw-h62v-c2w7"
        vuln = PYYAML_CVE_2020_14343

        denied_reasons = _simulate_denial("5.3.1", vuln, vid)
        approved_reasons = _simulate_denial("6.0.1", vuln, vid)

        assert denied_reasons, "expected at least one denial reason for 5.3.1"
        assert approved_reasons == [], "expected no denial reasons for patched 6.0.1"
