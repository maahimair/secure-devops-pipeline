#!/usr/bin/env python3
# tools/merge_scanners.py
# VerifierGate — scanner output normaliser.
#
# Collapses whatever the scanners dropped into scanner-output/ into one
# findings.json that correlate.py understands.
#
# The important behaviour here is what happens when a scanner produced NO file.
# A missing or empty report is treated as an error, not as "zero findings":
# silently treating an absent scan as a clean result is exactly the failure mode
# that lets a vulnerable build through.
#
# Standard library only.

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER_DIR = os.path.join(REPO_ROOT, "scanner-output")

# Reports that must exist for the gate to be trusted. A missing one is a hard
# failure.
REQUIRED_REPORTS = ("trivy.json",)

# Reports that are advisory: absence means the scanner found nothing or did not
# run in this environment, which is recorded but not fatal.
OPTIONAL_REPORTS = ("semgrep.json", "gitleaks.json")


class MergeError(RuntimeError):
    """Raised when required scanner output is missing or unusable."""


def load_report(path: str) -> List[Dict[str, Any]]:
    """Read one scanner report and flatten it into a list of findings."""
    # utf-8-sig transparently strips a byte-order mark. Scanner output piped
    # through a Windows shell can carry one, and a BOM makes json.load raise
    # before the pipeline ever gets to judge the findings.
    with open(path, "r", encoding="utf-8-sig") as handle:
        payload = json.load(handle)

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        # Trivy wraps results in Results[].Target.
        if "Results" in payload:
            findings: List[Dict[str, Any]] = []
            for result in payload.get("Results") or []:
                target = result.get("Target", "unknown")
                for vulnerability in result.get("Vulnerabilities") or []:
                    findings.append({
                        "id": vulnerability.get("VulnerabilityID")
                               or vulnerability.get("PkgName"),
                        "kind": "sca",
                        "title": vulnerability.get("Title")
                                 or vulnerability.get("Description", ""),
                        "severity": vulnerability.get("Severity", "UNKNOWN"),
                        "location": target,
                        "cvss": _trivy_cvss(vulnerability),
                        "epss": 0.0,
                        "kev": False,
                        "reachable": False,
                    })
            return findings

        for key in ("results", "findings"):
            if key in payload:
                return [item for item in payload[key] if isinstance(item, dict)]

    raise MergeError(f"{os.path.basename(path)}: unrecognised report structure")


def _trivy_cvss(vulnerability: Dict[str, Any]) -> float:
    """Pull a numeric CVSS out of Trivy's per-source score map."""
    cvss = vulnerability.get("CVSS") or {}
    for vendor in ("nvd", "redhat", "ghsa"):
        score = (cvss.get(vendor) or {}).get("V3Score")
        if isinstance(score, (int, float)):
            return float(score)
    return 0.0


def collect(scanner_dir: str = SCANNER_DIR) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []

    for name in REQUIRED_REPORTS:
        path = os.path.join(scanner_dir, name)
        if not os.path.isfile(path):
            raise MergeError(
                f"required scanner report missing: {name}. Refusing to treat an "
                f"absent scan as a clean result."
            )
        if os.path.getsize(path) == 0:
            raise MergeError(
                f"required scanner report is empty: {name}. The scanner most "
                f"likely failed; resolve that before promoting anything."
            )
        merged.extend(load_report(path))

    for name in OPTIONAL_REPORTS:
        path = os.path.join(scanner_dir, name)
        if not os.path.isfile(path):
            print(f"[WARN] optional report absent, continuing: {name}",
                  file=sys.stderr)
            continue
        merged.extend(load_report(path))

    return merged


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Merge scanner output into one findings file.",
    )
    parser.add_argument("--scanner-dir", default=SCANNER_DIR)
    parser.add_argument(
        "--out",
        default=os.path.join(SCANNER_DIR, "merged_findings.json"),
    )
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="permit zero findings (only valid for an intentionally empty repo)",
    )
    args = parser.parse_args(argv)

    try:
        findings = collect(args.scanner_dir)
    except (MergeError, json.JSONDecodeError, OSError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1

    if not findings and not args.allow_empty:
        print("[ERROR] Scanners produced no findings at all. That is more "
              "likely a misconfigured pipeline than a clean repository.",
              file=sys.stderr)
        return 1

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump({"results": findings}, handle, indent=2)
        handle.write("\n")

    print(f"MERGED: {len(findings)} finding(s) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())