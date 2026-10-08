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

    name = os.path.basename(path)

    if "gitleaks" in name:
        # Gitleaks writes a bare list of leak objects.
        if not isinstance(payload, list):
            raise MergeError(f"{name}: expected a JSON list of gitleaks findings")
        return _gitleaks_findings(payload)

    if "trivy" in name:
        if not isinstance(payload, dict):
            raise MergeError(f"{name}: expected a JSON object")
        return _trivy_findings(payload)

    if "semgrep" in name:
        if not isinstance(payload, dict):
            raise MergeError(f"{name}: expected a JSON object")
        return _semgrep_findings(payload)

    # Unrecognised filename: fall back to structural detection.
    return _sniff_report(name, payload)


def _sniff_report(name: str, payload: Any) -> List[Dict[str, Any]]:
    """Best-effort parse for a report whose filename is not recognised."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        if "Results" in payload:
            return _trivy_findings(payload)
        for key in ("results", "findings"):
            if key in payload:
                return [item for item in payload[key] if isinstance(item, dict)]

    raise MergeError(f"{name}: unrecognised report structure")


def _trivy_findings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Flatten Trivy output.

    Trivy OMITS the `Results` key entirely when it finds nothing, rather than
    emitting an empty list. Treating that as an unrecognised structure would
    fail the whole pipeline on a clean repository, so an absent Results key
    means zero findings.
    """
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

        # Trivy can also run its own secret scanner, which reports under a
        # different key inside the same Result object.
        for secret in result.get("Secrets") or []:
            findings.append({
                "id": f"trivy:{secret.get('RuleID', 'secret')}",
                "kind": "secret",
                "title": secret.get("Title", "Secret detected by Trivy"),
                "severity": secret.get("Severity", "CRITICAL"),
                "location": target,
                "cvss": 0.0,
                "epss": 0.0,
                "kev": False,
                "reachable": True,
            })

    return findings


def _semgrep_findings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Flatten Semgrep output.

    Semgrep puts the human message and severity under `extra`, and reports the
    file under `path`. Both are lifted into the common shape so the policy
    engine sees a real severity and a usable location.
    """
    findings: List[Dict[str, Any]] = []

    for entry in payload.get("results") or []:
        if not isinstance(entry, dict):
            continue

        extra = entry.get("extra") or {}
        path = str(entry.get("path") or "unknown")
        start = (entry.get("start") or {}).get("line")
        location = f"{path}:{start}" if start else path

        findings.append({
            "id": str(entry.get("check_id") or "semgrep:unknown-rule"),
            "kind": "sast",
            "title": str(extra.get("message") or entry.get("check_id") or ""),
            "severity": str(extra.get("severity") or "UNKNOWN"),
            "location": location,
            # Semgrep does not publish CVSS or EPSS. Default to non-reachable
            # and unexploited so SAST findings must clear the threshold on
            # CVSS alone rather than inheriting a fabricated exploitability.
            "cvss": 0.0,
            "epss": 0.0,
            "kev": False,
            "reachable": False,
        })

    return findings


def _trivy_cvss(vulnerability: Dict[str, Any]) -> float:
    """Pull a numeric CVSS out of Trivy's per-source score map."""
    cvss = vulnerability.get("CVSS") or {}
    for vendor in ("nvd", "redhat", "ghsa"):
        score = (cvss.get(vendor) or {}).get("V3Score")
        if isinstance(score, (int, float)):
            return float(score)
    return 0.0


def _gitleaks_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Map Gitleaks output onto the common representation.

    Gitleaks emits a different schema from Semgrep and Trivy: CamelCase keys,
    a `Secret` field rather than a vulnerability id, and no CVSS or EPSS score.
    Exposed secrets are treated as maximally severe with a reachable code path,
    because a leaked credential is exploitable the moment it is committed.
    """
    mapped: List[Dict[str, Any]] = []

    for entry in report:
        if not isinstance(entry, dict):
            continue

        rule_id = str(entry.get("RuleID") or "gitleaks:unknown-rule")
        file_path = str(entry.get("File") or "unknown")
        line = entry.get("StartLine")
        location = f"{file_path}:{line}" if line else file_path

        # Never carry the secret value itself forward. --redact blanks it, but
        # a local run without --redact would otherwise copy live credentials
        # into merged_findings.json and then into a CI artifact.
        description = str(entry.get("Description") or rule_id)

        mapped.append({
            "id": rule_id,
            "kind": "secret",
            "title": description,
            "severity": "CRITICAL",
            "location": location,
            "cvss": 0.0,
            "epss": 0.0,
            "kev": False,
            "reachable": True,
        })

    return mapped


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