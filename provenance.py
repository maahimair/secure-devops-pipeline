# provenance.py
# VerifierGate — Artifact provenance verification.
#
# Scanners prove the *source* was scanned. They say nothing about whether the
# artifact about to be promoted is the one that was actually assessed. This
# module closes that gap by re-deriving three properties of the artifact at
# promotion time and comparing them against the recorded attestation:
#
#   1. Artifact integrity  — SHA-256 of the file must match the recorded digest.
#   2. Source identity     — recorded source digest must match the expected one.
#   3. Freshness           — the attestation must be inside the freshness window,
#                            so a stale approval cannot be replayed later.
#
# A failure here is a deployment block, not a warning.
#
# Standard library only.

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict

VERIFIED = "VERIFIED"
BLOCKED = "BLOCKED"

# Reasons a promotion is refused, reported as stable machine-readable codes.
ARTIFACT_SWAP = "ARTIFACT SWAP DETECTED"
SOURCE_MISMATCH = "SOURCE MISMATCH"
STALE_PROVENANCE = "STALE PROVENANCE"
MISSING_ARTIFACT = "MISSING ARTIFACT"

DEFAULT_FRESHNESS_SECONDS = 3600


class ProvenanceError(ValueError):
    """Raised when a provenance document is malformed."""


def sha256_file(path: str, chunk_size: int = 65536) -> str:
    """Stream a SHA-256 digest so large artifacts do not need to be held in RAM."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def load_provenance(path: str) -> Dict[str, Any]:
    """Read and validate a provenance attestation document."""
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)

    if not isinstance(document, dict):
        raise ProvenanceError("provenance document must be a JSON object")

    for required in ("subject_hash", "source_digest", "generated_at"):
        if required not in document:
            raise ProvenanceError(f"provenance document missing '{required}'")

    return document


def verify(
    artifact_path: str,
    provenance: Dict[str, Any],
    expected_source_digest: str | None = None,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    now: float | None = None,
) -> Dict[str, Any]:
    """
    Verify an artifact against its attestation.

    Returns a result document. `verified` is the single value a caller should
    branch on; the remaining fields explain the outcome.
    """
    checks: list[Dict[str, Any]] = []

    # ── 1. Artifact present ──────────────────────────────────────────────────
    if not os.path.isfile(artifact_path):
        return {
            "verified": False,
            "result": BLOCKED,
            "reason": MISSING_ARTIFACT,
            "detail": f"Artifact not found: {artifact_path}",
            "checks": [],
        }

    actual_hash = sha256_file(artifact_path)
    expected_hash = str(provenance.get("subject_hash", "")).lower()

    artifact_ok = bool(expected_hash) and actual_hash == expected_hash
    checks.append({
        "check": "artifact_sha256",
        "passed": artifact_ok,
        "expected": expected_hash or "<absent>",
        "actual": actual_hash,
    })

    # ── 2. Source identity ───────────────────────────────────────────────────
    recorded_source = str(provenance.get("source_digest", "")).lower()
    expected_source = (expected_source_digest or "").lower()

    if expected_source:
        source_ok = bool(recorded_source) and recorded_source == expected_source
        checks.append({
            "check": "source_digest",
            "passed": source_ok,
            "expected": expected_source,
            "actual": recorded_source or "<absent>",
        })
    else:
        source_ok = True
        checks.append({
            "check": "source_digest",
            "passed": True,
            "expected": "<not supplied>",
            "actual": recorded_source or "<absent>",
            "skipped": True,
        })

    # ── 3. Freshness ─────────────────────────────────────────────────────────
    current_time = time.time() if now is None else now
    try:
        generated_at = float(provenance.get("generated_at"))
    except (TypeError, ValueError):
        generated_at = 0.0

    age_seconds = current_time - generated_at
    # A timestamp in the future means the clock or the attestation is wrong;
    # treat a negative age as stale rather than trusting it.
    freshness_ok = 0 <= age_seconds <= freshness_seconds
    checks.append({
        "check": "freshness",
        "passed": freshness_ok,
        "expected": f"age <= {freshness_seconds}s",
        "actual": f"age = {age_seconds:.0f}s",
    })

    # ── Verdict ──────────────────────────────────────────────────────────────
    if not artifact_ok:
        reason, detail = ARTIFACT_SWAP, (
            "Artifact SHA-256 does not match the attested subject hash. "
            "The file about to be promoted is not the file that was assessed."
        )
    elif not source_ok:
        reason, detail = SOURCE_MISMATCH, (
            "Recorded source digest does not match the expected source digest."
        )
    elif not freshness_ok:
        reason, detail = STALE_PROVENANCE, (
            f"Provenance is {age_seconds:.0f}s old, outside the "
            f"{freshness_seconds}s freshness window."
        )
    else:
        reason, detail = None, "All provenance checks passed."

    return {
        "verified": reason is None,
        "result": VERIFIED if reason is None else BLOCKED,
        "reason": reason,
        "detail": detail,
        "artifact_sha256": actual_hash,
        "checks": checks,
    }


def format_result(result: Dict[str, Any]) -> str:
    """Render a provenance result as a human-readable multi-line summary."""
    lines = [f"PROVENANCE: {result['result']}"]
    if result.get("reason"):
        lines.append(f"REASON: {result['reason']}")
        lines.append(f"DETAIL: {result['detail']}")
    for check in result.get("checks", []):
        mark = "PASS" if check["passed"] else "FAIL"
        suffix = " (skipped)" if check.get("skipped") else ""
        lines.append(f"  [{mark}] {check['check']}{suffix}: {check['actual']}")
    return "\n".join(lines)