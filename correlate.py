# correlate.py
# VerifierGate — Finding correlation and risk scoring.
#
# Normalises findings from several scanners (Semgrep, Trivy, Gitleaks, ...) into
# one common representation and reduces them to a single exploitability-weighted
# risk score. No scanner severity value is trusted on its own: CVSS alone misses
# that a CVE is already being exploited in the wild, and an EPSS of 0.94 says
# far more than a "high" label from any single tool.
#
# Standard library only.

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List

# ─── Risk model ───────────────────────────────────────────────────────────────
# Weights sum to 1.0 so the resulting score stays on a 0-100 scale.
#
#   Risk = (0.40 x CVSS/10 + 0.30 x EPSS + 0.20 x KEV + 0.10 x Reachable) x 100
#
# Rationale:
#   CVSS      — intrinsic technical severity, normalised from 0-10 to 0-1.
#   EPSS      — observed exploitation probability in the wild, already 0-1.
#   KEV       — binary: listed in CISA's Known Exploited Vulnerabilities.
#   Reachable — binary: the vulnerable code path is actually reachable.
WEIGHTS: Dict[str, float] = {
    "cvss": 0.40,
    "epss": 0.30,
    "kev": 0.20,
    "reachable": 0.10,
}

FINDING_KINDS = ("sast", "sca", "secret")


class CorrelationError(ValueError):
    """Raised when input findings cannot be interpreted safely."""


# ─── Normalisation ────────────────────────────────────────────────────────────

def _as_bool(value: Any) -> bool:
    """Coerce a scanner's assorted truthy spellings into a strict bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1", "y")
    return False


def _as_float(value: Any, field: str, low: float, high: float) -> float:
    """Read a numeric field and clamp it, rejecting anything unparseable."""
    if value is None:
        return low
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise CorrelationError(f"{field} must be numeric, got {value!r}") from exc
    if number != number:  # NaN
        raise CorrelationError(f"{field} must be a real number, got NaN")
    return max(low, min(high, number))


def calculate_risk(cvss: float, epss: float, kev: bool, reachable: bool) -> float:
    """Compute the VerifierGate risk score for a single finding (0-100)."""
    normalised_cvss = max(0.0, min(10.0, float(cvss))) / 10.0
    normalised_epss = max(0.0, min(1.0, float(epss)))

    weighted = (
        WEIGHTS["cvss"] * normalised_cvss
        + WEIGHTS["epss"] * normalised_epss
        + WEIGHTS["kev"] * (1.0 if kev else 0.0)
        + WEIGHTS["reachable"] * (1.0 if reachable else 0.0)
    )
    return round(weighted * 100.0, 1)


def normalise_finding(finding: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
    """
    Convert one raw scanner finding into the common VerifierGate shape.

    Accepts the field aliases the supported scanners actually emit, so callers do
    not have to reshape Semgrep and Trivy output by hand.
    """
    if not isinstance(finding, dict):
        raise CorrelationError(f"finding #{index} must be an object, got {type(finding).__name__}")

    kind = str(finding.get("kind") or finding.get("type") or "sca").strip().lower()
    if kind not in FINDING_KINDS:
        raise CorrelationError(
            f"finding #{index}: unknown kind {kind!r} (expected one of {', '.join(FINDING_KINDS)})"
        )

    identifier = (
        finding.get("id")
        or finding.get("cve")
        or finding.get("rule_id")
        or finding.get("check_id")
        or f"{kind.upper()}-UNIDENTIFIED-{index}"
    )

    severity_raw = str(finding.get("severity") or finding.get("impact") or "UNKNOWN").strip()

    return {
        "id": str(identifier),
        "kind": kind,
        "title": str(finding.get("title") or finding.get("description") or identifier),
        "severity": severity_raw,
        "location": str(finding.get("location") or finding.get("target") or "unknown"),
        "cvss": _as_float(
            finding.get("cvss", finding.get("cvss_score")),
            f"{identifier}.cvss", 0.0, 10.0,
        ),
        "epss": _as_float(finding.get("epss"), f"{identifier}.epss", 0.0, 1.0),
        "kev": _as_bool(finding.get("kev", finding.get("known_exploited"))),
        "reachable": _as_bool(finding.get("reachable")),
    }


# ─── Correlation ──────────────────────────────────────────────────────────────

def correlate(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalise every finding and attach its calculated risk score.

    Returned findings are sorted highest-risk first so a reviewer or a policy
    engine reads the most dangerous item at the top.
    """
    if isinstance(findings, dict):
        # Tolerate a scanner that emits {"results": [...]}.
        findings = findings.get("results", findings.get("findings", []))

    scored: List[Dict[str, Any]] = []
    for position, raw in enumerate(findings or []):
        normalised = normalise_finding(raw, position)
        normalised["risk_score"] = calculate_risk(
            normalised["cvss"],
            normalised["epss"],
            normalised["kev"],
            normalised["reachable"],
        )
        scored.append(normalised)

    scored.sort(key=lambda item: item["risk_score"], reverse=True)
    return scored


def load_findings(path: str) -> List[Dict[str, Any]]:
    """Read findings from a JSON file containing a list or a results object."""
    with open(path, "r", encoding="utf-8") as handle:
        return correlate(json.load(handle))


def dump_scored(scored: Iterable[Dict[str, Any]], path: str) -> None:
    """Write scored findings back out as JSON."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(list(scored), handle, indent=2)
        handle.write("\n")


def summarise(scored: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate view used for reporting and for the pipeline summary."""
    findings = list(scored)
    kev_ids = [f["id"] for f in findings if f["kev"]]
    secret_ids = [f["id"] for f in findings if f["kind"] == "secret"]
    scores = [f["risk_score"] for f in findings]

    return {
        "total_findings": len(findings),
        "max_risk_score": max(scores) if scores else 0.0,
        "mean_risk_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
        "known_exploited": kev_ids,
        "secrets": secret_ids,
        "blocked_by_default_rule": bool(kev_ids or secret_ids),
    }