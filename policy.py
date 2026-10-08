# policy.py
# VerifierGate — Policy-as-code evaluation.
#
# Turns scored findings into an explicit deployment decision. The policy is data
# (a JSON document), not code, so the rules a team enforces are reviewable in a
# pull request and can change without a code deploy.
#
# A finding is blocked when ANY enabled rule matches. Rules are evaluated in a
# fixed order and every violation is reported, so an operator sees the full
# picture rather than only the first reason a build stopped.
#
# Standard library only.

from __future__ import annotations

import json
from typing import Any, Dict, List

DEFAULT_POLICY: Dict[str, Any] = {
    "max_risk_score": 40,
    "block_known_exploited": True,
    "block_secrets": True,
}

BLOCK = "BLOCK"
ALLOW = "ALLOW"


class PolicyError(ValueError):
    """Raised when a policy document is malformed."""


def load_policy(path: str | None = None) -> Dict[str, Any]:
    """
    Load a policy document, falling back to the documented defaults.

    Unknown keys are rejected rather than ignored: a typo like
    "block_known_exploits" would otherwise silently disable a rule.
    """
    if path is None:
        return dict(DEFAULT_POLICY)

    with open(path, "r", encoding="utf-8") as handle:
        policy = json.load(handle)

    if not isinstance(policy, dict):
        raise PolicyError("policy document must be a JSON object")

    unknown = set(policy) - set(DEFAULT_POLICY)
    if unknown:
        raise PolicyError(
            f"unknown policy key(s): {', '.join(sorted(unknown))}; "
            f"expected any of {', '.join(sorted(DEFAULT_POLICY))}"
        )

    merged = dict(DEFAULT_POLICY)
    merged.update(policy)

    threshold = merged["max_risk_score"]
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise PolicyError("max_risk_score must be a number")
    if not 0 <= float(threshold) <= 100:
        raise PolicyError("max_risk_score must be between 0 and 100")

    for flag in ("block_known_exploited", "block_secrets"):
        if not isinstance(merged[flag], bool):
            raise PolicyError(f"{flag} must be true or false")

    return merged


def check_policy(scored: List[Dict[str, Any]], policy: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate scored findings against the policy.

    Returns a decision document containing the verdict plus every violation, so
    a blocked build can explain itself.
    """
    violations: List[Dict[str, Any]] = []
    threshold = float(policy.get("max_risk_score", DEFAULT_POLICY["max_risk_score"]))

    for finding in scored:
        risk = float(finding.get("risk_score", 0.0))

        if risk > threshold:
            violations.append({
                "rule": "max_risk_score",
                "id": finding.get("id"),
                "severity": "critical",
                "detail": (
                    f"Risk {risk} exceeds the maximum allowed score of {threshold:g}"
                ),
            })

        if policy.get("block_known_exploited") and finding.get("kev"):
            violations.append({
                "rule": "block_known_exploited",
                "id": finding.get("id"),
                "severity": "critical",
                "detail": (
                    "Finding is listed as known-exploited (CISA KEV)"
                ),
            })

        if (
            policy.get("block_secrets")
            and finding.get("kind") == "secret"
        ):
            violations.append({
                "rule": "block_secrets",
                "id": finding.get("id"),
                "severity": "critical",
                "detail": "Secret material detected in the source tree",
            })

    return {
        "decision": BLOCK if violations else ALLOW,
        "violations": violations,
        "policy": {
            "max_risk_score": threshold,
            "block_known_exploited": bool(policy.get("block_known_exploited")),
            "block_secrets": bool(policy.get("block_secrets")),
        },
        "evaluated_findings": len(scored),
    }


def format_decision(result: Dict[str, Any]) -> str:
    """Render a decision document as a human-readable multi-line summary."""
    lines = [f"DECISION: {result['decision']}"]

    if result["violations"]:
        lines.append(f"VIOLATIONS ({len(result['violations'])}):")
        for violation in result["violations"]:
            lines.append(
                f"  - [{violation['rule']}] {violation['id']}: {violation['detail']}"
            )
    else:
        lines.append(
            f"No policy violations across {result['evaluated_findings']} finding(s)."
        )

    return "\n".join(lines)