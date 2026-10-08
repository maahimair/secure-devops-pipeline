# gate.py
# VerifierGate — Command-line security gate.
#
# Orchestrates the three stages and turns the result into a process exit code,
# which is what a CI runner actually reacts to:
#
#   exit 0  -> stage passed, artifact may be promoted
#   exit 2  -> BLOCKED, deployment must not proceed
#   exit 1  -> a stage could not run (bad input, missing file, internal error)
#
# Separating 2 from 1 matters: a broken pipeline should be retried or fixed,
# while a genuine security block should stop the release and be reviewed.
#
# Usage:
#   python gate.py score   --findings findings.json --out scored_findings.json
#   python gate.py check   --findings scored_findings.json --policy policy.json
#   python gate.py verify  --artifact app.tar --provenance provenance.json \
#                          --source-digest <sha256> --ledger ledger.jsonl
#   python gate.py all     --findings findings.json --policy policy.json \
#                          --artifact app.tar --provenance provenance.json \
#                          --source-digest <sha256> --ledger ledger.jsonl
#
# Standard library only.

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List

import correlate
import ledger
import policy as policy_module
import provenance as provenance_module

EXIT_ALLOW = 0
EXIT_ERROR = 1
EXIT_BLOCK = 2


def _log(message: str) -> None:
    print(message, flush=True)


# ─── Stages ───────────────────────────────────────────────────────────────────

def stage_score(findings_path: str, out_path: str | None) -> Dict[str, Any]:
    """Correlate raw scanner findings and write the scored result."""
    scored = correlate.load_findings(findings_path)
    summary = correlate.summarise(scored)

    _log(f"CORRELATE: {summary['total_findings']} finding(s) normalised")
    for finding in scored:
        flags = []
        if finding["kev"]:
            flags.append("KEV")
        if finding["reachable"]:
            flags.append("REACHABLE")
        suffix = f" [{', '.join(flags)}]" if flags else ""
        _log(
            f"  {finding['risk_score']:>5.1f}  {finding['id']} "
            f"({finding['kind']}){suffix}"
        )
    _log(
        f"RISK: max={summary['max_risk_score']} "
        f"mean={summary['mean_risk_score']}"
    )

    if out_path:
        correlate.dump_scored(scored, out_path)
        _log(f"WROTE: {out_path}")

    return {"scored": scored, "summary": summary}


def stage_check(findings_path: str, policy_path: str | None) -> Dict[str, Any]:
    """Apply the deployment policy to scored findings."""
    scored = correlate.load_findings(findings_path)
    loaded_policy = policy_module.load_policy(policy_path)
    result = policy_module.check_policy(scored, loaded_policy)

    _log(policy_module.format_decision(result))
    return result


def stage_verify(
    artifact_path: str,
    provenance_path: str,
    source_digest: str | None,
    freshness_seconds: int,
) -> Dict[str, Any]:
    """Verify artifact integrity and provenance freshness before promotion."""
    attestation = provenance_module.load_provenance(provenance_path)
    result = provenance_module.verify(
        artifact_path,
        attestation,
        expected_source_digest=source_digest,
        freshness_seconds=freshness_seconds,
    )

    _log(provenance_module.format_result(result))
    return result


def _record(ledger_path: str | None, event: str, decision: str, detail: str) -> None:
    """Append to the audit ledger, treating audit failure as non-fatal.

    Ledger integrity provides evidence for a human review; losing that evidence
    must not silently turn a BLOCKED decision into a pass.
    """
    if not ledger_path:
        return
    try:
        ledger.append_record(
            ledger_path,
            event=event,
            decision=decision,
            detail=detail,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
    except (OSError, ledger.LedgerError) as error:
        print(f"[WARN] Ledger append failed: {error}", file=sys.stderr)


# ─── Commands ─────────────────────────────────────────────────────────────────

def command_score(args) -> int:
    stage_score(args.findings, args.out)
    return EXIT_ALLOW


def command_check(args) -> int:
    result = stage_check(args.findings, args.policy)
    decision = result["decision"]
    _record(
        args.ledger,
        event="policy_check",
        decision=decision,
        detail="; ".join(v["detail"] for v in result["violations"]) or "no violations",
    )
    return EXIT_BLOCK if decision == policy_module.BLOCK else EXIT_ALLOW


def command_verify(args) -> int:
    result = stage_verify(
        args.artifact, args.provenance, args.source_digest, args.freshness
    )
    _record(
        args.ledger,
        event="provenance_verify",
        decision="PROMOTE" if result["verified"] else "BLOCK",
        detail=result.get("reason") or "all checks passed",
    )
    return EXIT_ALLOW if result["verified"] else EXIT_BLOCK


def command_all(args) -> int:
    """Run score -> check -> verify, stopping at the first block."""
    _log("=" * 60)
    _log("VerifierGate — full pipeline")
    _log("=" * 60)

    scored = stage_score(args.findings, args.out)
    _log("-" * 60)

    loaded_policy = policy_module.load_policy(args.policy)
    decision = policy_module.check_policy(scored["scored"], loaded_policy)
    _log(policy_module.format_decision(decision))

    _record(
        args.ledger,
        event="policy_check",
        decision=decision["decision"],
        detail="; ".join(v["detail"] for v in decision["violations"]) or "no violations",
    )

    if decision["decision"] == policy_module.BLOCK:
        _log("-" * 60)
        _log("DEPLOY BLOCKED by policy. Artifact was not verified or promoted.")
        return EXIT_BLOCK

    _log("-" * 60)

    result = stage_verify(
        args.artifact, args.provenance, args.source_digest, args.freshness
    )

    _record(
        args.ledger,
        event="provenance_verify",
        decision="PROMOTE" if result["verified"] else "BLOCK",
        detail=result.get("reason") or "all checks passed",
    )

    if not result["verified"]:
        _log("-" * 60)
        _log("DEPLOY BLOCKED by provenance verification.")
        return EXIT_BLOCK

    _log("-" * 60)
    _log("All stages passed — artifact cleared for promotion.")
    return EXIT_ALLOW


def command_ledger(args) -> int:
    """Verify the hash chain of an existing ledger."""
    result = ledger.verify_ledger(args.path)
    if args.describe:
        for line in ledger.describe_chain(args.path):
            _log(line)
    _log(f"LEDGER: {'INTACT' if result['verified'] else 'TAMPER DETECTED'}")
    _log(f"  {result['detail']}")
    return EXIT_ALLOW if result["verified"] else EXIT_BLOCK


# ─── Argument parsing ─────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gate.py",
        description="VerifierGate centralised deployment security gate.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(sub):
        sub.add_argument("--ledger", help="audit ledger JSONL path")

    score = subparsers.add_parser("score", help="normalise and score findings")
    score.add_argument("--findings", required=True, help="raw findings JSON")
    score.add_argument("--out", help="write scored findings here")
    score.set_defaults(func=command_score)

    check = subparsers.add_parser("check", help="apply the deployment policy")
    check.add_argument("--findings", required=True, help="scored findings JSON")
    check.add_argument("--policy", help="policy JSON (defaults to built-in rules)")
    add_common(check)
    check.set_defaults(func=command_check)

    verify = subparsers.add_parser("verify", help="verify artifact provenance")
    verify.add_argument("--artifact", required=True, help="artifact to promote")
    verify.add_argument("--provenance", required=True, help="provenance JSON")
    verify.add_argument("--source-digest", help="expected source SHA-256")
    verify.add_argument(
        "--freshness", type=int, default=provenance_module.DEFAULT_FRESHNESS_SECONDS,
        help="provenance freshness window in seconds",
    )
    add_common(verify)
    verify.set_defaults(func=command_verify)

    run_all = subparsers.add_parser("all", help="run score, check and verify")
    run_all.add_argument("--findings", required=True)
    run_all.add_argument("--policy")
    run_all.add_argument("--out", help="write scored findings here")
    run_all.add_argument("--artifact")
    run_all.add_argument("--provenance")
    run_all.add_argument("--source-digest")
    run_all.add_argument(
        "--freshness", type=int, default=provenance_module.DEFAULT_FRESHNESS_SECONDS
    )
    add_common(run_all)
    run_all.set_defaults(func=command_all)

    ledger_cmd = subparsers.add_parser("ledger", help="verify the audit ledger")
    ledger_cmd.add_argument("path", help="ledger JSONL path")
    ledger_cmd.add_argument(
        "--describe", action="store_true", help="print one line per record"
    )
    ledger_cmd.set_defaults(func=command_ledger)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except (
        correlate.CorrelationError,
        policy_module.PolicyError,
        provenance_module.ProvenanceError,
        ledger.LedgerError,
    ) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError as error:
        print(f"[ERROR] File not found: {error.filename}", file=sys.stderr)
        return EXIT_ERROR
    except json.JSONDecodeError as error:
        print(f"[ERROR] Malformed JSON at line {error.lineno}: {error.msg}",
              file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())