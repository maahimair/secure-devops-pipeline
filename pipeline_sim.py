#!/usr/bin/env python3
# pipeline_sim.py
# VerifierGate — simulated pipeline scenarios.
#
# Builds each documented scenario under runs/, executes gate.py against it as a
# real subprocess, and records the observed exit code next to the expected one.
#
# These are SIMULATED validation cases. Nothing here touches a live system, a
# real network, or real credentials: every artifact, digest and CVE below is
# fabricated or drawn from documentation ranges.
#
# Usage:
#   python pipeline_sim.py                 # run every scenario
#   python pipeline_sim.py --list          # list scenario names
#   python pipeline_sim.py --only hardened_secret
#
# Exit code: 0 when every scenario matched its expected decision, else 1.

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
RUNS_DIR = os.path.join(REPO_ROOT, "runs")
GATE = os.path.join(REPO_ROOT, "gate.py")

# Provenance is stamped relative to the wall clock, because gate.py compares
# freshness against time.time(). Two hours old keeps every scenario inside the
# 24-hour window used below while still exercising the freshness check.
PROVENANCE_AGE_SECONDS = 7200

# ─── Finding fixtures ─────────────────────────────────────────────────────────

KEV_CVE = {
    "id": "CVE-2023-44487",
    "kind": "sca",
    "title": "HTTP/2 rapid reset request smuggling",
    "severity": "HIGH",
    "location": "requirements.txt",
    "cvss": 7.5,
    "epss": 0.94,
    "kev": True,
    "reachable": True,
}

LOW_RISK_CVE = {
    "id": "CVE-2024-1234",
    "kind": "sca",
    "title": "Minor issue in a non-reachable helper module",
    "severity": "MEDIUM",
    "location": "src/helpers.py",
    "cvss": 5.3,
    "epss": 0.01,
    "kev": False,
    "reachable": False,
}

FAINT_CVE = {
    "id": "CVE-2022-0001",
    "kind": "sca",
    "title": "Legacy library issue with no observed exploitation",
    "severity": "LOW",
    "location": "src/legacy.py",
    "cvss": 3.1,
    "epss": 0.001,
    "kev": False,
    "reachable": False,
}

FAKE_SECRET = {
    # Obviously fake, drawn from the AWS documentation example key space.
    "id": "gitleaks:aws-access-key-id",
    "kind": "secret",
    "title": "Hardcoded AWS access key ID in deployment script",
    "severity": "CRITICAL",
    "location": "deploy/release.sh",
    "cvss": 0.0,
    "epss": 0.0,
    "kev": False,
    "reachable": True,
}

SAST_FINDING = {
    "id": "semgrep:python.lang.security.audit.eval-detected",
    "kind": "sast",
    "title": "Use of eval() on user-controlled input",
    "severity": "WARNING",
    "location": "app/parser.py:88",
    "cvss": 6.0,
    "epss": 0.10,
    "kev": False,
    "reachable": False,
}

# ─── Policy fixtures ──────────────────────────────────────────────────────────

BASELINE_POLICY = {
    "max_risk_score": 40,
    "block_known_exploited": True,
    "block_secrets": False,
}

HARDENED_POLICY = {
    "max_risk_score": 25,
    "block_known_exploited": True,
    "block_secrets": True,
}

# ─── Scenario definitions ─────────────────────────────────────────────────────

SCENARIOS = [
    {
        "name": "normal_kev_dep",
        "description": "Baseline pipeline, known-exploited dependency present.",
        "findings": [KEV_CVE, LOW_RISK_CVE],
        "policy": BASELINE_POLICY,
        "tamper_artifact": False,
        "source_digest": None,
        "expected_exit": 2,
    },
    {
        "name": "normal_artifact_swap",
        "description": "Baseline pipeline, artifact modified after it was assessed.",
        "findings": [LOW_RISK_CVE, FAINT_CVE],
        "policy": BASELINE_POLICY,
        "tamper_artifact": True,
        "source_digest": None,
        "expected_exit": 2,
    },
    {
        "name": "hardened_kev_dep",
        "description": "Hardened pipeline, known-exploited dependency present.",
        "findings": [KEV_CVE],
        "policy": HARDENED_POLICY,
        "tamper_artifact": False,
        "source_digest": True,
        "expected_exit": 2,
    },
    {
        "name": "hardened_artifact_swap",
        "description": "Hardened pipeline, artifact swapped after assessment.",
        "findings": [LOW_RISK_CVE],
        "policy": HARDENED_POLICY,
        "tamper_artifact": True,
        "source_digest": True,
        "expected_exit": 2,
    },
    {
        "name": "hardened_secret",
        "description": "Hardened pipeline, secret material exposed in source.",
        "findings": [FAKE_SECRET, LOW_RISK_CVE],
        "policy": HARDENED_POLICY,
        "tamper_artifact": False,
        "source_digest": True,
        "expected_exit": 2,
    },
    {
        # Risk = 0.40*(6.0/10) + 0.30*0.10 = 27.0, which exceeds the hardened
        # threshold of 25. Reachability is what lifts it over the line, so this
        # demonstrates the threshold reacting to exploitability rather than to
        # the scanner's severity label alone.
        "name": "hardened_sast_reachable",
        "description": "Hardened pipeline, reachable SAST finding exceeds the threshold.",
        "findings": [LOW_RISK_CVE, SAST_FINDING],
        "policy": HARDENED_POLICY,
        "tamper_artifact": False,
        "source_digest": True,
        "expected_exit": 2,
    },
    {
        # Same scanner severity band, but unreachable: risk drops to 12.0 and
        # the hardened policy accepts it. Proves the gate discriminates on
        # reachability instead of blocking every SAST hit.
        "name": "hardened_sast_unreachable",
        "description": "Hardened pipeline, unreachable SAST finding is accepted.",
        "findings": [LOW_RISK_CVE, dict(SAST_FINDING, reachable=False, cvss=3.0)],
        "policy": HARDENED_POLICY,
        "tamper_artifact": False,
        "source_digest": True,
        "expected_exit": 0,
    },
    {
        "name": "hardened_none",
        "description": "Hardened pipeline, no simulated attack, clean promotion.",
        "findings": [FAINT_CVE],
        "policy": HARDENED_POLICY,
        "tamper_artifact": False,
        "source_digest": True,
        "expected_exit": 0,
    },
]


# ─── Scenario construction ────────────────────────────────────────────────────

def build_scenario(scenario: dict, target_dir: str) -> dict:
    """Materialise a scenario directory and return its gate.py arguments."""
    os.makedirs(target_dir, exist_ok=True)

    findings_path = os.path.join(target_dir, "findings.json")
    with open(findings_path, "w", encoding="utf-8") as handle:
        json.dump(scenario["findings"], handle, indent=2)
        handle.write("\n")

    policy_path = os.path.join(target_dir, "policy.json")
    with open(policy_path, "w", encoding="utf-8") as handle:
        json.dump(scenario["policy"], handle, indent=2)
        handle.write("\n")

    # A deterministic fake artifact, so digests are reproducible run to run.
    artifact_path = os.path.join(target_dir, "app.tar")
    payload = f"verifiergate-demo-build::{scenario['name']}".encode("utf-8")
    with open(artifact_path, "wb") as handle:
        handle.write(payload)

    # Imported lazily so the module can still print --list without side effects.
    import provenance

    genuine_hash = provenance.sha256_file(artifact_path)
    source_digest = provenance.sha256_bytes(scenario["name"].encode("utf-8"))

    provenance_path = os.path.join(target_dir, "provenance.json")
    with open(provenance_path, "w", encoding="utf-8") as handle:
        json.dump({
            "subject_hash": genuine_hash,
            "source_digest": source_digest,
            "generated_at": time.time() - PROVENANCE_AGE_SECONDS,
            "builder": "simulated",
            "note": "Synthetic attestation for validation only.",
        }, handle, indent=2)
        handle.write("\n")

    if scenario["tamper_artifact"]:
        # Swap the artifact after the attestation was recorded.
        with open(artifact_path, "wb") as handle:
            handle.write(b"TAMPERED-ARTIFACT-NOT-THE-ASSESSED-BUILD")

    argv = [
        sys.executable, GATE, "all",
        "--findings", findings_path,
        "--policy", policy_path,
        "--artifact", artifact_path,
        "--provenance", provenance_path,
        "--freshness", "86400",
        "--ledger", os.path.join(target_dir, "ledger.jsonl"),
    ]

    # Only the hardened scenarios bind the artifact to a specific source
    # revision, so only they supply the expected source digest.
    if scenario.get("source_digest"):
        argv += ["--source-digest", source_digest]

    return {"argv": argv, "dir": target_dir}


# ─── Execution ────────────────────────────────────────────────────────────────

def run_scenario(scenario: dict, clean: bool = True) -> dict:
    target_dir = os.path.join(RUNS_DIR, scenario["name"])
    if clean and os.path.isdir(target_dir):
        shutil.rmtree(target_dir)

    built = build_scenario(scenario, target_dir)

    completed = subprocess.run(
        built["argv"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    observed = completed.returncode
    passed = observed == scenario["expected_exit"]

    with open(os.path.join(target_dir, "gate_output.txt"), "w",
              encoding="utf-8") as handle:
        handle.write(completed.stdout)
        if completed.stderr:
            handle.write("\n--- stderr ---\n")
            handle.write(completed.stderr)

    return {
        "name": scenario["name"],
        "description": scenario["description"],
        "expected_exit": scenario["expected_exit"],
        "observed_exit": observed,
        "decision": "PROMOTE" if observed == 0 else "BLOCK",
        "passed": passed,
        "output": completed.stdout,
        "dir": target_dir,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run VerifierGate simulated pipeline scenarios.",
    )
    parser.add_argument("--only", help="run a single scenario by name")
    parser.add_argument("--list", action="store_true", help="list scenario names")
    parser.add_argument(
        "--no-clean", action="store_true",
        help="keep any existing scenario directory instead of rebuilding it",
    )
    args = parser.parse_args(argv)

    if args.list:
        for scenario in SCENARIOS:
            print(f"{scenario['name']:<24} expected exit {scenario['expected_exit']}"
                  f"  ({scenario['description']})")
        return 0

    selected = SCENARIOS
    if args.only:
        selected = [s for s in SCENARIOS if s["name"] == args.only]
        if not selected:
            print(f"Unknown scenario: {args.only}", file=sys.stderr)
            print(f"Available: {', '.join(s['name'] for s in SCENARIOS)}",
                  file=sys.stderr)
            return 1

    os.makedirs(RUNS_DIR, exist_ok=True)

    print("=" * 72)
    print("VerifierGate — simulated pipeline scenarios")
    print("=" * 72)

    results = []
    for scenario in selected:
        result = run_scenario(scenario, clean=not args.no_clean)
        results.append(result)

        mark = "PASS" if result["passed"] else "FAIL"
        print(f"\n[{mark}] {result['name']}")
        print(f"       {result['description']}")
        print(f"       expected exit {result['expected_exit']}, "
              f"observed {result['observed_exit']} -> {result['decision']}")
        print(f"       artifacts: {os.path.relpath(result['dir'], REPO_ROOT)}")

    summary_path = os.path.join(RUNS_DIR, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump([
            {key: value for key, value in result.items() if key != "output"}
            for result in results
        ], handle, indent=2)
        handle.write("\n")

    failed = [result for result in results if not result["passed"]]

    print()
    print("=" * 72)
    print(f"Scenarios: {len(results) - len(failed)}/{len(results)} matched "
          f"expected decisions")
    print(f"Summary written to {os.path.relpath(summary_path, REPO_ROOT)}")

    if failed:
        print("RESULT: FAIL")
        for result in failed:
            print(f"  - {result['name']}: expected "
                  f"{result['expected_exit']}, got {result['observed_exit']}")
        print("=" * 72)
        return 1

    print("RESULT: PASS")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())