# tests/test_gate.py
# VerifierGate — core security control validation.
#
# Each test asserts on the gate's process exit code rather than on internal
# state, because the exit code is the contract the CI runner actually depends on.
#
# Runs under pytest and under the bundled stdlib runner (tests/run_tests.py).

import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import correlate                      # noqa: E402
import gate                           # noqa: E402
import ledger as ledger_module        # noqa: E402
import policy as policy_module        # noqa: E402
import provenance as provenance_module  # noqa: E402

EXIT_ALLOW = gate.EXIT_ALLOW
EXIT_BLOCK = gate.EXIT_BLOCK


# ─── Fixtures ─────────────────────────────────────────────────────────────────

# CVE-2023-44487 is the documented attack case: HTTP/2 Rapid Reset, actively
# exploited, and reachable. Calculated risk = 88.2.
KEV_FINDING = {
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

# A low-risk, unexploited, unreachable finding. Calculated risk = 21.5.
CLEAN_FINDING = {
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


class GateTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def write_json(self, name, payload):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        return path

    def make_artifact(self, content=b"verifiergate-demo-artifact"):
        path = os.path.join(self.tmp, "app.tar")
        with open(path, "wb") as handle:
            handle.write(content)
        return path


# ─── The four documented controls ─────────────────────────────────────────────

class TestCoreControls(GateTestCase):

    def test_kev_blocked(self):
        """Known-exploited, reachable finding above the threshold is rejected (exit 2)."""
        findings_path = self.write_json("findings.json", [KEV_FINDING])

        scored = correlate.load_findings(findings_path)
        self.assertEqual(scored[0]["risk_score"], 88.2,
                         "documented risk score for CVE-2023-44487")

        policy = policy_module.load_policy(None)
        result = policy_module.check_policy(scored, policy)

        self.assertEqual(result["decision"], policy_module.BLOCK)

        rules = {violation["rule"] for violation in result["violations"]}
        self.assertIn("max_risk_score", rules)
        self.assertIn("block_known_exploited", rules)

        # The CLI must surface the block as exit code 2.
        scored_path = os.path.join(self.tmp, "scored.json")
        correlate.dump_scored(scored, scored_path)
        exit_code = gate.main([
            "check", "--findings", scored_path, "--ledger",
            os.path.join(self.tmp, "ledger.jsonl"),
        ])
        self.assertEqual(exit_code, EXIT_BLOCK)

    def test_clean_allowed(self):
        """Low-risk finding within policy is accepted (exit 0)."""
        findings_path = self.write_json("findings.json", [CLEAN_FINDING])

        scored = correlate.load_findings(findings_path)
        self.assertEqual(scored[0]["risk_score"], 21.5)

        result = policy_module.check_policy(
            scored, policy_module.load_policy(None)
        )
        self.assertEqual(result["decision"], policy_module.ALLOW)
        self.assertEqual(result["violations"], [])

        scored_path = os.path.join(self.tmp, "scored.json")
        correlate.dump_scored(scored, scored_path)
        exit_code = gate.main(["check", "--findings", scored_path])
        self.assertEqual(exit_code, EXIT_ALLOW)

    def test_artifact_swap_detected(self):
        """An artifact modified after attestation is detected (exit 2)."""
        artifact = self.make_artifact(b"original-assessed-build")

        genuine_provenance = {
            "subject_hash": provenance_module.sha256_file(artifact),
            "source_digest": "a" * 64,
            "generated_at": 1_700_000_000,
        }

        # The artifact changes after it was assessed.
        with open(artifact, "wb") as handle:
            handle.write(b"tampered-swapped-build")

        result = provenance_module.verify(
            artifact,
            genuine_provenance,
            expected_source_digest="a" * 64,
            freshness_seconds=10_000_000_000,
            now=1_700_000_100,
        )

        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], provenance_module.ARTIFACT_SWAP)

        provenance_path = self.write_json("provenance.json", genuine_provenance)
        exit_code = gate.main([
            "verify",
            "--artifact", artifact,
            "--provenance", provenance_path,
            "--source-digest", "a" * 64,
            "--freshness", "10000000000",
        ])
        self.assertEqual(exit_code, EXIT_BLOCK)

    def test_ledger_tamper_evidence(self):
        """A modified historical ledger record breaks the hash chain."""
        ledger_path = os.path.join(self.tmp, "ledger.jsonl")

        for index in range(3):
            ledger_module.append_record(
                ledger_path,
                event=f"pipeline_stage_{index}",
                decision="ALLOW" if index < 2 else "PROMOTE",
                detail=f"stage {index} completed",
                timestamp="2026-01-01T00:00:00Z",
            )

        self.assertTrue(ledger_module.verify_ledger(ledger_path)["verified"])

        # Someone edits a historical decision.
        ledger_module.tamper_record(
            ledger_path, 1, "stage 1 completed — actually this failed"
        )

        result = ledger_module.verify_ledger(ledger_path)
        self.assertFalse(result["verified"], "tampering must be detected")
        self.assertEqual(result["broken_at"], 1)

        exit_code = gate.main(["ledger", ledger_path])
        self.assertEqual(exit_code, EXIT_BLOCK)


# ─── Risk scoring ─────────────────────────────────────────────────────────────

class TestRiskScoring(GateTestCase):

    def test_documented_scores(self):
        """The three documented findings must reproduce their documented scores."""
        cases = [
            ({"cvss": 7.5, "epss": 0.94, "kev": True, "reachable": True}, 88.2),
            ({"cvss": 5.3, "epss": 0.01, "kev": False, "reachable": False}, 21.5),
            ({"cvss": 3.1, "epss": 0.001, "kev": False, "reachable": False}, 12.4),
        ]
        for inputs, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(correlate.calculate_risk(**inputs), expected)

    def test_score_is_bounded(self):
        for cvss in (0, 5, 10):
            for epss in (0, 0.5, 1):
                score = correlate.calculate_risk(cvss, epss, True, True)
                self.assertGreaterEqual(score, 0.0)
                self.assertLessEqual(score, 100.0)

    def test_kev_increases_score(self):
        without = correlate.calculate_risk(7.5, 0.94, False, True)
        with_kev = correlate.calculate_risk(7.5, 0.94, True, True)
        self.assertGreater(with_kev, without)

    def test_results_sorted_highest_risk_first(self):
        scored = correlate.correlate([CLEAN_FINDING, KEV_FINDING])
        self.assertEqual(scored[0]["id"], "CVE-2023-44487")

    def test_scanner_field_aliases_normalise(self):
        """Trivy/CVE style inputs map onto the common representation."""
        scored = correlate.correlate([{
            "cve": "CVE-2024-0001",
            "cvss_score": "6.5",
            "known_exploited": "true",
            "target": "app/pkg.go",
        }])
        self.assertEqual(scored[0]["id"], "CVE-2024-0001")
        self.assertEqual(scored[0]["cvss"], 6.5)
        self.assertTrue(scored[0]["kev"])

    def test_out_of_range_values_are_clamped(self):
        scored = correlate.correlate([{
            "id": "X-1", "cvss": 99, "epss": 4.2, "kind": "sca",
        }])
        self.assertEqual(scored[0]["cvss"], 10.0)
        self.assertEqual(scored[0]["epss"], 1.0)

    def test_non_numeric_cvss_is_rejected(self):
        with self.assertRaises(correlate.CorrelationError):
            correlate.correlate([{"id": "X-2", "cvss": "critical"}])

    def test_unknown_kind_is_rejected(self):
        with self.assertRaises(correlate.CorrelationError):
            correlate.correlate([{"id": "X-3", "kind": "unknown-scanner"}])

    def test_secret_finding_is_blocked(self):
        secret = {"id": "gitleaks-aws-key", "kind": "secret", "cvss": 0, "epss": 0}
        result = policy_module.check_policy(
            correlate.correlate([secret]), policy_module.load_policy(None)
        )
        self.assertEqual(result["decision"], policy_module.BLOCK)
        self.assertIn(
            "block_secrets",
            {violation["rule"] for violation in result["violations"]},
        )


# ─── Policy ───────────────────────────────────────────────────────────────────

class TestPolicy(GateTestCase):

    def test_secrets_rule_can_be_disabled(self):
        secret = {"id": "gitleaks-key", "kind": "secret"}
        relaxed = dict(policy_module.DEFAULT_POLICY)
        relaxed["block_secrets"] = False
        result = policy_module.check_policy(correlate.correlate([secret]), relaxed)
        self.assertEqual(result["decision"], policy_module.ALLOW)

    def test_kev_rule_can_be_disabled(self):
        """Score threshold still blocks a KEV finding; the rule itself is off."""
        relaxed = dict(policy_module.DEFAULT_POLICY)
        relaxed["block_known_exploited"] = False
        relaxed["max_risk_score"] = 100
        result = policy_module.check_policy(
            correlate.correlate([KEV_FINDING]), relaxed
        )
        self.assertEqual(result["decision"], policy_module.ALLOW)

    def test_unknown_policy_key_is_rejected(self):
        """A typo must not silently disable a rule."""
        path = self.write_json("policy.json", {"block_known_exploits": True})
        with self.assertRaises(policy_module.PolicyError):
            policy_module.load_policy(path)

    def test_out_of_range_threshold_is_rejected(self):
        path = self.write_json("policy.json", {"max_risk_score": 250})
        with self.assertRaises(policy_module.PolicyError):
            policy_module.load_policy(path)

    def test_threshold_boundary(self):
        finding = dict(CLEAN_FINDING)
        finding["cvss"] = 5.3
        finding["epss"] = 0.01
        # Risk is 21.5. A threshold of 21.5 passes; 21.4 blocks.
        at_limit = dict(policy_module.DEFAULT_POLICY, max_risk_score=21.5)
        below = dict(policy_module.DEFAULT_POLICY, max_risk_score=21.4)
        scored = correlate.correlate([finding])
        self.assertEqual(
            policy_module.check_policy(scored, at_limit)["decision"],
            policy_module.ALLOW,
        )
        self.assertEqual(
            policy_module.check_policy(scored, below)["decision"],
            policy_module.BLOCK,
        )

    def test_empty_findings_are_allowed(self):
        result = policy_module.check_policy([], policy_module.load_policy(None))
        self.assertEqual(result["decision"], policy_module.ALLOW)


# ─── Provenance ───────────────────────────────────────────────────────────────

class TestProvenance(GateTestCase):

    def _attestation(self, artifact, generated_at):
        return {
            "subject_hash": provenance_module.sha256_file(artifact),
            "source_digest": "b" * 64,
            "generated_at": generated_at,
        }

    def test_valid_provenance_verifies(self):
        artifact = self.make_artifact(b"good-build")
        attestation = self._attestation(artifact, 1_700_000_000)
        result = provenance_module.verify(
            artifact, attestation,
            expected_source_digest="b" * 64,
            freshness_seconds=3600,
            now=1_700_000_100,
        )
        self.assertTrue(result["verified"])
        self.assertEqual(result["result"], provenance_module.VERIFIED)

    def test_source_digest_mismatch_is_detected(self):
        artifact = self.make_artifact(b"good-build")
        attestation = self._attestation(artifact, 1_700_000_000)
        result = provenance_module.verify(
            artifact, attestation,
            expected_source_digest="c" * 64,   # a different source
            freshness_seconds=3600,
            now=1_700_000_100,
        )
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], provenance_module.SOURCE_MISMATCH)

    def test_stale_provenance_is_detected(self):
        artifact = self.make_artifact(b"good-build")
        attestation = self._attestation(artifact, 1_700_000_000)
        result = provenance_module.verify(
            artifact, attestation,
            expected_source_digest="b" * 64,
            freshness_seconds=60,
            now=1_700_000_999,   # ~16 minutes later
        )
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], provenance_module.STALE_PROVENANCE)

    def test_future_timestamp_is_not_trusted(self):
        """A timestamp ahead of the clock means something is wrong; fail closed."""
        artifact = self.make_artifact(b"good-build")
        attestation = self._attestation(artifact, 1_700_009_999)
        result = provenance_module.verify(
            artifact, attestation,
            expected_source_digest="b" * 64,
            freshness_seconds=3600,
            now=1_700_000_000,
        )
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], provenance_module.STALE_PROVENANCE)

    def test_missing_artifact_is_detected(self):
        result = provenance_module.verify(
            os.path.join(self.tmp, "absent.tar"),
            {"subject_hash": "d" * 64, "source_digest": "b" * 64,
             "generated_at": 1_700_000_000},
        )
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], provenance_module.MISSING_ARTIFACT)

    def test_malformed_provenance_document_is_rejected(self):
        path = self.write_json("provenance.json", {"subject_hash": "x"})
        with self.assertRaises(provenance_module.ProvenanceError):
            provenance_module.load_provenance(path)


# ─── Ledger ───────────────────────────────────────────────────────────────────

class TestLedger(GateTestCase):

    def test_chain_starts_at_genesis(self):
        path = os.path.join(self.tmp, "ledger.jsonl")
        record = ledger_module.append_record(path, "e", "ALLOW", "d", "t")
        self.assertEqual(record["prev_hash"], ledger_module.GENESIS)

    def test_empty_ledger_verifies(self):
        path = os.path.join(self.tmp, "ledger.jsonl")
        self.assertTrue(ledger_module.verify_ledger(path)["verified"])

    def test_recomputed_hash_matches_stored_hash(self):
        path = os.path.join(self.tmp, "ledger.jsonl")
        record = ledger_module.append_record(path, "e", "ALLOW", "d", "t")
        body = {key: record[key] for key in ledger_module.RECORD_FIELDS}
        self.assertEqual(
            ledger_module.compute_hash(body, record["prev_hash"]),
            record["self_hash"],
        )

    def test_each_record_links_to_its_predecessor(self):
        path = os.path.join(self.tmp, "ledger.jsonl")
        ledger_module.append_record(path, "a", "ALLOW", "", "t")
        second = ledger_module.append_record(path, "b", "ALLOW", "", "t")

        records = ledger_module._read_records(path)
        self.assertEqual(second["prev_hash"], records[0]["self_hash"])

    def test_inserted_record_is_detected(self):
        path = os.path.join(self.tmp, "ledger.jsonl")
        ledger_module.append_record(path, "a", "ALLOW", "", "t")
        ledger_module.append_record(path, "c", "ALLOW", "", "t")

        forged = {
            "event": "b", "timestamp": "t", "decision": "ALLOW", "detail": "",
            "prev_hash": ledger_module.GENESIS, "self_hash": "0" * 64,
        }
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(lines[0])
            handle.write(json.dumps(forged) + "\n")
            handle.write(lines[1])

        result = ledger_module.verify_ledger(path)
        self.assertFalse(result["verified"])

    def test_deleted_record_is_detected(self):
        path = os.path.join(self.tmp, "ledger.jsonl")
        for name in ("a", "b", "c"):
            ledger_module.append_record(path, name, "ALLOW", "", "t")

        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
        with open(path, "w", encoding="utf-8") as handle:
            handle.writelines([lines[0], lines[2]])

        result = ledger_module.verify_ledger(path)
        self.assertFalse(result["verified"])
        self.assertEqual(result["broken_at"], 1)

    def test_malformed_json_is_reported(self):
        path = os.path.join(self.tmp, "ledger.jsonl")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{not json\n")
        with self.assertRaises(ledger_module.LedgerError):
            ledger_module.verify_ledger(path)


# ─── Gate CLI contract ────────────────────────────────────────────────────────

class TestGateCli(GateTestCase):

    def _pipeline_files(self, artifact_content=b"build"):
        findings = self.write_json("findings.json", [CLEAN_FINDING])
        scored_path = os.path.join(self.tmp, "scored.json")
        correlate.dump_scored(correlate.load_findings(findings), scored_path)

        artifact = self.make_artifact(artifact_content)
        source_digest = "e" * 64
        attestation = {
            "subject_hash": provenance_module.sha256_file(artifact),
            "source_digest": source_digest,
            "generated_at": 1_700_000_000,
        }
        provenance_path = self.write_json("provenance.json", attestation)
        return scored_path, artifact, provenance_path, source_digest

    def test_all_passes_for_clean_pipeline(self):
        scored_path, artifact, prov, digest = self._pipeline_files()
        exit_code = gate.main([
            "all",
            "--findings", scored_path,
            "--artifact", artifact,
            "--provenance", prov,
            "--source-digest", digest,
            "--freshness", "10000000000",
            "--ledger", os.path.join(self.tmp, "ledger.jsonl"),
        ])
        self.assertEqual(exit_code, EXIT_ALLOW)

    def test_all_blocks_on_policy_before_verifying(self):
        findings = self.write_json("findings.json", [KEV_FINDING])
        scored_path = os.path.join(self.tmp, "scored.json")
        correlate.dump_scored(correlate.load_findings(findings), scored_path)

        exit_code = gate.main([
            "all",
            "--findings", scored_path,
            "--artifact", self.make_artifact(),
            "--provenance", self.write_json(
                "provenance.json",
                {"subject_hash": "f" * 64, "source_digest": "g" * 64,
                 "generated_at": 1_700_000_000},
            ),
        ])
        self.assertEqual(exit_code, EXIT_BLOCK)

    def test_missing_findings_file_exits_one(self):
        """A broken pipeline (exit 1) is distinguishable from a block (exit 2)."""
        exit_code = gate.main([
            "check", "--findings", os.path.join(self.tmp, "absent.json")
        ])
        self.assertEqual(exit_code, gate.EXIT_ERROR)

    def test_malformed_findings_json_exits_one(self):
        path = os.path.join(self.tmp, "bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{ not json")
        exit_code = gate.main(["score", "--findings", path])
        self.assertEqual(exit_code, gate.EXIT_ERROR)

    def test_pipeline_appends_to_ledger(self):
        _, artifact, prov, digest = self._pipeline_files()
        ledger_path = os.path.join(self.tmp, "ledger.jsonl")

        gate.main([
            "all", "--findings", _, "--artifact", artifact,
            "--provenance", prov, "--source-digest", digest,
            "--freshness", "10000000000", "--ledger", ledger_path,
        ])

        self.assertTrue(ledger_module.verify_ledger(ledger_path)["verified"])
        events = [
            record["event"]
            for record in ledger_module._read_records(ledger_path)
        ]
        self.assertIn("policy_check", events)
        self.assertIn("provenance_verify", events)


if __name__ == "__main__":
    unittest.main(verbosity=2)