# tests/test_merge_scanners.py
# Regression tests for tools/merge_scanners.py.
#
# Every shape in this file was observed from a real scanner, and each one broke
# the pipeline before it had a test. The common thread: a scanner that finds
# nothing does not necessarily produce an empty file or an empty list, and code
# that assumes it does turns a clean repository into a red build.

import json
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
for path in (REPO_ROOT, TOOLS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

import merge_scanners  # noqa: E402


class ReportShapeTestCase(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def write(self, name, payload):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
        return path


class TestTrivyShapes(ReportShapeTestCase):

    def test_results_absent_means_zero_findings(self):
        """
        Trivy omits the Results key entirely when it finds nothing.

        This is the real shape of `trivy fs` on a clean repository. An earlier
        version raised 'unrecognised report structure' here, so CI could never
        report green.
        """
        path = self.write("trivy.json", {
            "SchemaVersion": 2,
            "CreatedAt": "2026-10-08T00:00:00Z",
            "ArtifactName": ".",
            "ArtifactType": "filesystem",
        })
        self.assertEqual(merge_scanners.load_report(path), [])

    def test_results_empty_list_means_zero_findings(self):
        path = self.write("trivy.json", {"SchemaVersion": 2, "Results": []})
        self.assertEqual(merge_scanners.load_report(path), [])

    def test_vulnerabilities_are_mapped(self):
        path = self.write("trivy.json", {
            "SchemaVersion": 2,
            "Results": [{
                "Target": "requirements.txt",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2023-44487",
                    "PkgName": "http2",
                    "Title": "HTTP/2 rapid reset",
                    "Severity": "HIGH",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                }],
            }],
        })
        findings = merge_scanners.load_report(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "CVE-2023-44487")
        self.assertEqual(findings[0]["kind"], "sca")
        self.assertEqual(findings[0]["cvss"], 7.5)
        self.assertEqual(findings[0]["location"], "requirements.txt")

    def test_cvss_falls_back_through_vendor_order(self):
        path = self.write("trivy.json", {
            "SchemaVersion": 2,
            "Results": [{
                "Target": "app",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-0001",
                    "Severity": "MEDIUM",
                    "CVSS": {"ghsa": {"V3Score": 4.4}},
                }],
            }],
        })
        self.assertEqual(merge_scanners.load_report(path)[0]["cvss"], 4.4)

    def test_missing_cvss_becomes_zero_not_a_crash(self):
        path = self.write("trivy.json", {
            "SchemaVersion": 2,
            "Results": [{
                "Target": "app",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0002"}],
            }],
        })
        self.assertEqual(merge_scanners.load_report(path)[0]["cvss"], 0.0)

    def test_trivy_secret_scanner_output_is_mapped(self):
        path = self.write("trivy.json", {
            "SchemaVersion": 2,
            "Results": [{
                "Target": "config.py",
                "Secrets": [{
                    "RuleID": "generic-api-key",
                    "Title": "Generic API key",
                    "Severity": "CRITICAL",
                }],
            }],
        })
        findings = merge_scanners.load_report(path)
        self.assertEqual(findings[0]["kind"], "secret")
        self.assertEqual(findings[0]["id"], "trivy:generic-api-key")


class TestSemgrepShapes(ReportShapeTestCase):

    def test_results_key_absent_means_zero_findings(self):
        path = self.write("semgrep.json", {"results": [], "errors": []})
        self.assertEqual(merge_scanners.load_report(path), [])

    def test_severity_and_message_come_from_extra(self):
        """Semgrep nests the message and severity under `extra`, not the top level."""
        path = self.write("semgrep.json", {"results": [{
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "app/parser.py",
            "start": {"line": 88, "col": 1},
            "extra": {
                "message": "Use of eval() on user-controlled input",
                "severity": "WARNING",
            },
        }]})
        finding = merge_scanners.load_report(path)[0]
        self.assertEqual(finding["kind"], "sast")
        self.assertEqual(finding["severity"], "WARNING")
        self.assertEqual(finding["title"], "Use of eval() on user-controlled input")
        self.assertEqual(finding["location"], "app/parser.py:88")

    def test_sast_findings_do_not_inherit_fabricated_exploitability(self):
        path = self.write("semgrep.json", {"results": [{
            "check_id": "rule-1", "path": "a.py",
            "extra": {"severity": "ERROR"},
        }]})
        finding = merge_scanners.load_report(path)[0]
        self.assertEqual(finding["kev"], False)
        self.assertEqual(finding["reachable"], False)
        self.assertEqual(finding["epss"], 0.0)


class TestGitleaksShapes(ReportShapeTestCase):

    def test_empty_list_means_no_leaks(self):
        path = self.write("gitleaks.json", [])
        self.assertEqual(merge_scanners.load_report(path), [])

    def test_leaks_are_mapped_to_secret_kind(self):
        path = self.write("gitleaks.json", [{
            "Description": "AWS Access Key ID",
            "StartLine": 12,
            "File": "deploy/release.sh",
            "RuleID": "aws-access-token",
            # Present when --redact is NOT used locally.
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Match": "AKIAIOSFODNN7EXAMPLE",
        }])
        finding = merge_scanners.load_report(path)[0]
        self.assertEqual(finding["kind"], "secret")
        self.assertEqual(finding["id"], "aws-access-token")
        self.assertEqual(finding["location"], "deploy/release.sh:12")
        self.assertEqual(finding["severity"], "CRITICAL")

    def test_secret_value_is_never_carried_forward(self):
        """
        A local run without --redact produces real credentials. Those must never
        reach merged_findings.json, which is uploaded as a CI artifact.
        """
        path = self.write("gitleaks.json", [{
            "Description": "AWS Access Key ID",
            "File": "deploy.sh",
            "RuleID": "aws-access-token",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Match": "AKIAIOSFODNN7EXAMPLE",
        }])
        serialised = json.dumps(merge_scanners.load_report(path))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", serialised)


class TestBOMTolerance(ReportShapeTestCase):
    def test_utf8_bom_does_not_break_parsing(self):
        path = os.path.join(self.tmp, "trivy.json")
        with open(path, "w", encoding="utf-8-sig") as handle:
            json.dump({"SchemaVersion": 2, "Results": []}, handle)
        self.assertEqual(merge_scanners.load_report(path), [])


class TestCollect(ReportShapeTestCase):

    def test_missing_required_report_is_an_error(self):
        """A scanner that produced no file must not read as a clean scan."""
        with self.assertRaises(merge_scanners.MergeError):
            merge_scanners.collect(self.tmp)

    def test_empty_required_report_is_an_error(self):
        with open(os.path.join(self.tmp, "trivy.json"), "w", encoding="utf-8") as h:
            h.write("")
        with self.assertRaises(merge_scanners.MergeError):
            merge_scanners.collect(self.tmp)

    def test_clean_repository_collects_successfully(self):
        self.write("trivy.json", {"SchemaVersion": 2})
        self.write("gitleaks.json", [])
        self.write("semgrep.json", {"results": []})
        self.assertEqual(merge_scanners.collect(self.tmp), [])

    def test_missing_optional_report_is_a_warning_not_an_error(self):
        self.write("trivy.json", {"SchemaVersion": 2, "Results": []})
        # No semgrep.json or gitleaks.json present.
        self.assertEqual(merge_scanners.collect(self.tmp), [])

    def test_findings_from_all_scanners_are_combined(self):
        self.write("trivy.json", {
            "SchemaVersion": 2,
            "Results": [{
                "Target": "req.txt",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2023-44487",
                    "Severity": "HIGH",
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                }],
            }],
        })
        self.write("gitleaks.json", [{
            "Description": "AWS key", "File": "d.sh", "RuleID": "aws",
        }])
        self.write("semgrep.json", {"results": [{
            "check_id": "rule-1", "path": "a.py",
            "extra": {"severity": "WARNING"},
        }]})

        findings = merge_scanners.collect(self.tmp)
        self.assertEqual(len(findings), 3)
        self.assertEqual({f["kind"] for f in findings}, {"sca", "secret", "sast"})


if __name__ == "__main__":
    unittest.main(verbosity=2)