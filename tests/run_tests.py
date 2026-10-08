#!/usr/bin/env python3
# tests/run_tests.py
# VerifierGate — dependency-free test runner.
#
# Executes tests/test_gate.py using only the standard library, so the security
# controls can be validated on a runner (or a locked-down host) where pytest is
# not installed.
#
# Exit code mirrors the gate contract: 0 = all passed, 1 = a test failed.
#
# Usage:
#   python tests/run_tests.py
#   python tests/run_tests.py -v

import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.join(REPO_ROOT, "tests")

for path in (REPO_ROOT, TESTS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)


def main(argv):
    verbosity = 2 if ("-v" in argv or "--verbose" in argv) else 1

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=TESTS_DIR, pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)

    total = result.testsRun
    failed = len(result.failures) + len(result.errors)

    print()
    print("=" * 60)
    print(f"VerifierGate validation: {total - failed}/{total} passed")
    if failed:
        print(f"RESULT: FAIL ({failed} failing)")
        print("=" * 60)
        return 1

    print("RESULT: PASS")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))