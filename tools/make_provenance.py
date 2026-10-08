#!/usr/bin/env python3
# tools/make_provenance.py
# VerifierGate — provenance attestation generator.
#
# Produces the attestation that provenance.py later verifies. It records the
# SHA-256 of the built artifact and the source revision it came from, so the
# gate can detect an artifact swap at promotion time.
#
# Scope note: this is a MINIMAL attestation. It proves the artifact matches a
# recorded digest from this pipeline, but it is NOT a signed attestation — the
# digest lives in the same repository as the artifact, so it proves internal
# consistency rather than provenance from an independent signer. A production
# deployment should generate provenance with Sigstore/cosign in the build step
# instead. See the Limitations section of the project documentation.
#
# Standard library only.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import provenance as provenance_module  # noqa: E402


def source_digest_for(revision: str) -> str:
    """Derive the expected source digest from a revision string.

    The revision itself (a 40-char git SHA) is recorded separately as
    `source_revision`; the `source_digest` is its SHA-256 so every component
    comparing against it handles a fixed-width hex value.
    """
    return hashlib.sha256(revision.encode("utf-8")).hexdigest()


def build_attestation(
    artifact_path: str,
    source_revision: str,
    builder: str,
    workflow_ref: str | None = None,
) -> dict:
    return {
        "subject_hash": provenance_module.sha256_file(artifact_path),
        "source_digest": source_digest_for(source_revision),
        "source_revision": source_revision,
        "generated_at": time.time(),
        "builder": builder,
        "artifact": os.path.basename(artifact_path),
        "ci_workflow_ref": workflow_ref,
        "attestation_version": 1,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a provenance attestation for a built artifact.",
    )
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--source", required=True,
        help="expected source revision, normally `git rev-parse HEAD`",
    )
    parser.add_argument(
        "--builder", default="local",
        help="identifier recorded as the builder",
    )
    parser.add_argument(
        "--workflow-ref", default=os.environ.get("GITHUB_WORKFLOW_REF"),
    )
    parser.add_argument(
        "--print-source-digest",
        action="store_true",
        help="print the source digest on stdout for shell capture",
    )
    args = parser.parse_args(argv)

    if not os.path.isfile(args.artifact):
        print(f"[ERROR] Artifact not found: {args.artifact}", file=sys.stderr)
        return 1

    attestation = build_attestation(
        args.artifact, args.source, args.builder, args.workflow_ref
    )

    parent = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(parent, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(attestation, handle, indent=2)
        handle.write("\n")

    print(f"PROVENANCE: wrote {args.out}")
    print(f"  artifact       {attestation['artifact']}")
    print(f"  subject_sha256 {attestation['subject_hash']}")
    print(f"  source_digest  {attestation['source_digest']}")

    if args.print_source_digest:
        # Emit just the digest on the last line so a shell can capture it:
        #   python tools/make_provenance.py ... --print-source-digest \
        #     | tail -n1
        print(source_digest_for(args.source))

    return 0


if __name__ == "__main__":
    sys.exit(main())