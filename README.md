# VerifierGate

**Exploitability-correlated risk gates with provenance-verified artifact promotion and tamper-evident audit logging.**

VerifierGate is a DevSecOps prototype that adds a single, centralised security
decision to a CI/CD pipeline. It combines scanner findings with exploitability
context, enforces the result through policy-as-code, verifies the integrity of
the exact artifact being promoted, and records every decision in a hash-chained
audit ledger.

> **Status:** research prototype. The attack cases are simulated validation
> scenarios, not attacks against a live system.

---

## The problem it addresses

Conventional DevSecOps pipelines run SAST, SCA and secret scanners as separate
pass/fail checks. Two gaps follow from that:

1. **Severity is not exploitability.** A scanner's `HIGH` label carries no
   information about whether a vulnerability is being exploited in the wild, or
   whether the vulnerable code path is even reachable. Teams routinely either
   block on noise or wave through real risk.
2. **The assessed artifact may not be the promoted artifact.** Scanners prove the
   *source* was scanned. Nothing ties the file that ships to the file that was
   assessed, so a swap between the two is invisible.

VerifierGate closes both with one decision point.

---

## Pipeline

```text
                        BUILD
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
    Semgrep            Trivy            Gitleaks
     (SAST)            (SCA)           (Secrets)
        └─────────────────┼─────────────────┘
                          ▼
                   merge_scanners.py
                          ▼
                    correlate.py        normalise + risk score
                          ▼
                     policy.py          policy-as-code
                          ▼
                 ┌────────┴────────┐
                 ▼                 ▼
              BLOCK              ALLOW
                                   ▼
                            provenance.py     artifact + source + freshness
                                   ▼
                               ledger.py       hash-chained audit record
                                   ▼
                               PROMOTE
```

Scanners produce findings. **They are not the decision-maker.** `correlate.py`
reduces them to one number, `policy.py` judges that number against explicit
rules, and `gate.py` enforces the verdict through its exit code.

---

## Risk scoring

```text
Risk = (0.40 × CVSS/10 + 0.30 × EPSS + 0.20 × KEV + 0.10 × Reachable) × 100
```

| Signal | Weight | Range | Meaning |
| --- | --- | --- | --- |
| CVSS | 0.40 | 0–1 (from 0–10) | Intrinsic technical severity |
| EPSS | 0.30 | 0–1 | Observed exploitation probability |
| KEV | 0.20 | 0 or 1 | Listed in CISA Known Exploited Vulnerabilities |
| Reachable | 0.10 | 0 or 1 | The vulnerable path is actually reachable |

Weights sum to 1.0, so the score stays on a 0–100 scale. CVSS dominates because
it is the most broadly applicable signal, but a KEV listing plus high EPSS will
outrank a higher-CVSS vulnerability that has never been exploited.

### Worked examples

| Finding | CVSS | EPSS | KEV | Reachable | Risk |
| --- | --- | --- | --- | --- | --- |
| CVE-2023-44487 | 7.5 | 0.94 | Yes | Yes | **88.2** |
| CVE-2024-1234 | 5.3 | 0.01 | No | No | **21.5** |
| CVE-2022-0001 | 3.1 | 0.001 | No | No | **12.4** |

These are computed by `correlate.calculate_risk()` from the inputs above, and are
asserted in `tests/test_gate.py::TestRiskScoring::test_documented_scores`.

---

## Policy

```json
{
  "max_risk_score": 40,
  "block_known_exploited": true,
  "block_secrets": true
}
```

A finding is blocked when **any** enabled rule matches, and *every* violation is
reported so a blocked build can explain itself. Unknown keys are **rejected**
rather than ignored — a typo like `block_known_exploits` would otherwise
silently disable a security rule.

---

## Exit codes

The exit code is the contract a CI runner reacts to:

| Code | Meaning | Runner should |
| --- | --- | --- |
| `0` | Stage passed | Continue the pipeline |
| `2` | **BLOCKED** by policy or provenance | Stop the deployment |
| `1` | A stage could not run | Fix the pipeline, then re-run |

Separating 2 from 1 matters: a broken pipeline should be retried or repaired,
while a genuine security block should stop the release and go to review.

---

## Components

| Component | Purpose | Output |
| --- | --- | --- |
| `correlate.py` | Merges findings and calculates risk scores | Scored findings JSON |
| `policy.py` | Evaluates findings against deployment rules | `BLOCK` / `ALLOW` + violations |
| `provenance.py` | Checks artifact hash, source digest and freshness | `VERIFIED` / `BLOCKED` + reason |
| `ledger.py` | Records decisions using a hash chain | `ledger.jsonl` |
| `gate.py` | CLI orchestrating score, check and verify | Exit 0 / 1 / 2 |
| `pipeline_sim.py` | Runs the simulated scenarios | `runs/` + `summary.json` |
| `tools/merge_scanners.py` | Normalises Semgrep/Trivy/Gitleaks output | `merged_findings.json` |
| `tools/make_provenance.py` | Generates a provenance attestation | `provenance.json` |
| `tests/test_gate.py` | Validates the core security controls | 37 tests |
| `tests/test_merge_scanners.py` | Pins real scanner output shapes | 19 tests |
| `tests/run_tests.py` | Runs the suite with no dependencies | PASS/FAIL + exit code |

Everything is **Python 3.9+ standard library only** — no third-party runtime
dependencies. `requirements.txt` is intentionally empty of packages, so the gate
runs on a minimal or network-restricted runner.

---

## Usage

### Score findings

```bash
python gate.py score --findings findings.json --out scored_findings.json
```

```
CORRELATE: 3 finding(s) normalised
   88.2  CVE-2023-44487 (sca) [KEV, REACHABLE]
   21.5  CVE-2024-1234 (sca)
   12.4  CVE-2022-0001 (sca)
RISK: max=88.2 mean=40.7
```

### Apply policy

```bash
python gate.py check --findings scored_findings.json --policy policy.json
```

```
DECISION: BLOCK
VIOLATIONS (2):
  - [max_risk_score] CVE-2023-44487: Risk 88.2 exceeds the maximum allowed score of 40
  - [block_known_exploited] CVE-2023-44487: Finding is listed as known-exploited (CISA KEV)
```

Exit code `2`.

### Verify provenance

```bash
python gate.py verify \
  --artifact app.tar \
  --provenance provenance.json \
  --source-digest "$(cat expected_source_digest.txt)" \
  --freshness 3600
```

```
PROVENANCE: BLOCKED
REASON: ARTIFACT SWAP DETECTED
  [PASS] artifact_sha256: 7cd88adf...
  [PASS] source_digest: d53b751e...
  [FAIL] freshness: age = 16s
```

### Verify the audit ledger

```bash
python gate.py ledger ledger.jsonl --describe
```

```
Record 1: prev=GENESIS -> self=8236e39e...
Record 2: prev=8236e39e -> self=1dfa973d...
Record 3: prev=1dfa973d -> self=115cf403...
LEDGER: INTACT
```

---

## Artifact provenance verification

Before promotion, `provenance.py` re-derives three properties of the artifact
and compares them against the recorded attestation:

| Check | Failure reason |
| --- | --- |
| Artifact SHA-256 matches the attested subject hash | `ARTIFACT SWAP DETECTED` |
| Recorded source digest matches the expected source digest | `SOURCE MISMATCH` |
| Attestation is inside the freshness window | `STALE PROVENANCE` |

A timestamp *ahead* of the clock is treated as stale rather than trusted — a
wrong clock or a forged timestamp fails closed instead of passing.

---

## Tamper-evident audit ledger

Each record embeds the hash of its predecessor:

```text
Record 1: prev = GENESIS  →  self_hash = AAA
Record 2: prev = AAA      →  self_hash = BBB
Record 3: prev = BBB      →  self_hash = CCC
```

Editing record 2's body changes its self-hash, which no longer matches the
`prev_hash` record 3 recorded. `verify_ledger()` reports the first broken index
and the CLI exits `2`. The test suite covers modification, insertion and
deletion.

The ledger provides **evidence**. It does not block a deployment — `gate.py`
owns that decision.

---

## Automated testing

```bash
python tests/run_tests.py -v     # no dependencies
python -m pytest tests -q        # if pytest is available
```

56 tests. The four core controls map to documented controls:

| Test | Validates | Expected |
| --- | --- | --- |
| `test_kev_blocked` | Known-exploited finding is rejected | exit 2 |
| `test_clean_allowed` | Low-risk finding is accepted | exit 0 |
| `test_artifact_swap_detected` | Modified artifact is detected | exit 2 |
| `test_ledger_tamper_evidence` | Modified record is detected | verification false |

Plus risk-scoring reproduction, policy edge cases, provenance freshness and
source-binding, ledger insertion/deletion detection, and CLI exit-code
contracts.

`tests/test_merge_scanners.py` pins the real output shapes of all three
scanners. Each of these was a live CI failure before it had a test, and they
share one root cause: **a scanner that finds nothing does not necessarily
produce an empty list.** Trivy omits its `Results` key entirely, so treating
that as an unrecognised structure turns a clean repository into a red build.

---

## Simulated scenarios

```bash
python pipeline_sim.py           # run all
python pipeline_sim.py --list
python pipeline_sim.py --only hardened_secret
```

Each scenario is materialised under `runs/` and executed as a real subprocess, so
the recorded exit codes are observed rather than asserted by the harness.

| Scenario | Condition | Expected |
| --- | --- | --- |
| `normal_kev_dep` | Baseline pipeline, known-exploited dependency | BLOCK |
| `normal_artifact_swap` | Baseline pipeline, artifact modified | BLOCK |
| `hardened_kev_dep` | Hardened pipeline, known-exploited dependency | BLOCK |
| `hardened_artifact_swap` | Hardened pipeline, artifact swapped | BLOCK |
| `hardened_secret` | Hardened pipeline, secret exposed | BLOCK |
| `hardened_sast_reachable` | Reachable SAST finding exceeds threshold | BLOCK |
| `hardened_sast_unreachable` | Same severity, unreachable → accepted | ALLOW |
| `hardened_none` | No simulated attack | ALLOW |

`runs/` is gitignored and regenerated deterministically.

---

## GitHub Actions workflow

`.github/workflows/devsecops.yml` wires the whole pipeline into CI. Hardening
choices and why they matter:

* **`permissions: contents: read`** — the pipeline needs no write access, so no
  write scope is granted at all.
* **Every third-party action pinned to a full commit SHA.** A mutable tag like
  `@v4` can be repointed at new code by anyone who compromises the upstream
  repository; a SHA cannot.
* **`persist-credentials: false`** — stops the checkout token being written into
  `.git/config`, where a later step could exfiltrate it.
* **`concurrency` with `cancel-in-progress`** — a stale push cannot report
  success after a newer one.
* **Each gate stage is a separate step**, so a failure names the stage that
  broke instead of one opaque job failure.
* **Missing scanner output is a hard error.** An absent or empty report is never
  treated as "zero findings" — that is precisely the failure mode that lets a
  vulnerable build through.
* **Evidence is uploaded with `if: always()`**, so the ledger and reports survive
  a blocked run.

---

## Limitations

* Risk weights are heuristic and are not calibrated against real organisational
  risk data.
* **Secrets are governed entirely by `block_secrets`, not by the risk score.**
  The formula is calibrated for CVE-shaped findings; a secret has no CVSS and no
  EPSS, so its score reflects reachability alone and comes out at **10.0**,
  below any sane `max_risk_score`. Setting `block_secrets: false` for
  convenience therefore lets a committed credential through with a score of
  10.0. This is asserted by
  `TestPolicy::test_secret_risk_score_is_low_and_rule_dependent`, so the
  behaviour stays visible rather than accidental.
* EPSS and KEV values are supplied as input data; there is no live
  synchronisation with FIRST or CISA.
* Reachability is a finding signal, not a computed call-graph analysis.
* The provenance attestation is a **minimal, unsigned** record. It proves the
  artifact matches a digest recorded by the same pipeline, not provenance from an
  independent signer. Production should use Sigstore/cosign.
* The current CI example generates provenance as part of the same job. A stronger
  design has a separate attestation service or a protected build environment.
* The attack scenarios are simulated validation cases, not attacks against a live
  system.

## Future work

* Live CISA KEV and FIRST EPSS ingestion.
* Sigstore/cosign keyless signing and attestation verification.
* Real SBOM generation and dependency-graph reachability.
* CodeQL or equivalent for computed reachability.
* OPA/Rego for policy-as-code.
* Dashboard for risk, gate decisions and audit history.

---

## Repository layout

```text
secure-devops-pipeline/
├── correlate.py               # Normalisation and risk scoring
├── policy.py                  # Policy-as-code evaluation
├── provenance.py              # Artifact provenance verification
├── ledger.py                  # Hash-chained audit ledger
├── gate.py                    # CLI orchestrator (exit 0 / 1 / 2)
├── pipeline_sim.py            # Simulated scenarios
├── findings.json              # Sample findings fixture
├── policy.json                # Deployment policy
├── tools/
│   ├── merge_scanners.py      # Semgrep/Trivy/Gitleaks normaliser
│   └── make_provenance.py     # Attestation generator
├── tests/
│   ├── test_gate.py           # 37 tests
│   ├── test_merge_scanners.py # 19 tests
│   └── run_tests.py           # Dependency-free runner
└── .github/workflows/
    └── devsecops.yml          # CI security pipeline
```