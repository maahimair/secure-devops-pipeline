# ledger.py
# VerifierGate — Tamper-evident audit ledger.
#
# Every gate decision is appended to a hash-chained JSONL ledger. Each record
# embeds the hash of the record before it, so any edit to a historical entry
# breaks the chain at that point and at every point after it.
#
#   Record 1: prev = GENESIS  -> self_hash = AAA
#   Record 2: prev = AAA      -> self_hash = BBB
#   Record 3: prev = BBB      -> self_hash = CCC
#
# Editing record 2's body changes its self_hash, which no longer matches the
# prev_hash that record 3 recorded. verify_ledger() reports the first broken
# index.
#
# This ledger provides evidence. It does not block a deployment — gate.py owns
# that decision.
#
# Standard library only.

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Iterable, List

GENESIS = "GENESIS"

RECORD_FIELDS = ("event", "timestamp", "decision", "detail")


class LedgerError(ValueError):
    """Raised when a ledger file cannot be parsed."""


def _canonical(body: Dict[str, Any]) -> str:
    """Serialise a record body deterministically so hashes are reproducible."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(body: Dict[str, Any], prev_hash: str) -> str:
    """Hash one record: its body bound to the previous record's hash."""
    payload = f"{prev_hash}|{_canonical(body)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_records(path: str) -> List[Dict[str, Any]]:
    if not os.path.isfile(path):
        return []

    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise LedgerError(
                    f"{path}:{line_number} is not valid JSON: {exc.msg}"
                ) from exc
    return records


def last_hash(path: str) -> str:
    """Hash of the most recent record, or GENESIS for an empty ledger."""
    records = _read_records(path)
    if not records:
        return GENESIS
    return str(records[-1].get("self_hash", GENESIS))


def append_record(
    path: str,
    event: str,
    decision: str,
    detail: str = "",
    timestamp: str = "",
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Append one record to the chain and return it.

    The previous hash is read inside this function so callers cannot append a
    record that silently forks the chain.
    """
    records = _read_records(path)
    prev_hash = str(records[-1].get("self_hash", GENESIS)) if records else GENESIS

    body: Dict[str, Any] = {
        "event": event,
        "timestamp": timestamp,
        "decision": decision,
        "detail": detail,
    }
    if extra:
        body["extra"] = extra

    record = {
        **body,
        "prev_hash": prev_hash,
        "self_hash": compute_hash(body, prev_hash),
    }

    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")

    return record


def verify_ledger(path: str) -> Dict[str, Any]:
    """
    Walk the chain and confirm every link.

    Returns {"verified": bool, "records": int, "broken_at": int | None, ...}.
    """
    records = _read_records(path)

    if not records:
        return {
            "verified": True,
            "records": 0,
            "broken_at": None,
            "detail": "Ledger is empty; nothing to verify.",
        }

    expected_prev = GENESIS

    for position, record in enumerate(records):
        body = {key: record.get(key, "") for key in RECORD_FIELDS}
        if "extra" in record:
            body["extra"] = record["extra"]

        # The chain must start at genesis.
        if record.get("prev_hash") != expected_prev:
            return {
                "verified": False,
                "records": len(records),
                "broken_at": position,
                "detail": (
                    f"Record {position} expects prev_hash "
                    f"{expected_prev[:12]!r} but stores "
                    f"{str(record.get('prev_hash'))[:12]!r}. "
                    "A record was inserted, removed or reordered."
                ),
            }

        # The record's own hash must match its contents.
        recomputed = compute_hash(body, expected_prev)
        if recomputed != record.get("self_hash"):
            return {
                "verified": False,
                "records": len(records),
                "broken_at": position,
                "detail": (
                    f"Record {position} body was modified: recomputed hash "
                    f"{recomputed[:12]!r} does not match stored "
                    f"{str(record.get('self_hash'))[:12]!r}."
                ),
            }

        expected_prev = recomputed

    return {
        "verified": True,
        "records": len(records),
        "broken_at": None,
        "detail": f"All {len(records)} record(s) verified; chain intact.",
    }


def tamper_record(path: str, index: int, new_detail: str) -> None:
    """
    Rewrite one record's body *without* fixing its hash.

    This exists so tests and demos can prove the chain actually detects
    modification. It is never called by gate.py.
    """
    records = _read_records(path)
    if not 0 <= index < len(records):
        raise LedgerError(f"index {index} out of range (0..{len(records) - 1})")

    records[index]["detail"] = new_detail

    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def describe_chain(path: str) -> Iterable[str]:
    """Yield a short human-readable summary line per record."""
    for position, record in enumerate(_read_records(path)):
        yield (
            f"Record {position + 1}: "
            f"prev={str(record.get('prev_hash'))[:12]} "
            f"-> self={str(record.get('self_hash'))[:12]} "
            f"[{record.get('decision')}] {record.get('event')}"
        )