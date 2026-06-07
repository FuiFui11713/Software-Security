"""Persistence helpers for previously analyzed OverflowGuard files."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import uuid

from analyzer import Finding

HISTORY_PATH = Path(__file__).with_name(".overflowguard_history.json")
MAX_HISTORY_ENTRIES = 30


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _source_hash(source: str) -> str:
    return sha256(source.encode("utf-8", errors="replace")).hexdigest()


def _finding_to_dict(finding: Finding) -> dict[str, object]:
    return asdict(finding)


def _finding_from_dict(data: dict[str, object]) -> Finding:
    risk = str(data.get("risk", data.get("severity", "")))
    return Finding(
        line_number=int(data.get("line_number", 0)),
        line_content=str(data.get("line_content", "")),
        function_name=str(data.get("function_name", "")),
        expression=str(data.get("expression", data.get("line_content", ""))),
        cwe=str(data.get("cwe", "")),
        category=str(data.get("category", "")),
        type=str(data.get("type", "")),
        risk_type=str(data.get("risk_type", "REAL_OVERFLOW_RISK")),
        risk=risk,
        severity=str(data.get("severity", risk)),
        certainty_type=str(data.get("certainty_type", "POTENTIAL")),
        confidence=int(data.get("confidence", 0)),
        reason=str(data.get("reason", "")),
        suggestion=str(data.get("suggestion", "")),
    )


def load_history() -> list[dict[str, object]]:
    if not HISTORY_PATH.exists():
        return []

    try:
        data = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(data, list):
        return []

    cleaned: list[dict[str, object]] = []
    for entry in data:
        if isinstance(entry, dict):
            cleaned.append(entry)
    return cleaned


def save_history(entries: list[dict[str, object]]) -> None:
    HISTORY_PATH.write_text(
        json.dumps(entries[:MAX_HISTORY_ENTRIES], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def record_analysis(filename: str, source: str, findings: list[Finding]) -> dict[str, object]:
    entry = {
        "id": uuid.uuid4().hex,
        "filename": filename,
        "created_at": _now_iso(),
        "source_hash": _source_hash(source),
        "source": source,
        "findings": [_finding_to_dict(f) for f in findings],
        "total_findings": len(findings),
    }

    history = load_history()
    history = [item for item in history if item.get("source_hash") != entry["source_hash"]]
    history.insert(0, entry)
    save_history(history)
    return entry


def get_history_entry(entry_id: str) -> dict[str, object] | None:
    for entry in load_history():
        if str(entry.get("id", "")) == entry_id:
            return entry
    return None


def delete_history_entry(entry_id: str) -> bool:
    history = load_history()
    filtered = [entry for entry in history if str(entry.get("id", "")) != entry_id]
    if len(filtered) == len(history):
        return False
    save_history(filtered)
    return True


def entry_to_findings(entry: dict[str, object]) -> list[Finding]:
    findings_data = entry.get("findings", [])
    if not isinstance(findings_data, list):
        return []
    findings: list[Finding] = []
    for item in findings_data:
        if isinstance(item, dict):
            findings.append(_finding_from_dict(item))
    return findings


def entry_summary(entry: dict[str, object]) -> str:
    filename = str(entry.get("filename", "unknown"))
    created_at = str(entry.get("created_at", ""))
    total_findings = int(entry.get("total_findings", 0))
    return f"{filename} · {created_at[:19].replace('T', ' ')} · {total_findings} findings"
