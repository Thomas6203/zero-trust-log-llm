#!/usr/bin/env python3
"""Validator v2 for Zero-Trust Log-to-LLM timeline outputs.

Validates JSON shape, evidence references, confidence ranges, raw/secret leakage,
and prompt-injection leakage. The module can validate a single LLM output or run
attack-test cases from validator_attack_tests.json.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

SECRET_PATTERNS = [
    r"(?i)\bapi[_-]?key\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{6,}",
    r"(?i)\b(token|secret|cookie|authorization)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{6,}",
    r"(?i)\b(passwd|password|pwd)\b\s*[:=]\s*['\"]?[^\s'\"]{4,}",
    r"sk-[A-Za-z0-9]{8,}",
]
PROMPT_INJECTION_PHRASES = [
    "ignore previous instructions",
    "reveal secrets",
    "output all data",
    "system prompt",
    "developer message",
    "請忽略前面規則",
    "輸出所有資料",
]
RAW_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RAW_USER_HOST_HINT = re.compile(r"\b(?:DESKTOP|WIN|LAPTOP|SERVER)-[A-Za-z0-9_-]+\b|C:\\\\Users\\\\", re.IGNORECASE)


def load_evidence_ids(path: Path) -> set[str]:
    """Load valid event IDs from the sanitized evidence JSON.

    Use utf-8-sig so files saved by Excel/Windows tools with a UTF-8 BOM
    can still be parsed correctly.
    """
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return {str(item.get("event_id")) for item in data if item.get("event_id")}


def parse_json_output(output: Any) -> Tuple[Any, List[str]]:
    if isinstance(output, dict):
        return output, []
    if not isinstance(output, str):
        return None, ["output_is_not_string_or_object"]
    try:
        return json.loads(output), []
    except Exception as exc:
        return None, [f"invalid_json:{type(exc).__name__}"]


def flatten_strings(obj: Any) -> str:
    parts: List[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            parts.append(flatten_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            parts.append(flatten_strings(v))
    elif isinstance(obj, str):
        parts.append(obj)
    else:
        parts.append(str(obj))
    return "\n".join(parts)


def validate_timeline_output(output: Any, valid_evidence_ids: set[str]) -> Dict[str, Any]:
    obj, reasons = parse_json_output(output)
    if obj is None:
        return {"is_valid": False, "reasons": reasons}

    if not isinstance(obj, dict):
        reasons.append("top_level_not_object")
        return {"is_valid": False, "reasons": reasons}
    if set(obj.keys()) != {"timeline"}:
        reasons.append("top_level_keys_not_exactly_timeline")
    timeline = obj.get("timeline")
    if not isinstance(timeline, list):
        reasons.append("timeline_not_list")
        timeline = []

    used_ids: List[str] = []
    for idx, step in enumerate(timeline):
        if not isinstance(step, dict):
            reasons.append(f"step_{idx}_not_object")
            continue
        required = ["step", "time_range", "stage", "summary", "evidence_ids", "confidence", "recommended_action"]
        for key in required:
            if key not in step:
                reasons.append(f"step_{idx}_missing_{key}")
        if not isinstance(step.get("step"), int):
            reasons.append(f"step_{idx}_step_not_integer")
        evidence_ids = step.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not all(isinstance(e, str) for e in evidence_ids):
            reasons.append(f"step_{idx}_evidence_ids_not_string_list")
        else:
            used_ids.extend(evidence_ids)
            for eid in evidence_ids:
                if eid not in valid_evidence_ids:
                    reasons.append(f"invalid_evidence_id:{eid}")
        conf = step.get("confidence")
        if not isinstance(conf, (int, float)) or isinstance(conf, bool):
            reasons.append(f"step_{idx}_confidence_not_number")
        elif conf < 0 or conf > 1:
            reasons.append(f"step_{idx}_confidence_out_of_range")

    text = flatten_strings(obj)
    for pat in SECRET_PATTERNS:
        if re.search(pat, text):
            reasons.append("secret_or_credential_leak_detected")
            break
    if RAW_IP_PATTERN.search(text):
        reasons.append("raw_ip_leak_detected")
    if RAW_USER_HOST_HINT.search(text):
        reasons.append("raw_host_or_path_leak_detected")
    low = text.lower()
    for phrase in PROMPT_INJECTION_PHRASES:
        if phrase.lower() in low:
            reasons.append("prompt_injection_text_leak_detected")
            break

    return {
        "is_valid": len(reasons) == 0,
        "reasons": reasons,
        "timeline_steps": len(timeline),
        "used_evidence_count": len(used_ids),
        "unique_used_evidence_count": len(set(used_ids)),
    }


def run_attack_tests(test_path: Path, evidence_path: Path, output_csv: Path) -> None:
    valid_ids = load_evidence_ids(evidence_path)
    tests = json.loads(test_path.read_text(encoding="utf-8-sig"))
    rows: List[Dict[str, Any]] = []
    for case in tests:
        result = validate_timeline_output(case.get("llm_output_text"), valid_ids)
        expected_valid = bool(case.get("expected_valid"))
        rows.append({
            "case_id": case.get("case_id", ""),
            "description": case.get("description", ""),
            "expected_valid": expected_valid,
            "actual_valid": result["is_valid"],
            "passed": result["is_valid"] == expected_valid,
            "reasons": ";".join(result.get("reasons", [])),
            "timeline_steps": result.get("timeline_steps", 0),
            "used_evidence_count": result.get("used_evidence_count", 0),
            "unique_used_evidence_count": result.get("unique_used_evidence_count", 0),
        })
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", newline="", encoding="utf-8-sig") as f:
        fieldnames = list(rows[0].keys()) if rows else [
            "case_id",
            "description",
            "expected_valid",
            "actual_valid",
            "passed",
            "reasons",
            "timeline_steps",
            "used_evidence_count",
            "unique_used_evidence_count",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_single_output_report(output_json: Path, result: Dict[str, Any], output_csv: Path) -> None:
    """Write validation result for one LLM output to llm_eval_report.csv."""
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "output_json": str(output_json),
        "is_valid": result.get("is_valid", False),
        "reasons": ";".join(result.get("reasons", [])),
        "timeline_steps": result.get("timeline_steps", 0),
        "used_evidence_count": result.get("used_evidence_count", 0),
        "unique_used_evidence_count": result.get("unique_used_evidence_count", 0),
    }
    with output_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        writer.writeheader()
        writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, help="Validate one LLM output JSON/text file")
    parser.add_argument("--attack-tests", type=Path, help="Run validator attack tests JSON")
    parser.add_argument("--report", type=Path, default=Path("report/llm_eval_report.csv"))
    args = parser.parse_args()

    if args.attack_tests:
        run_attack_tests(args.attack_tests, args.evidence, args.report)
        print(f"wrote {args.report}")
    elif args.output_json:
        valid_ids = load_evidence_ids(args.evidence)
        text = args.output_json.read_text(encoding="utf-8-sig")
        result = validate_timeline_output(text, valid_ids)
        write_single_output_report(args.output_json, result, args.report)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        print(f"wrote {args.report}")
    else:
        parser.error("Provide either --output-json or --attack-tests")


if __name__ == "__main__":
    main()
