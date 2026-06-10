"""
Apply Classifier Validation Report to team_evidence_v2.json

Purpose
-------
After running classifier_output_validator.py, the validation result is stored in:

data/processed/classifier_validation_report.csv

This script writes the validation status back into each evidence record as:

"classifier_validation": {
  "is_valid": true,
  "is_rejected": false,
  "isolated_classifier_suspicious": false,
  "fallback_to_deterministic_features": false,
  "action": "accept_classifier_output",
  "errors": []
}

It only updates classifier_validation.
It does NOT modify classifier_output, risk_tags, text_features, safe_summary,
or any other evidence fields.

Typical usage
-------------
python src/apply_classifier_validation.py ^
  --evidence data/processed/team_evidence_v2.json ^
  --classifier-report data/processed/classifier_validation_report.csv ^
  --output data/processed/team_evidence_v2.json

Safer usage:
python src/apply_classifier_validation.py ^
  --evidence data/processed/team_evidence_v2.json ^
  --classifier-report data/processed/classifier_validation_report.csv ^
  --output data/processed/team_evidence_v2_validated.json ^
  --strict
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


TRUE_VALUES = {"true", "1", "yes", "y", "t"}
FALSE_VALUES = {"false", "0", "no", "n", "f", ""}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    text = str(value).strip().lower()

    if text in TRUE_VALUES:
        return True

    if text in FALSE_VALUES:
        return False

    return False


def parse_errors(value: Any) -> List[str]:
    text = str(value or "").strip()

    if not text:
        return []

    # classifier_output_validator.py joins errors with semicolon.
    return [part.strip() for part in text.split(";") if part.strip()]


def read_validation_report(path: Path) -> Dict[str, Dict[str, Any]]:
    """
    Read classifier_validation_report.csv and return event_id -> validation object.

    CLS adversarial rows can exist in the report, but they will be ignored later
    because they do not exist in team_evidence_v2.json.
    """
    validation_map: Dict[str, Dict[str, Any]] = {}

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for idx, row in enumerate(reader, start=1):
            event_id = str(row.get("event_id", "")).strip()
            if not event_id:
                continue

            if event_id in validation_map:
                raise ValueError(f"duplicate event_id in classifier report: {event_id}")

            is_valid = parse_bool(row.get("classifier_output_valid") or row.get("is_valid"))
            is_rejected = parse_bool(row.get("classifier_output_rejected"))
            suspicious = parse_bool(row.get("isolated_classifier_suspicious"))
            fallback = parse_bool(row.get("fallback_to_deterministic_features"))

            action = str(row.get("action", "")).strip()
            errors = parse_errors(row.get("errors"))

            validation_map[event_id] = {
                "is_valid": is_valid,
                "is_rejected": is_rejected,
                "isolated_classifier_suspicious": suspicious,
                "fallback_to_deterministic_features": fallback,
                "action": action,
                "errors": errors,
            }

    return validation_map


def apply_validation(
    evidence_records: List[Dict[str, Any]],
    validation_map: Dict[str, Dict[str, Any]],
    strict: bool = False,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if not isinstance(evidence_records, list):
        raise ValueError("evidence file must be a JSON array")

    evidence_ids: Set[str] = set()
    updated_records: List[Dict[str, Any]] = []
    updated_count = 0
    missing_in_report: List[str] = []

    for idx, record in enumerate(evidence_records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"evidence row {idx} is not an object")

        event_id = str(record.get("event_id", "")).strip()
        if not event_id:
            raise ValueError(f"evidence row {idx} has missing event_id")

        if event_id in evidence_ids:
            raise ValueError(f"duplicate event_id in evidence file: {event_id}")

        evidence_ids.add(event_id)

        new_record = dict(record)

        if event_id in validation_map:
            new_record["classifier_validation"] = validation_map[event_id]
            updated_count += 1
        else:
            missing_in_report.append(event_id)
            new_record["classifier_validation"] = {
                "is_valid": False,
                "is_rejected": True,
                "isolated_classifier_suspicious": True,
                "fallback_to_deterministic_features": True,
                "action": "reject_missing_classifier_validation",
                "errors": ["missing_classifier_validation_report_row"],
            }

        updated_records.append(new_record)

    report_ids = set(validation_map.keys())
    extra_report_ids = sorted(report_ids - evidence_ids)
    missing_in_report = sorted(missing_in_report)

    if strict and missing_in_report:
        raise ValueError(
            "classifier report missing evidence event_id(s): "
            + ", ".join(missing_in_report)
        )

    summary = {
        "evidence_count": len(evidence_records),
        "validation_report_count": len(validation_map),
        "updated_count": updated_count,
        "missing_in_report_count": len(missing_in_report),
        "extra_report_ids_count": len(extra_report_ids),
        "missing_in_report": missing_in_report,
        "extra_report_ids": extra_report_ids,
    }

    return updated_records, summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Write classifier_validation_report.csv results back into evidence JSON."
    )
    parser.add_argument(
        "--evidence",
        type=Path,
        required=True,
        help="Path to data/processed/team_evidence_v2.json.",
    )
    parser.add_argument(
        "--classifier-report",
        type=Path,
        required=True,
        help="Path to data/processed/classifier_validation_report.csv.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output evidence JSON path.",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="Optional output summary JSON path.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if classifier report is missing any evidence event_id.",
    )

    args = parser.parse_args()

    evidence_records = load_json(args.evidence)
    validation_map = read_validation_report(args.classifier_report)

    updated_records, summary = apply_validation(
        evidence_records=evidence_records,
        validation_map=validation_map,
        strict=args.strict,
    )

    write_json(updated_records, args.output)

    if args.summary:
        write_json(summary, args.summary)

    print(f"wrote {args.output}")
    print(f"evidence_count={summary['evidence_count']}")
    print(f"validation_report_count={summary['validation_report_count']}")
    print(f"updated_count={summary['updated_count']}")
    print(f"missing_in_report_count={summary['missing_in_report_count']}")
    print(f"extra_report_ids_count={summary['extra_report_ids_count']}")

    if args.summary:
        print(f"wrote {args.summary}")


if __name__ == "__main__":
    main()
