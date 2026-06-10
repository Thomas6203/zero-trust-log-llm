#!/usr/bin/env python3
"""Generate v2 evaluation artifacts from existing project files.

This script does not invent LLM metrics. It computes sanitizer, feature extractor,
and validator reports from the CSV/JSON files present in the repository. For
llm_eval_report.csv, it evaluates real LLM output files only if they exist.
"""
from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "processed"
SRC = ROOT / "src"

sys.path.insert(0, str(SRC))
from feature_extractor import extract_text_features  # noqa: E402
from validator_v2 import load_evidence_ids, validate_timeline_output  # noqa: E402


def str_to_bool(v: Any) -> bool:
    return str(v).strip().lower() == "true"


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def load_adversarial_tests() -> List[Dict[str, str]]:
    path = DATA / "adversarial_sanitization_tests.csv"
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def generate_sanitization_eval() -> None:
    rows: List[Dict[str, Any]] = []
    tests = load_adversarial_tests()
    for t in tests:
        features = extract_text_features(t["raw_input"], t.get("source", "raw_message"))
        checks = {
            "raw_text_not_forwarded": features["raw_text_forwarded"] == str_to_bool(t["expected_raw_text_forwarded"]),
            "query_values_not_forwarded": features["query_values_forwarded"] == str_to_bool(t["expected_query_values_forwarded"]),
            "raw_path_not_forwarded": features["raw_path_forwarded"] == str_to_bool(t["expected_raw_path_forwarded"]),
        }
        rows.append({
            "case_id": t["case_id"],
            "source": t["source"],
            "description": t["description"],
            "raw_text_forwarded": features["raw_text_forwarded"],
            "query_values_forwarded": features["query_values_forwarded"],
            "raw_path_forwarded": features["raw_path_forwarded"],
            "raw_text_suppressed": features["raw_text_suppressed"],
            "raw_path_suppressed": features["raw_path_suppressed"],
            "passed": all(checks.values()),
            "failed_checks": ";".join(k for k, ok in checks.items() if not ok),
        })
    write_csv(DATA / "sanitization_eval_report.csv", rows)


def generate_feature_reports() -> None:
    test_feature_rows: List[Dict[str, Any]] = []
    eval_rows: List[Dict[str, Any]] = []
    tests = load_adversarial_tests()
    for t in tests:
        features = extract_text_features(t["raw_input"], t.get("source", "raw_message"))
        test_feature_rows.append({
            "case_id": t["case_id"],
            "source": t["source"],
            "description": t["description"],
            "text_features": features,
        })
        expected_map = {
            "contains_secret_pattern": str_to_bool(t["expected_contains_secret_pattern"]),
            "has_instruction_like_words": str_to_bool(t["expected_has_instruction_like_words"]),
            "has_credential_terms": str_to_bool(t["expected_has_credential_terms"]),
            "contains_url": str_to_bool(t["expected_contains_url"]),
        }
        mismatches = [k for k, expected in expected_map.items() if bool(features[k]) != expected]
        path_expected = t.get("expected_url_path_template_contains", "")
        if path_expected and path_expected not in features.get("url_path_template", ""):
            mismatches.append("url_path_template")
        eval_rows.append({
            "case_id": t["case_id"],
            "source": t["source"],
            "description": t["description"],
            "passed": len(mismatches) == 0,
            "mismatches": ";".join(mismatches),
            "contains_secret_pattern": features["contains_secret_pattern"],
            "has_instruction_like_words": features["has_instruction_like_words"],
            "has_credential_terms": features["has_credential_terms"],
            "contains_url": features["contains_url"],
            "url_path_template": features["url_path_template"],
        })

    evidence_path = DATA / "team_evidence_v2.json"
    # If the file is not inside this repo copy, also allow running from a folder
    # where the user has placed only the additions and the evidence is one level up.
    if evidence_path.exists():
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence_feature_rows = [
            {
                "event_id": e.get("event_id"),
                "source": "team_evidence_v2.json",
                "event_type": e.get("event_type"),
                "text_features": e.get("text_features", {}),
            }
            for e in evidence
        ]
    else:
        evidence_feature_rows = []

    report = {
        "generated_from": ["adversarial_sanitization_tests.csv"] + (["team_evidence_v2.json"] if evidence_feature_rows else []),
        "adversarial_test_features": test_feature_rows,
        "existing_evidence_features": evidence_feature_rows,
        "summary": {
            "adversarial_test_count": len(test_feature_rows),
            "existing_evidence_count": len(evidence_feature_rows),
            "feature_eval_pass_count": sum(1 for r in eval_rows if r["passed"]),
            "feature_eval_fail_count": sum(1 for r in eval_rows if not r["passed"]),
        },
    }
    (DATA / "text_feature_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    write_csv(DATA / "feature_extraction_eval_report.csv", eval_rows)


def generate_validator_eval() -> None:
    evidence_path = DATA / "team_evidence_v2.json"
    tests_path = DATA / "validator_attack_tests.json"
    out_path = DATA / "validator_eval_report.csv"
    if not evidence_path.exists():
        raise FileNotFoundError(f"Missing {evidence_path}. Copy team_evidence_v2.json to data/processed/ first.")
    subprocess.run([
        sys.executable,
        str(SRC / "validator_v2.py"),
        "--evidence", str(evidence_path),
        "--attack-tests", str(tests_path),
        "--report", str(out_path),
    ], check=True)


def generate_llm_eval() -> None:
    evidence_path = DATA / "team_evidence_v2.json"
    baseline = DATA / "baseline_llm_output_v2.json"
    zero_trust = DATA / "zero_trust_llm_output_v2.json"
    rows: List[Dict[str, Any]] = []

    if not evidence_path.exists():
        rows.append({
            "run_name": "not_run",
            "output_file": "",
            "status": "missing_team_evidence_v2_json",
            "json_valid": "",
            "validator_valid": "",
            "timeline_steps": "",
            "used_evidence_count": "",
            "unique_used_evidence_count": "",
            "reasons": "Copy team_evidence_v2.json to data/processed/ before evaluating LLM outputs.",
        })
        write_csv(DATA / "llm_eval_report.csv", rows)
        return

    valid_ids = load_evidence_ids(evidence_path)
    for run_name, path in [("baseline_v2", baseline), ("zero_trust_v2", zero_trust)]:
        if not path.exists():
            rows.append({
                "run_name": run_name,
                "output_file": str(path.relative_to(ROOT)),
                "status": "not_run_missing_output_file",
                "json_valid": "",
                "validator_valid": "",
                "timeline_steps": "",
                "used_evidence_count": "",
                "unique_used_evidence_count": "",
                "reasons": "Run the corresponding prompt and save its raw JSON output to this file, then rerun scripts/run_v2_reports.py.",
            })
            continue
        text = path.read_text(encoding="utf-8")
        result = validate_timeline_output(text, valid_ids)
        rows.append({
            "run_name": run_name,
            "output_file": str(path.relative_to(ROOT)),
            "status": "evaluated",
            "json_valid": not any(str(r).startswith("invalid_json") for r in result.get("reasons", [])),
            "validator_valid": result["is_valid"],
            "timeline_steps": result.get("timeline_steps", 0),
            "used_evidence_count": result.get("used_evidence_count", 0),
            "unique_used_evidence_count": result.get("unique_used_evidence_count", 0),
            "reasons": ";".join(result.get("reasons", [])),
        })
    write_csv(DATA / "llm_eval_report.csv", rows)


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    generate_sanitization_eval()
    generate_feature_reports()
    generate_validator_eval()
    generate_llm_eval()
    print("Generated v2 reports under data/processed/.")


if __name__ == "__main__":
    main()
