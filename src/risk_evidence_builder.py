"""
Risk Tagging + Evidence Construction Builder

Purpose
-------
Build data/processed/team_evidence_v2.json from:
1. data/processed/team_events_masked_v2.csv
2. rules/risk_rules_v2.yml

This script performs deterministic risk tagging and evidence construction.
It does NOT call the isolated classifier and does NOT call the main LLM.

Typical usage
-------------
python src/risk_evidence_builder.py ^
  --events data/processed/team_events_masked_v2.csv ^
  --rules rules/risk_rules_v2.yml ^
  --output data/processed/team_evidence_v2.json

Optional:
python src/risk_evidence_builder.py ^
  --events data/processed/team_events_masked_v2.csv ^
  --rules rules/risk_rules_v2.yml ^
  --output data/processed/team_evidence_v2_classifier_output_empty.json ^
  --empty-classifier-output
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd


DEFAULT_RULES = {
    "event_type_rules": {
        "login_failed": {
            "risk_tags": ["login_failed"],
            "risk_score": 0.25,
            "mitre_tactic_hint": "Credential Access",
        },
        "login_success": {
            "risk_tags": ["login_success"],
            "risk_score": 0.2,
            "mitre_tactic_hint": "Initial Access",
        },
        "process_execution": {
            "risk_tags": [],
            "risk_score": 0.0,
            "mitre_tactic_hint": "Execution",
        },
        "file_access": {
            "risk_tags": [],
            "risk_score": 0.0,
            "mitre_tactic_hint": "Collection",
        },
        "network_connection": {
            "risk_tags": [],
            "risk_score": 0.0,
            "mitre_tactic_hint": "Command and Control",
        },
        "web_request": {
            "risk_tags": [],
            "risk_score": 0.0,
            "mitre_tactic_hint": "Unknown",
        },
        "app_error": {
            "risk_tags": [],
            "risk_score": 0.0,
            "mitre_tactic_hint": "Unknown",
        },
    },
    "tag_scores": {
        "raw_text_suppressed": 0.0,
        "query_values_suppressed": 0.05,
        "raw_path_suppressed": 0.05,
        "secret_detected": 0.45,
        "possible_prompt_injection": 0.7,
        "encoded_payload": 0.55,
        "suspicious_command": 0.45,
        "suspicious_powershell": 0.5,
        "sensitive_file_access": 0.5,
        "external_connection": 0.35,
        "credential_request": 0.65,
        "phishing_like": 0.65,
        "brute_force_login": 0.5,
        "successful_after_failures": 0.65,
    },
    "mitre_by_tag": {
        "possible_prompt_injection": "Defense Evasion",
        "secret_detected": "Credential Access",
        "encoded_payload": "Execution",
        "suspicious_powershell": "Execution",
        "suspicious_command": "Execution",
        "sensitive_file_access": "Collection",
        "external_connection": "Command and Control",
        "credential_request": "Credential Access",
        "phishing_like": "Initial Access",
        "brute_force_login": "Credential Access",
        "successful_after_failures": "Initial Access",
    },
}


SUSPICIOUS_COMMAND_HINTS = [
    "powershell",
    "cmd",
    "download_or_web_request",
    "encoded_payload",
    "credential_access_tooling",
    "account_or_privilege_change",
    "secret_pattern_present",
    "instruction_like_text_present",
]

SENSITIVE_FILE_HINTS = [
    "sensitive_file_indicator",
    ".env",
    "id_rsa",
    "shadow",
    "sam",
    "ntds",
    "credential",
    "password",
]

EXTERNAL_IP_ALIAS_RE = re.compile(r"^IP_\d{3}$")


def load_yaml_like_rules(path: Optional[Path]) -> Dict[str, Any]:
    """
    Load YAML rules when PyYAML is available.
    If the file is missing or YAML parsing fails, fall back to DEFAULT_RULES.

    The script is intentionally robust so the pipeline can still run during demos.
    """
    if path is None or not path.exists():
        return DEFAULT_RULES

    try:
        import yaml  # type: ignore

        with path.open("r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f) or {}

        if not isinstance(loaded, dict):
            return DEFAULT_RULES

        return merge_rules(DEFAULT_RULES, loaded)

    except Exception:
        return DEFAULT_RULES


def merge_rules(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Shallow/deep merge for common rule sections.
    User-provided rules override defaults without requiring every section.
    """
    merged = json.loads(json.dumps(base))

    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key].update(value)
        else:
            merged[key] = value

    return merged


def clean_value(value: Any) -> str:
    if value is None:
        return ""
    if pd.isna(value):
        return ""
    return str(value).strip()


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    text = clean_value(value).lower()
    return text in {"true", "1", "yes", "y"}


def parse_tags(value: Any) -> List[str]:
    """
    Parse preprocess_tags from common forms:
    - "tag1|tag2"
    - "tag1,tag2"
    - "['tag1', 'tag2']"
    - JSON list
    """
    if value is None or pd.isna(value):
        return []

    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]

    text = str(value).strip()
    if not text:
        return []

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(x).strip() for x in parsed if str(x).strip()]
    except Exception:
        pass

    text = text.strip("[]")
    text = text.replace("'", "").replace('"', "")

    if "|" in text:
        parts = text.split("|")
    else:
        parts = text.split(",")

    return [part.strip() for part in parts if part.strip()]


def add_unique(tags: List[str], tag: str) -> None:
    if tag and tag not in tags:
        tags.append(tag)


def infer_text_features(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build deterministic text_features from masked event columns.

    This does not recover or forward raw text. It only uses sanitized columns and flags.
    """
    url_path_template = clean_value(row.get("url_path_template"))
    query_param_names_text = clean_value(row.get("query_param_names"))

    query_param_names: List[str] = []
    if query_param_names_text:
        try:
            parsed = json.loads(query_param_names_text)
            if isinstance(parsed, list):
                query_param_names = [str(x) for x in parsed]
            else:
                query_param_names = [query_param_names_text]
        except Exception:
            query_param_names = [
                part.strip()
                for part in query_param_names_text.replace("|", ",").split(",")
                if part.strip()
            ]

    command_summary = clean_value(row.get("sanitized_command_summary") or row.get("command_line"))
    file_summary = clean_value(row.get("sanitized_file_summary") or row.get("file_path"))
    safe_text = " ".join(
        x
        for x in [
            clean_value(row.get("event_type")),
            url_path_template,
            command_summary,
            file_summary,
            clean_value(row.get("preprocess_tags")),
        ]
        if x
    )

    contains_url = bool(url_path_template)
    has_instruction_like_words = (
        "{instruction_like_segment}" in url_path_template
        or parse_bool(row.get("contains_instruction_like_words"))
        or "possible_prompt_injection" in parse_tags(row.get("preprocess_tags"))
        or "instruction_like_text_present" in command_summary
    )

    contains_secret_pattern = (
        parse_bool(row.get("contains_secret_pattern"))
        or "secret_detected" in parse_tags(row.get("preprocess_tags"))
        or "secret_pattern_present" in command_summary
        or "secret_pattern_present" in file_summary
    )

    encoded_text_detected = (
        "encoded_payload" in parse_tags(row.get("preprocess_tags"))
        or "encoded_payload" in command_summary
        or "encodedcommand" in command_summary.lower()
    )

    has_credential_terms = any(
        term in safe_text.lower()
        for term in ["credential", "password", "token", "mfa", "login", "account verification"]
    )

    has_urgent_words = any(
        term in safe_text.lower()
        for term in ["urgent", "immediately", "suspended", "verify now", "within 24 hours"]
    )

    return {
        "contains_url": contains_url,
        "url_count": 1 if contains_url else 0,
        "query_param_names": query_param_names,
        "query_values_forwarded": parse_bool(row.get("query_values_forwarded")),
        "url_path_template": url_path_template,
        "url_path_templated": any(
            marker in url_path_template
            for marker in [
                "{numeric_segment}",
                "{uuid_segment}",
                "{hex_segment}",
                "{long_text_segment}",
                "{instruction_like_segment}",
                "{command_like_segment}",
            ]
        ),
        "has_urgent_words": has_urgent_words,
        "has_credential_terms": has_credential_terms,
        "has_instruction_like_words": has_instruction_like_words,
        "encoded_text_detected": encoded_text_detected,
        "contains_secret_pattern": contains_secret_pattern,
        "text_length": len(safe_text),
        "language_hint": "zh" if re.search(r"[\u4e00-\u9fff]", safe_text) else "en",
        "raw_text_forwarded": parse_bool(row.get("raw_message_forwarded")),
        "raw_text_suppressed": not parse_bool(row.get("raw_message_forwarded")),
        "raw_path_forwarded": parse_bool(row.get("raw_path_forwarded")),
        "raw_path_suppressed": parse_bool(row.get("raw_path_suppressed")),
    }


def apply_risk_rules(
    row: Dict[str, Any],
    text_features: Dict[str, Any],
    rules: Dict[str, Any],
    login_failure_counts: Dict[Tuple[str, str], int],
) -> Tuple[List[str], float, str]:
    event_type = clean_value(row.get("event_type"))
    base_rule = rules.get("event_type_rules", {}).get(event_type, {})

    risk_tags: List[str] = []
    for tag in base_rule.get("risk_tags", []):
        add_unique(risk_tags, str(tag))

    for tag in parse_tags(row.get("preprocess_tags")):
        add_unique(risk_tags, tag)

    command_summary = clean_value(row.get("sanitized_command_summary") or row.get("command_line")).lower()
    file_summary = clean_value(row.get("sanitized_file_summary") or row.get("file_path")).lower()
    dst_ip = clean_value(row.get("dst_ip") or row.get("dst_ip_alias"))

    if event_type == "login_failed":
        add_unique(risk_tags, "login_failed")
        user = clean_value(row.get("user") or row.get("user_alias"))
        src_ip = clean_value(row.get("src_ip") or row.get("src_ip_alias"))
        key = (user, src_ip)
        if login_failure_counts.get(key, 0) >= 5:
            add_unique(risk_tags, "brute_force_login")

    if event_type == "login_success":
        add_unique(risk_tags, "login_success")
        user = clean_value(row.get("user") or row.get("user_alias"))
        src_ip = clean_value(row.get("src_ip") or row.get("src_ip_alias"))
        key = (user, src_ip)
        if login_failure_counts.get(key, 0) >= 5:
            add_unique(risk_tags, "successful_after_failures")

    if event_type == "process_execution":
        if any(hint in command_summary for hint in SUSPICIOUS_COMMAND_HINTS):
            add_unique(risk_tags, "suspicious_command")
        if "powershell" in command_summary:
            add_unique(risk_tags, "suspicious_powershell")
        if text_features.get("encoded_text_detected"):
            add_unique(risk_tags, "encoded_payload")

    if event_type == "file_access":
        if any(hint in file_summary for hint in SENSITIVE_FILE_HINTS):
            add_unique(risk_tags, "sensitive_file_access")

    if event_type == "network_connection":
        if dst_ip and EXTERNAL_IP_ALIAS_RE.match(dst_ip):
            add_unique(risk_tags, "external_connection")

    if text_features.get("contains_secret_pattern"):
        add_unique(risk_tags, "secret_detected")

    if text_features.get("has_instruction_like_words"):
        add_unique(risk_tags, "possible_prompt_injection")

    if text_features.get("has_credential_terms"):
        add_unique(risk_tags, "credential_request")

    if text_features.get("has_urgent_words") and text_features.get("contains_url"):
        add_unique(risk_tags, "phishing_like")

    base_score = float(base_rule.get("risk_score", 0.0) or 0.0)
    tag_scores = rules.get("tag_scores", {})
    score = base_score

    for tag in risk_tags:
        try:
            score += float(tag_scores.get(tag, 0.0) or 0.0)
        except Exception:
            pass

    score = min(round(score, 2), 1.0)

    mitre_hint = clean_value(base_rule.get("mitre_tactic_hint")) or "Unknown"
    mitre_by_tag = rules.get("mitre_by_tag", {})

    # Prefer higher-signal tags for MITRE hint.
    priority_tags = [
        "possible_prompt_injection",
        "secret_detected",
        "encoded_payload",
        "suspicious_powershell",
        "suspicious_command",
        "sensitive_file_access",
        "external_connection",
        "credential_request",
        "phishing_like",
        "successful_after_failures",
        "brute_force_login",
    ]

    for tag in priority_tags:
        if tag in risk_tags and tag in mitre_by_tag:
            mitre_hint = str(mitre_by_tag[tag])
            break

    return risk_tags, score, mitre_hint


def build_safe_summary(row: Dict[str, Any], risk_tags: List[str], risk_score: float, mitre_hint: str) -> str:
    event_id = clean_value(row.get("event_id"))
    event_type = clean_value(row.get("event_type"))
    host = clean_value(row.get("host") or row.get("host_alias"))
    user = clean_value(row.get("user") or row.get("user_alias"))

    if "brute_force_login" in risk_tags:
        return (
            f"Event {event_id} is part of a repeated failed-login pattern for {user}. "
            "The event was marked as brute_force_login without forwarding raw authentication text."
        )

    if "successful_after_failures" in risk_tags:
        return (
            f"Event {event_id} is a successful login after multiple previous failed attempts for {user}. "
            "This suggests a possible account compromise sequence."
        )

    if "suspicious_command" in risk_tags or "suspicious_powershell" in risk_tags:
        return (
            f"Event {event_id} shows suspicious command execution on {host} by {user}. "
            "The original command line was sanitized before LLM input."
        )

    if "sensitive_file_access" in risk_tags:
        return (
            f"Event {event_id} is a file access event on {host} matching sensitive file indicators. "
            "The original file path was not forwarded to the main LLM."
        )

    if "external_connection" in risk_tags:
        return (
            f"Event {event_id} is a network connection event involving {host}. "
            "The event was summarized without exposing raw network logs."
        )

    if "possible_prompt_injection" in risk_tags:
        return (
            f"Event {event_id} contains instruction-like or prompt-injection-like indicators in sanitized features. "
            "The raw untrusted text was not forwarded."
        )

    if "secret_detected" in risk_tags:
        return (
            f"Event {event_id} contains a secret-like pattern detected by deterministic preprocessing. "
            "The secret value was not forwarded."
        )

    return (
        f"Event {event_id} is a {event_type} event involving {user} on {host}. "
        f"Risk tags were assigned from deterministic features. MITRE tactic hint: {mitre_hint}."
    )


def count_login_failures(df: pd.DataFrame) -> Dict[Tuple[str, str], int]:
    counts: Dict[Tuple[str, str], int] = {}

    for _, row in df.iterrows():
        event_type = clean_value(row.get("event_type"))
        if event_type != "login_failed":
            continue

        user = clean_value(row.get("user") or row.get("user_alias"))
        src_ip = clean_value(row.get("src_ip") or row.get("src_ip_alias"))
        key = (user, src_ip)
        counts[key] = counts.get(key, 0) + 1

    return counts


def build_evidence_records(
    events_csv: Path,
    rules_path: Optional[Path],
    empty_classifier_output: bool = True,
) -> List[Dict[str, Any]]:
    df = pd.read_csv(events_csv, dtype=str).fillna("")
    rules = load_yaml_like_rules(rules_path)
    login_failure_counts = count_login_failures(df)

    records: List[Dict[str, Any]] = []

    for _, row_series in df.iterrows():
        row = row_series.to_dict()

        text_features = infer_text_features(row)
        risk_tags, risk_score, mitre_hint = apply_risk_rules(
            row=row,
            text_features=text_features,
            rules=rules,
            login_failure_counts=login_failure_counts,
        )

        event_id = clean_value(row.get("event_id"))

        record = {
            "event_id": event_id,
            "timestamp": clean_value(row.get("timestamp")),
            "event_type": clean_value(row.get("event_type")),
            "host": clean_value(row.get("host") or row.get("host_alias")),
            "user": clean_value(row.get("user") or row.get("user_alias")),
            "src_ip": clean_value(row.get("src_ip") or row.get("src_ip_alias")),
            "dst_ip": clean_value(row.get("dst_ip") or row.get("dst_ip_alias")),
            "risk_tags": risk_tags,
            "risk_score": risk_score,
            "mitre_tactic_hint": mitre_hint,
            "safe_summary": build_safe_summary(row, risk_tags, risk_score, mitre_hint),
            "text_features": text_features,
        }

        if empty_classifier_output:
            record["classifier_output"] = {}
            record["classifier_validation"] = {
                "is_valid": False,
                "reasons": ["classifier_output_pending"],
                "action": "pending_isolated_classifier",
            }
        else:
            record["classifier_output"] = {
                "intent_category": "unknown",
                "contains_request_for_credentials": False,
                "contains_instruction_to_model": False,
            }
            record["classifier_validation"] = {
                "is_valid": False,
                "reasons": ["classifier_output_not_validated"],
                "action": "requires_classifier_validation",
            }

        records.append(record)

    return records


def write_json(data: Any, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def write_risk_eval_report(records: List[Dict[str, Any]], output_path: Path) -> None:
    rows = []

    for record in records:
        rows.append(
            {
                "event_id": record["event_id"],
                "event_type": record["event_type"],
                "risk_tags": "|".join(record["risk_tags"]),
                "risk_score": record["risk_score"],
                "mitre_tactic_hint": record["mitre_tactic_hint"],
            }
        )

    pd.DataFrame(rows).to_csv(output_path, index=False, encoding="utf-8-sig")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build team_evidence_v2.json from masked events and risk rules."
    )
    parser.add_argument(
        "--events",
        type=Path,
        required=True,
        help="Path to data/processed/team_events_masked_v2.csv.",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=Path("rules/risk_rules_v2.yml"),
        help="Path to rules/risk_rules_v2.yml.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed/team_evidence_v2.json"),
        help="Output evidence JSON path.",
    )
    parser.add_argument(
        "--risk-report",
        type=Path,
        default=None,
        help="Optional output CSV for risk_tag_eval_report.csv.",
    )
    parser.add_argument(
        "--empty-classifier-output",
        action="store_true",
        help="Write classifier_output as {} and mark classifier_validation as pending.",
    )

    args = parser.parse_args()

    records = build_evidence_records(
        events_csv=args.events,
        rules_path=args.rules,
        empty_classifier_output=args.empty_classifier_output,
    )

    write_json(records, args.output)

    if args.risk_report:
        write_risk_eval_report(records, args.risk_report)

    print(f"wrote {args.output}")
    print(f"records={len(records)}")

    if args.risk_report:
        print(f"wrote {args.risk_report}")

    high_risk_count = sum(1 for r in records if float(r.get("risk_score", 0.0)) >= 0.7)
    prompt_like_count = sum(1 for r in records if "possible_prompt_injection" in r.get("risk_tags", []))
    secret_count = sum(1 for r in records if "secret_detected" in r.get("risk_tags", []))

    print(f"high_risk_count={high_risk_count}")
    print(f"prompt_like_count={prompt_like_count}")
    print(f"secret_detected_count={secret_count}")


if __name__ == "__main__":
    main()
