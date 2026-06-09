#!/usr/bin/env python3
"""
Zero-Trust Log-to-LLM Sanitizer v2

Generate data/processed/team_events_masked_v2.csv from
 data/processed/team_events_raw.csv

This file is intentionally deterministic so the sanitized dataset is
reproducible and not treated as a manually edited CSV.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import re
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
from urllib.parse import parse_qsl, urlparse

import pandas as pd

BASE_COLUMNS = [
    "event_id",
    "timestamp",
    "source",
    "host",
    "user",
    "src_ip",
    "dst_ip",
    "event_type",
    "url",
    "command_line",
    "file_path",
    "raw_message",
    "ground_truth_stage",
]

V2_COLUMNS = [
    "host_alias",
    "user_alias",
    "src_ip_alias",
    "dst_ip_alias",
    "url_path_template",
    "query_param_names",
    "query_values_forwarded",
    "raw_message_forwarded",
    "raw_path_forwarded",
    "raw_path_suppressed",
    "command_line_forwarded",
    "file_path_forwarded",
    "sanitized_command_summary",
    "sanitized_file_summary",
    "contains_secret_pattern",
    "contains_instruction_like_words",
    "preprocess_tags",
]

SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|cookie)\b\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)\bsk-[A-Za-z0-9]{8,}"),
    re.compile(r"(?i)\bAKIA[0-9A-Z]{12,}\b"),
    re.compile(r"(?i)\b[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
]

INSTRUCTION_LIKE_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(all\s+)?previous\s+instructions?\b"),
    re.compile(r"(?i)\breveal\s+(all\s+)?(secrets?|system\s+prompt|passwords?|tokens?)\b"),
    re.compile(r"(?i)\bdisregard\s+(the\s+)?(rules?|instructions?)\b"),
    re.compile(r"(?i)\bprint\s+(the\s+)?(system\s+prompt|hidden\s+prompt|secrets?)\b"),
    re.compile(r"(?i)\byou\s+are\s+now\b"),
    re.compile(r"(?i)\bdeveloper\s+message\b"),
    re.compile(r"(?i)\bsystem\s+message\b"),
    re.compile(r"(?i)\bdo\s+not\s+follow\s+(the\s+)?rules\b"),
    re.compile(r"請忽略"),
    re.compile(r"忽略前面"),
    re.compile(r"輸出所有資料"),
    re.compile(r"洩漏"),
]

BASE64_LIKE = re.compile(r"(?i)(?:-enc|-encodedcommand|frombase64string|[A-Za-z0-9+/]{40,}={0,2})")


def clean_cell(value: object) -> str:
    """Convert NaN/None to empty string and strip whitespace."""
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except TypeError:
        pass
    return str(value).strip()


def has_secret(text: str) -> bool:
    return any(pattern.search(text or "") for pattern in SECRET_PATTERNS)


def has_instruction_like_text(text: str) -> bool:
    return any(pattern.search(text or "") for pattern in INSTRUCTION_LIKE_PATTERNS)


def first_seen_alias(values: Iterable[str], prefix: str) -> Dict[str, str]:
    """Build stable aliases by first appearance in the dataset."""
    mapping: Dict[str, str] = {}
    counter = 1
    for value in values:
        value = clean_cell(value)
        if not value:
            continue
        if value not in mapping:
            mapping[value] = f"{prefix}_{counter:03d}"
            counter += 1
    return mapping


def is_public_ip(value: str) -> bool:
    value = clean_cell(value)
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def template_path_segment(segment: str) -> str:
    raw = segment.strip()
    lower = raw.lower()

    if not raw:
        return ""
    if re.fullmatch(r"\d+", raw):
        return "{numeric_segment}"
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", raw):
        return "{uuid_segment}"
    if re.fullmatch(r"[0-9a-fA-F]{16,}", raw):
        return "{hex_segment}"
    if len(raw) >= 24 and re.search(r"[A-Za-z]", raw) and re.search(r"\d", raw):
        return "{long_text_segment}"

    instruction_words = [
        "ignore", "previous", "instruction", "instructions", "reveal",
        "secret", "secrets", "system", "prompt", "password", "token",
    ]
    if any(word in lower for word in instruction_words):
        return "{instruction_like_segment}"

    if re.search(r"(?i)(powershell|cmd|bash|wget|curl|base64|encodedcommand)", raw):
        return "{command_like_segment}"

    return raw


def template_url_path(url: str) -> Tuple[str, bool, bool]:
    """Return path_template, path_was_templated, raw_path_suppressed."""
    url = clean_cell(url)
    if not url:
        return "", False, False

    parsed = urlparse(url)
    raw_path = parsed.path or ""
    if not raw_path and url.startswith("/"):
        raw_path = url.split("?", 1)[0]
    if not raw_path:
        return "", False, False

    segments = [seg for seg in raw_path.split("/") if seg]
    templated_segments = [template_path_segment(seg) for seg in segments]
    template = "/" + "/".join(templated_segments) if templated_segments else "/"
    return template, segments != templated_segments, True


def extract_query_param_names(url: str) -> List[str]:
    """Keep query parameter names only. Query values are never forwarded."""
    url = clean_cell(url)
    if not url:
        return []

    parsed = urlparse(url)
    query = parsed.query
    if not query and "?" in url:
        query = url.split("?", 1)[1]

    names: List[str] = []
    for key, _ in parse_qsl(query, keep_blank_values=True):
        if key and key not in names:
            names.append(key)
    return names


def summarize_command(command_line: str) -> str:
    text = clean_cell(command_line)
    if not text:
        return ""

    lower = text.lower()
    hints: List[str] = []
    if "powershell" in lower or "pwsh" in lower:
        hints.append("powershell")
    if "cmd.exe" in lower or lower.startswith("cmd "):
        hints.append("cmd")
    if "curl" in lower or "wget" in lower or "invoke-webrequest" in lower:
        hints.append("download_or_web_request")
    if "-enc" in lower or "-encodedcommand" in lower or BASE64_LIKE.search(text):
        hints.append("encoded_payload")
    if "net user" in lower or "add-localgroupmember" in lower:
        hints.append("account_or_privilege_change")
    if "mimikatz" in lower or "sekurlsa" in lower:
        hints.append("credential_access_tooling")
    if has_secret(text):
        hints.append("secret_pattern_present")
    if has_instruction_like_text(text):
        hints.append("instruction_like_text_present")
    if not hints:
        hints.append("command_observed")
    return "command_summary:" + ";".join(sorted(set(hints)))


def summarize_file_path(file_path: str) -> str:
    text = clean_cell(file_path)
    if not text:
        return ""

    lower = text.lower()
    hints: List[str] = []
    if any(term in lower for term in [".env", "id_rsa", "shadow", "sam", "ntds.dit", "credentials", "password"]):
        hints.append("sensitive_file_indicator")
    suffix = Path(text).suffix.lower().replace(".", "")
    if suffix:
        hints.append(f"file_extension_{suffix}")
    if has_secret(text):
        hints.append("secret_pattern_present")
    if not hints:
        hints.append("file_access_observed")
    return "file_summary:" + ";".join(sorted(set(hints)))


def build_preprocess_tags(
    raw_message: str,
    url: str,
    command_line: str,
    file_path: str,
    query_param_names: List[str],
    path_template: str,
    raw_path_suppressed: bool,
) -> List[str]:
    tags: List[str] = []
    if raw_message:
        tags.append("raw_text_suppressed")
    if query_param_names:
        tags.append("query_values_suppressed")
    if raw_path_suppressed:
        tags.append("raw_path_suppressed")

    combined = " ".join([raw_message, url, command_line, file_path])
    if has_secret(combined):
        tags.append("secret_detected")
    if has_instruction_like_text(combined) or "{instruction_like_segment}" in path_template:
        tags.append("possible_prompt_injection")
        tags.append("untrusted_user_text")
    if BASE64_LIKE.search(combined):
        tags.append("encoded_payload")

    return sorted(set(tags))


def sanitize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Sanitize a raw event dataframe and return the v2 masked dataframe."""
    for col in BASE_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    df = df.copy()
    for col in df.columns:
        df[col] = df[col].map(clean_cell)

    host_map = first_seen_alias(df["host"], "HOST")
    user_map = first_seen_alias(df["user"], "USER")
    ip_map = first_seen_alias(list(df["src_ip"]) + list(df["dst_ip"]), "IP")

    output_rows = []
    for _, row in df.iterrows():
        raw_message = clean_cell(row.get("raw_message", ""))
        url = clean_cell(row.get("url", ""))
        command_line = clean_cell(row.get("command_line", ""))
        file_path = clean_cell(row.get("file_path", ""))

        host_alias = host_map.get(clean_cell(row.get("host", "")), "")
        user_alias = user_map.get(clean_cell(row.get("user", "")), "")
        src_ip_alias = ip_map.get(clean_cell(row.get("src_ip", "")), "")
        dst_ip_alias = ip_map.get(clean_cell(row.get("dst_ip", "")), "")

        path_template, _path_templated, raw_path_suppressed = template_url_path(url)
        query_names = extract_query_param_names(url)
        combined_text = " ".join([raw_message, url, command_line, file_path])

        preprocess_tags = build_preprocess_tags(
            raw_message=raw_message,
            url=url,
            command_line=command_line,
            file_path=file_path,
            query_param_names=query_names,
            path_template=path_template,
            raw_path_suppressed=raw_path_suppressed,
        )

        out = row.to_dict()

        # Replace sensitive raw values with safe aliases/summaries.
        out["host"] = host_alias
        out["user"] = user_alias
        out["src_ip"] = src_ip_alias
        out["dst_ip"] = dst_ip_alias
        out["url"] = path_template
        out["command_line"] = summarize_command(command_line)
        out["file_path"] = summarize_file_path(file_path)
        out["raw_message"] = "[RAW_MESSAGE_SUPPRESSED]" if raw_message else ""

        out["host_alias"] = host_alias
        out["user_alias"] = user_alias
        out["src_ip_alias"] = src_ip_alias
        out["dst_ip_alias"] = dst_ip_alias
        out["url_path_template"] = path_template
        out["query_param_names"] = ",".join(query_names)
        out["query_values_forwarded"] = False
        out["raw_message_forwarded"] = False
        out["raw_path_forwarded"] = False
        out["raw_path_suppressed"] = raw_path_suppressed
        out["command_line_forwarded"] = False
        out["file_path_forwarded"] = False
        out["sanitized_command_summary"] = summarize_command(command_line)
        out["sanitized_file_summary"] = summarize_file_path(file_path)
        out["contains_secret_pattern"] = has_secret(combined_text)
        out["contains_instruction_like_words"] = has_instruction_like_text(combined_text) or (
            "{instruction_like_segment}" in path_template
        )
        out["preprocess_tags"] = ";".join(preprocess_tags)

        output_rows.append(out)

    out_df = pd.DataFrame(output_rows)

    ordered_cols: List[str] = []
    for col in BASE_COLUMNS + V2_COLUMNS:
        if col in out_df.columns and col not in ordered_cols:
            ordered_cols.append(col)
    for col in out_df.columns:
        if col not in ordered_cols:
            ordered_cols.append(col)

    return out_df[ordered_cols]


def sanitize_file(input_path: Path, output_path: Path) -> pd.DataFrame:
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    df = pd.read_csv(input_path, dtype=str, keep_default_na=False)
    out_df = sanitize_dataframe(df)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(output_path, index=False, quoting=csv.QUOTE_MINIMAL)
    return out_df


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate team_events_masked_v2.csv from team_events_raw.csv")
    parser.add_argument("--input", default="data/processed/team_events_raw.csv", help="Input raw event CSV path")
    parser.add_argument("--output", default="data/processed/team_events_masked_v2.csv", help="Output sanitized CSV path")
    args = parser.parse_args()

    out_df = sanitize_file(Path(args.input), Path(args.output))

    raw_forwarded = int(out_df["raw_message_forwarded"].astype(str).str.lower().eq("true").sum())
    query_forwarded = int(out_df["query_values_forwarded"].astype(str).str.lower().eq("true").sum())
    secret_rows = int(out_df["contains_secret_pattern"].astype(str).str.lower().eq("true").sum())
    instruction_rows = int(out_df["contains_instruction_like_words"].astype(str).str.lower().eq("true").sum())

    print(f"wrote {args.output}")
    print(f"rows={len(out_df)}")
    print(f"raw_message_forwarded_true={raw_forwarded}")
    print(f"query_values_forwarded_true={query_forwarded}")
    print(f"contains_secret_pattern_rows={secret_rows}")
    print(f"contains_instruction_like_words_rows={instruction_rows}")


if __name__ == "__main__":
    main()
