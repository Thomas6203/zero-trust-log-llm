#!/usr/bin/env python3
"""Deterministic text feature extraction for Zero-Trust Log-to-LLM v2.

This module intentionally avoids LLM calls. It converts untrusted raw text,
URLs, command lines, and paths into safe boolean/count/template features.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, unquote, urlparse

URGENT_WORDS = [
    "urgent", "immediately", "suspended", "expire", "expires", "within", "now",
    "緊急", "立即", "馬上", "停用", "過期"
]
CREDENTIAL_TERMS = [
    "password", "passwd", "pwd", "credential", "credentials", "login", "verify",
    "token", "api_key", "apikey", "cookie", "authorization", "密碼", "憑證", "驗證", "登入"
]
INSTRUCTION_LIKE_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"reveal\s+secrets?",
    r"output\s+all\s+data",
    r"system\s+prompt",
    r"developer\s+message",
    r"請忽略.*規則",
    r"忽略.*指令",
    r"輸出所有資料",
    r"揭露.*秘密",
]
SECRET_PATTERNS = [
    r"(?i)\bapi[_-]?key\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}",
    r"(?i)\b(token|secret|cookie|authorization)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{8,}",
    r"(?i)\b(passwd|password|pwd)\b\s*[:=]\s*['\"]?[^\s'\"]{4,}",
    r"sk-[A-Za-z0-9]{8,}",
]
BASE64ISH = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
NUMERIC_SEGMENT = re.compile(r"^\d{2,}$")
HEX_SEGMENT = re.compile(r"^[a-fA-F0-9]{16,}$")
LONG_SEGMENT = re.compile(r"^[A-Za-z0-9_\-]{30,}$")


def _lower(text: str) -> str:
    return (text or "").lower()


def contains_any(text: str, words: Iterable[str]) -> bool:
    low = _lower(text)
    return any(w.lower() in low for w in words)


def has_instruction_like_words(text: str) -> bool:
    return any(re.search(p, text or "", flags=re.IGNORECASE) for p in INSTRUCTION_LIKE_PATTERNS)


def contains_secret_pattern(text: str) -> bool:
    return any(re.search(p, text or "") for p in SECRET_PATTERNS)


def language_hint(text: str) -> str:
    if re.search(r"[\u4e00-\u9fff]", text or ""):
        return "zh"
    if re.search(r"[A-Za-z]", text or ""):
        return "en"
    return "unknown"


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    urls = re.findall(r"https?://[^\s'\"]+", text)
    if text.startswith("/"):
        urls.append(text)
    return urls


def template_path(path: str) -> str:
    if not path:
        return ""
    path = unquote(path)
    parts = [p for p in path.split("/") if p]
    out: List[str] = []
    for part in parts:
        low = part.lower()
        if NUMERIC_SEGMENT.match(part):
            out.append("{numeric_segment}")
        elif HEX_SEGMENT.match(part):
            out.append("{hex_segment}")
        elif has_instruction_like_words(part.replace("-", " ").replace("_", " ")):
            out.append("{instruction_like_segment}")
        elif LONG_SEGMENT.match(part):
            out.append("{long_text_segment}")
        else:
            out.append(low)
    return "/" + "/".join(out) if out else "/"


def parse_url_features(text: str) -> Dict[str, Any]:
    urls = extract_urls(text)
    query_names: List[str] = []
    templates: List[str] = []
    raw_query_values = ""
    raw_paths = ""
    for u in urls:
        parsed = urlparse(u)
        path = parsed.path if parsed.path else (u if u.startswith("/") else "")
        query = parsed.query
        if not query and "?" in u:
            query = u.split("?", 1)[1]
        for k, v in parse_qsl(query, keep_blank_values=True):
            if k not in query_names:
                query_names.append(k)
            raw_query_values += " " + v
        if path:
            templates.append(template_path(path))
            raw_paths += " " + path
    primary_template = templates[0] if templates else ""
    combined_url_text = " ".join([text or "", raw_query_values, raw_paths])
    return {
        "contains_url": bool(urls),
        "url_count": len(urls),
        "query_param_names": query_names,
        "query_values_forwarded": False,
        "url_path_template": primary_template,
        "url_path_templated": bool(primary_template and primary_template != (urlparse(urls[0]).path if urls and not urls[0].startswith('/') else urls[0].split('?', 1)[0] if urls else "")),
        "raw_path_forwarded": False,
        "raw_path_suppressed": bool(urls),
        "url_text_has_instruction_like_words": has_instruction_like_words(combined_url_text.replace("-", " ").replace("_", " ")),
        "url_text_has_credential_terms": contains_any(combined_url_text, CREDENTIAL_TERMS),
        "url_text_contains_secret_pattern": contains_secret_pattern(combined_url_text),
    }


def extract_text_features(text: str, source: str = "raw_message") -> Dict[str, Any]:
    text = text or ""
    url_features = parse_url_features(text)
    instruction_flag = has_instruction_like_words(text.replace("-", " ").replace("_", " ")) or url_features["url_text_has_instruction_like_words"]
    credential_flag = contains_any(text, CREDENTIAL_TERMS) or url_features["url_text_has_credential_terms"]
    secret_flag = contains_secret_pattern(text) or url_features["url_text_contains_secret_pattern"]
    features = {
        "contains_url": url_features["contains_url"],
        "url_count": url_features["url_count"],
        "query_param_names": url_features["query_param_names"],
        "query_values_forwarded": False,
        "url_path_template": url_features["url_path_template"],
        "url_path_templated": url_features["url_path_templated"],
        "has_urgent_words": contains_any(text, URGENT_WORDS),
        "has_credential_terms": credential_flag,
        "has_instruction_like_words": instruction_flag,
        "encoded_text_detected": bool(BASE64ISH.search(text)) or " -enc" in _lower(text) or "encodedcommand" in _lower(text),
        "contains_secret_pattern": secret_flag,
        "text_length": len(text),
        "language_hint": language_hint(text),
        "raw_text_forwarded": False,
        "raw_text_suppressed": True,
        "raw_path_forwarded": False,
        "raw_path_suppressed": url_features["raw_path_suppressed"],
    }
    return features


def extract_file(input_path: Path, output_path: Path, text_column: str = "raw_input", id_column: str = "case_id") -> None:
    rows: List[Dict[str, Any]] = []
    with input_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            features = extract_text_features(row.get(text_column, ""), row.get("source", "raw_message"))
            rows.append({
                id_column: row.get(id_column, ""),
                "source": row.get("source", ""),
                "description": row.get("description", ""),
                "text_features": features,
            })
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--text-column", default="raw_input")
    parser.add_argument("--id-column", default="case_id")
    args = parser.parse_args()
    extract_file(args.input, args.output, args.text_column, args.id_column)


if __name__ == "__main__":
    main()
