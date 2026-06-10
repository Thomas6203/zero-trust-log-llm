# 🛡️ Zero-Trust Log-to-LLM Threat Timeline Reconstruction

> 中文：零信任 Log-to-LLM 資安事件時間線重建系統  
> A Zero-Trust Pipeline for Secure Evidence-Gated Threat Timeline Reconstruction with LLMs

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red)
![LLM](https://img.shields.io/badge/LLM-Evidence--Gated-purple)
![Pipeline](https://img.shields.io/badge/Pipeline-Zero--Trust-green)

---

## 📌 Table of Contents

- [一、專題概述](#一專題概述)
- [二、核心設計理念](#二核心設計理念)
- [三、系統流程](#三系統流程)
- [四、專案資料夾結構](#四專案資料夾結構)
- [五、主要模組說明](#五主要模組說明)
- [六、資料集策略](#六資料集策略)
- [七、主要輸出檔案](#七主要輸出檔案)
- [八、如何執行](#八如何執行)
- [九、報告與展示建議觀看順序](#九報告與展示建議觀看順序)
- [十、Evaluation Metrics](#十evaluation-metrics)
- [十一、Baseline Prompt vs Zero-Trust Prompt](#十一baseline-prompt-vs-zero-trust-prompt)
- [十二、安全設計重點](#十二安全設計重點)
- [十三、目前完成項目](#十三目前完成項目)
- [十四、限制與未來工作](#十四限制與未來工作)
- [十五、結論](#十五結論)

---

## 一、專題概述

### Zero-Trust Log-to-LLM Threat Timeline Reconstruction

**中文：零信任 Log-to-LLM 資安事件時間線重建系統**

本專題的核心概念是建立一套 **Zero-Trust Log-to-LLM Threat Timeline Reconstruction** 流程，也就是零信任的資安事件時間線重建系統。我們的不是單純把 raw log 直接丟給 LLM，讓模型自行判斷事件，而是先將 log 轉換成安全、遮蔽、結構化的 evidence，再讓 LLM 根據 evidence 重建攻擊時間線。這樣可以降低敏感資料外洩、prompt injection、LLM hallucination，以及處理 LLM 輸出難以追溯證據的問題。

我們的新穎點是 **Zero-Trust Log-to-LLM Pipeline**：所有來自使用者或外部系統的 Log 的自然語言欄位預設為不可信，即使未命中任何惡意規則，也不會以原文形式進入主 LLM，而不是等偵測到 prompt injection 才處理。

> **本專題對新的提示注入攻擊不敏感，因為主 LLM 根本沒有看到原文。**

傳統 **rule-based** 方法可以偵測已知威脅，但遇到 **zero-day**、語句變形、**URL encoding**、混合語言或攻擊者刻意改寫指令時，單純規則容易失效。

而 **LLM** 的優勢是能整理 logs、code、network events 中的 sequence 與 context，但我們也不能把所有判斷都交給 LLM，因為 LLM 可能洩漏資料、被 prompt injection 影響，或產生沒有證據支持的敘述。綜合以上優缺點，於是我們建構了 **Zero-Trust Log-to-LLM** 系統。

---

## 二、核心設計理念

本專題的設計重點不是讓 LLM 直接讀取 raw logs，而是將 raw logs 先經過多層安全處理，轉換為可控的 **evidence records**。

主 LLM 只能看到經過以下模組處理後的資料：

- `sanitizer`
- `feature_extractor`
- `risk_tagger`
- `isolated_classifier`
- `classifier_output_validator`
- `main_llm_output_gate`

### 🧩 四個核心原則

| 原則 | 說明 |
|---|---|
| **Zero-Trust Input Handling** | 所有 `raw_message`、URL query value、URL path、command_line、file_path、user-controlled text 預設為不可信，不直接送入主 LLM。 |
| **Deterministic Feature Extraction** | 系統先用 rule-based / deterministic 方法抽取安全特徵，例如 `contains_url`、`has_credential_terms`、`has_instruction_like_words`、`encoded_text_detected`、`contains_secret_pattern`。 |
| **Evidence-Gated Reasoning** | 主 LLM 只能根據 evidence records 產生 timeline，每一個 timeline step 都必須引用 `evidence_ids`，避免 hallucination。 |
| **Output Validation** | LLM 輸出後會經過 validator / output gate 檢查 JSON 格式、evidence_id、confidence、secret leak、raw IP leak 與 prompt injection leak。 |

---

## 三、系統流程

### 🧭 High-Level Pipeline

```text
Raw Logs
  ↓
Dataset Parser
  ↓
Zero-Trust Preprocessing / Sanitization
  ↓
Feature Extraction
  ↓
Risk Evidence Building
  ↓
Isolated Classifier
  ↓
Classifier Output Validation
  ↓
Main LLM Evidence Selection
  ↓
Zero-Trust Prompting
  ↓
Main LLM Timeline Reconstruction
  ↓
Main LLM Output Gate / Validator
  ↓
Evaluation Reports
```

### 📦 Repo Data Flow

```text
data/processed/team_events_raw.csv
  ↓
data/processed/team_events_masked.csv
  ↓
data/processed/team_events_masked_v2.csv
  ↓
data/processed/team_evidence.json
  ↓
data/processed/team_evidence_v2.json
  ↓
data/processed/team_evidence_v2_validated.json
  ↓
data/processed/team_evidence_v2_main_llm_input.json
  ↓
prompts/zero_trust_prompt_v2.txt
  ↓
Main LLM Output
  ↓
src/main_llm_output_gate.py
  ↓
data/processed/llm_eval_report.csv
```

---

## 四、專案資料夾結構

```text
zero-trust-log-llm/
│
├── data/
│   ├── raw/
│   │   └── original_dataset/
│   │
│   └── processed/
│       ├── team_events_raw.csv
│       ├── team_events_masked.csv
│       ├── team_events_masked_v2.csv
│       ├── team_evidence.json
│       ├── team_evidence_v2.json
│       ├── team_evidence_v2_validated.json
│       ├── team_evidence_v2_main_llm_input.json
│       ├── team_evidence_v2_rejected_by_classifier.json
│       ├── classifier_validation_report.csv
│       ├── apply_classifier_validation_summary.json
│       ├── main_llm_input_selection_summary.json
│       ├── adversarial_sanitization_tests.csv
│       ├── sanitization_eval_report.csv
│       ├── text_feature_report.json
│       ├── feature_extraction_eval_report.csv
│       ├── risk_tag_eval_report.csv
│       ├── validator_attack_tests.json
│       ├── validator_eval_report.csv
│       └── llm_eval_report.csv
│
├── prompts/
│   ├── baseline_prompt.txt
│   ├── baseline_prompt_v2.txt
│   ├── zero_trust_prompt.txt
│   ├── zero_trust_prompt_v2.txt
│   ├── strict_json_prompt.txt
│   └── isolated_classifier_prompt.txt
│
├── rules/
│   ├── field_policy.yml
│   ├── field_policy_v2.yml
│   ├── risk_rules.yml
│   ├── risk_rules_v2.yml
│   └── dataset_mapping.yml
│
├── schemas/
│   └── classifier_output_schema.json
│
├── scripts/
│   └── run_v2_reports.py
│
├── src/
│   ├── config.py
│   ├── parser.py
│   ├── sanitizer.py
│   ├── feature_extractor.py
│   ├── risk_tagger.py
│   ├── evidence_builder.py
│   ├── risk_evidence_builder.py
│   ├── llm_reasoner.py
│   ├── apply_classifier_outputs.py
│   ├── apply_classifier_validation.py
│   ├── classifier_output_validator.py
│   ├── select_main_llm_evidence.py
│   ├── main_llm_output_gate.py
│   └── run_v2_reports.py
│
├── README_RUN_V2.md
└── README.md
```

---

## 五、主要模組說明

### 1. Dataset Parser

負責將原始 log 或 prototype dataset 轉換成統一欄位格式。

**主要輸出：**

```text
data/processed/team_events_raw.csv
```

此檔案是整個 pipeline 的起點，欄位包含：

```text
event_id
timestamp
source
host
user
src_ip
dst_ip
event_type
url
command_line
file_path
raw_message
ground_truth_stage
```

---

### 2. Zero-Trust Preprocessing / Sanitization

負責對 raw event table 進行敏感資料遮蔽與欄位安全處理。

**主要輸出：**

```text
data/processed/team_events_masked.csv
data/processed/team_events_masked_v2.csv
```

處理內容包含：

```text
raw host → HOST_001
raw user → USER_001
raw IP → IP_001
URL path → url_path_template
URL query value → suppressed
raw_message → suppressed
command_line → summarized or feature-only
file_path → suppressed or template
```

> 核心精神：**主 LLM 不看 raw logs，只看安全化欄位。**

---

### 3. Field Policy v2

欄位安全政策定義於：

```text
rules/field_policy_v2.yml
```

此檔案用來定義不同欄位的處理方式，例如：

```yaml
forward_to_main_llm: false
allowed_transform: alias
allowed_transform: template
allowed_transform: feature_only
allowed_transform: suppress
```

| 欄位 | 主 LLM 是否可看原文 | 處理方式 |
|---|---|---|
| `event_id` | 可以 | 保留 |
| `timestamp` | 可以 | 保留 |
| `event_type` | 可以 | 保留 |
| `host` | 不可看 raw value | alias |
| `user` | 不可看 raw value | alias |
| `src_ip / dst_ip` | 不可看 raw value | alias |
| `raw_message` | 不可 | suppress / feature_only |
| `URL query value` | 不可 | 只保留 query parameter name |
| `URL path` | 不直接給 | template |
| `token / password / cookie / API key` | 不可 | suppress |

---

### 4. Feature Extraction

Feature extraction 由以下程式負責：

```text
src/feature_extractor.py
```

**主要輸出：**

```text
data/processed/text_feature_report.json
data/processed/feature_extraction_eval_report.csv
```

此階段不把危險文字送給主 LLM，而是轉成 deterministic features。

範例：

```json
{
  "contains_url": true,
  "url_count": 1,
  "query_param_names": ["q"],
  "query_values_forwarded": false,
  "url_path_template": "/search",
  "has_urgent_words": false,
  "has_credential_terms": true,
  "has_instruction_like_words": true,
  "encoded_text_detected": false,
  "contains_secret_pattern": false,
  "raw_text_forwarded": false,
  "raw_text_suppressed": true
}
```

---

### 5. Risk Tagging and Evidence Building

Risk tagging 與 evidence construction 由以下檔案負責：

```text
src/risk_tagger.py
src/evidence_builder.py
src/risk_evidence_builder.py
rules/risk_rules.yml
rules/risk_rules_v2.yml
```

**主要輸出：**

```text
data/processed/team_evidence.json
data/processed/team_evidence_v2.json
```

Evidence record 的目標是把事件轉換成主 LLM 可以安全使用的結構化資料。

---

### 6. Isolated Classifier

本專題加入 **isolated classifier** 作為低權限分類器，負責判斷事件文字是否具有 credential request、phishing-like、prompt injection-like 或 malware delivery 等傾向。

相關檔案：

```text
prompts/isolated_classifier_prompt.txt
schemas/classifier_output_schema.json
src/classifier_output_validator.py
src/apply_classifier_outputs.py
src/apply_classifier_validation.py
```

Classifier 的輸出必須符合固定 JSON schema：

```json
{
  "intent_category": "benign",
  "contains_request_for_credentials": false,
  "contains_instruction_to_model": false
}
```

允許的 `intent_category` 包含：

```text
benign
credential_request
phishing_like
prompt_injection_like
malware_delivery
unknown
```

**主要輸出：**

```text
data/processed/classifier_validation_report.csv
data/processed/apply_classifier_validation_summary.json
data/processed/team_evidence_v2_validated.json
data/processed/team_evidence_v2_rejected_by_classifier.json
```

---

### 7. Main LLM Evidence Selection

通過 classifier validation 的 evidence 會再經過 main LLM input selection。

相關程式：

```text
src/select_main_llm_evidence.py
```

**主要輸出：**

```text
data/processed/team_evidence_v2_main_llm_input.json
data/processed/main_llm_input_selection_summary.json
```

此階段的目標是只把可以進入主 LLM 的 evidence records 選出來。

---

### 8. Prompt Pipeline

本專題使用兩組 prompt 進行對照：

```text
prompts/baseline_prompt.txt
prompts/baseline_prompt_v2.txt
prompts/zero_trust_prompt.txt
prompts/zero_trust_prompt_v2.txt
prompts/strict_json_prompt.txt
```

| Prompt | 用途 |
|---|---|
| `baseline_prompt.txt` / `baseline_prompt_v2.txt` | comparison baseline，模擬較直接的 log 分析方式 |
| `zero_trust_prompt.txt` / `zero_trust_prompt_v2.txt` | 正式系統 prompt，要求 LLM 只能根據 sanitized evidence 重建 timeline |
| `strict_json_prompt.txt` | 要求 LLM 只能輸出 JSON，不要輸出 Markdown 或額外說明 |

---

### 9. Main LLM Output Gate

LLM output gate 由以下程式負責：

```text
src/main_llm_output_gate.py
```

主要任務是檢查主 LLM 的輸出是否安全、格式是否正確，以及 evidence 是否可追溯。

檢查項目包含：

```text
JSON 是否可解析
是否存在 timeline key
timeline step 是否包含必要欄位
evidence_ids 是否存在於 evidence records
confidence 是否在 0 到 1 之間
summary 是否洩漏 secret
summary 是否包含 raw IP
summary 是否包含 prompt injection 原文
是否出現 unexpected top-level key
```

---

## 六、資料集策略

本專題目標資料來源為：

```text
OTRF Security Datasets / Mordor
```

OTRF / Mordor 適合用於 security data analysis、threat hunting 與 adversarial behavior reconstruction。

在 prototype 階段，系統使用已整理好的 processed dataset 驗證 pipeline：

```text
data/processed/team_events_raw.csv
data/processed/team_events_masked.csv
data/processed/team_evidence.json
data/processed/team_evidence_v2.json
```

若要換成真實 OTRF / Mordor 資料，只需要讓 parser 將原始資料轉換成相同欄位格式的 `team_events_raw.csv`，後續 pipeline 不需要大幅修改。

---

## 七、主要輸出檔案

| 類別 | 檔案 | 用途 |
|---|---|---|
| Sanitization | `adversarial_sanitization_tests.csv` | 測試 prompt injection、URL query injection、secret、token、credential request |
| Sanitization | `sanitization_eval_report.csv` | sanitizer 評估結果 |
| Feature Extraction | `text_feature_report.json` | text features 明細 |
| Feature Extraction | `feature_extraction_eval_report.csv` | feature extractor 評估 |
| Risk Tagging | `risk_tag_eval_report.csv` | risk tags 與 risk score 評估 |
| Evidence | `team_evidence_v2.json` | v2 evidence records |
| Classifier | `classifier_validation_report.csv` | isolated classifier schema validation |
| Classifier | `team_evidence_v2_validated.json` | 通過 classifier validation 的 evidence |
| Main LLM Input | `team_evidence_v2_main_llm_input.json` | 最後允許送入主 LLM 的 evidence |
| Validator | `validator_attack_tests.json` | validator attack tests |
| Validator | `validator_eval_report.csv` | validator 評估結果 |
| LLM Evaluation | `llm_eval_report.csv` | baseline / zero-trust LLM output 評估 |

---

## 八、如何執行

### 1. 安裝環境

建議使用 **Python 3.10+**。

```bash
pip install pandas pyyaml jsonschema python-dateutil
```

---

### 2. 執行 v2 report pipeline

```bash
python src/run_v2_reports.py
```

若本地版本仍保留 `scripts/run_v2_reports.py`，也可以使用：

```bash
python scripts/run_v2_reports.py
```

執行後會更新或產生：

```text
data/processed/sanitization_eval_report.csv
data/processed/text_feature_report.json
data/processed/feature_extraction_eval_report.csv
data/processed/validator_eval_report.csv
data/processed/llm_eval_report.csv
```

---

### 3. 單獨執行 feature extraction

```bash
python src/feature_extractor.py \
  --input data/processed/adversarial_sanitization_tests.csv \
  --output data/processed/text_feature_report_from_tests.json
```

PowerShell：

```powershell
python src\feature_extractor.py `
  --input data\processed\adversarial_sanitization_tests.csv `
  --output data\processed\text_feature_report_from_tests.json
```

---

### 4. 執行 classifier output validation

```bash
python src/classifier_output_validator.py \
  --evidence data/processed/team_evidence_v2.json \
  --schema schemas/classifier_output_schema.json \
  --output data/processed/classifier_validation_report.csv
```

PowerShell：

```powershell
python src\classifier_output_validator.py `
  --evidence data\processed\team_evidence_v2.json `
  --schema schemas\classifier_output_schema.json `
  --output data\processed\classifier_validation_report.csv
```

---

### 5. 選出主 LLM 可用 evidence

```bash
python src/select_main_llm_evidence.py
```

主要輸出：

```text
data/processed/team_evidence_v2_main_llm_input.json
data/processed/main_llm_input_selection_summary.json
```

---

## 九、報告與展示建議觀看順序

```text
1. data/processed/team_events_raw.csv
2. data/processed/team_events_masked.csv
3. rules/field_policy_v2.yml
4. data/processed/adversarial_sanitization_tests.csv
5. data/processed/sanitization_eval_report.csv
6. src/feature_extractor.py
7. data/processed/text_feature_report.json
8. data/processed/feature_extraction_eval_report.csv
9. rules/risk_rules_v2.yml
10. src/risk_evidence_builder.py
11. data/processed/team_evidence_v2.json
12. prompts/isolated_classifier_prompt.txt
13. schemas/classifier_output_schema.json
14. src/classifier_output_validator.py
15. data/processed/classifier_validation_report.csv
16. src/select_main_llm_evidence.py
17. data/processed/team_evidence_v2_main_llm_input.json
18. prompts/zero_trust_prompt_v2.txt
19. prompts/strict_json_prompt.txt
20. src/main_llm_output_gate.py
21. data/processed/validator_attack_tests.json
22. data/processed/validator_eval_report.csv
23. data/processed/llm_eval_report.csv
```

---

## 十、Evaluation Metrics

| 面向 | Metrics | 相關檔案 |
|---|---|---|
| Dataset Quality | Field Completeness, Timestamp Parse Rate, Event Type Coverage | `dataset_quality_report.csv` |
| Sanitization | Raw Text Exposure Rate, Query Value Exposure Rate, Secret Suppression Rate, PII Masking Coverage | `sanitization_eval_report.csv` |
| Feature Extraction | URL Detection, Credential Term Detection, Instruction-like Word Detection, Encoded Payload Detection | `feature_extraction_eval_report.csv` |
| Risk Tagging | Tag Coverage, Risk Score Consistency, MITRE Tactic Mapping | `risk_tag_eval_report.csv` |
| Classifier Validation | JSON Schema Validity, Allowed Intent Category, Boolean Field Type Check | `classifier_validation_report.csv` |
| LLM Output Validation | JSON Validity Rate, Evidence Validity Rate, Secret Leak Detection, Raw IP Leak Detection | `validator_eval_report.csv`, `llm_eval_report.csv` |

---

## 十一、Baseline Prompt vs Zero-Trust Prompt

| 項目 | Baseline Prompt | Zero-Trust Prompt |
|---|---|---|
| 輸入資料 | 較接近 raw logs 或低限制輸入 | 只使用 sanitized evidence |
| 是否可看 raw text | 可能可以 | 不可以 |
| evidence_id 約束 | 弱 | 強制引用 valid evidence_ids |
| JSON 格式 | 不一定穩定 | strict JSON |
| Prompt Injection 風險 | 較高 | 較低 |
| Secret Leak 風險 | 較高 | 較低 |
| 可追溯性 | 較弱 | 較強 |

---

## 十二、安全設計重點

> 不要相信 raw log。  
> 不要讓主 LLM 看 user-controlled text。  
> 不要讓 classifier 的自由輸出直接進入主流程。  
> 不要相信 LLM 輸出。  
> 所有輸入要先轉成 evidence。  
> 所有輸出要再經過 validator。

具體防護包含：

- `raw_message` 預設 suppressed
- URL query value 不送入主 LLM，只保留 query parameter names
- URL path 進行 template 或 instruction-like segment abstraction
- raw user、raw host、raw IP 轉成 alias
- command_line 不直接傳給主 LLM，而是轉成 risk_tags、text_features、safe_summary
- classifier output 必須符合 JSON schema
- 主 LLM 只能讀 validated evidence
- LLM 輸出必須通過 output gate
- 每個 timeline step 必須有 `evidence_ids`
- `confidence` 必須在 0 到 1 之間

---

## 十三、目前完成項目

- [x] Zero-Trust field policy
- [x] Adversarial sanitization tests
- [x] Sanitization evaluation report
- [x] Text feature extraction
- [x] Feature extraction evaluation report
- [x] Risk evidence building
- [x] Isolated classifier prompt
- [x] Classifier output schema
- [x] Classifier validation report
- [x] Main LLM evidence selection
- [x] Zero-trust prompt v2
- [x] Strict JSON prompt
- [x] Validator attack tests
- [x] Validator evaluation report
- [x] LLM evaluation report

---

這代表目前系統已經不只是單純的 log summarization prototype，而是具備一條完整的 Zero-Trust Log-to-LLM 安全資料流。

## 十四、限制與未來工作

### Limitations

- Prototype dataset 規模有限，後續可接入更多 OTRF / Mordor scenarios。
- 目前主要使用 deterministic rules 與 schema validation，尚未整合大型 SIEM 平台。
- LLM timeline output 仍需要人工或 API 實際產生後，才能完整比較 baseline 與 zero-trust prompt 的差異。
- MITRE tactic mapping 目前以 rule-based hint 為主，未來可加入更細緻的 technique-level mapping。
- 目前沒有執行自動封鎖 IP、停用帳號等 active response action，避免安全風險。
- 尚未進行 large-scale fine-tuning，本專題重點放在 zero-trust pipeline、prompt pipeline 與 evaluation metrics。

### Future Work

- 接入更多 Mordor attack scenarios
- 加入 MITRE ATT&CK technique-level labeling
- 加入 SIEM / EDR log adapter
- 建立 dashboard
- 加入 human-in-the-loop review
- 比較不同 LLM 在同一批 evidence 上的 hallucination rate
- 加入更完整的 prompt injection benchmark

---

## 十五、結論

本專題建立了一套 **Zero-Trust Log-to-LLM Threat Timeline Reconstruction pipeline**。它不是直接把 raw logs 丟給 LLM，而是先透過 field policy、sanitization、feature extraction、risk tagging、isolated classifier、classifier validation、main LLM input selection 等步驟，把不可信任的 log 轉換成安全、結構化、可追溯的 evidence records。

主 LLM 只根據 validated evidence 重建攻擊時間線，最後再由 output gate / validator 檢查 JSON 格式、evidence_id、confidence、secret leak、raw IP leak 與 prompt injection leak。這樣的設計可以降低敏感資料外洩、prompt injection、LLM hallucination 以及證據不可追溯等問題。

> **Final Takeaway:**  
> LLM can reason over cybersecurity evidence, but raw logs must first be transformed into safe, structured, and verifiable evidence.
