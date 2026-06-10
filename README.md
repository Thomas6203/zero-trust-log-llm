一、專題概述
Zero-Trust Log-to-LLM Threat Timeline Reconstruction
中文：零信任 Log-to-LLM 資安事件時間線重建系統

本專題的核心概念是建立一套 Zero-Trust Log-to-LLM Threat Timeline Reconstruction 流程，也就是零信任的資安事件時間線重建系統。我們的不是單純把 raw log 直接丟給 LLM，讓模型自行判斷事件，而是先將 log 轉換成安全、遮蔽、結構化的 evidence，再讓 LLM 根據 evidence 重建攻擊時間線。這樣可以降低敏感資料外洩、prompt injection、LLM hallucination，以及處理LLM輸出難以追溯證據的問題。

我們的新穎點是 Zero-Trust Log-to-LLM Pipeline：所有來自使用者或外部系統的 Log 的自然語言欄位預設為不可信，即使未命中任何惡意規則，也不會以原文形式進入主 LLM，而不是等偵測到 prompt injection 才處理。

本專題對新的提示注入攻擊不敏感，因為主 LLM 根本沒有看到原文。

傳統 rule-based 方法可以偵測已知威脅，但遇到 zero-day、語句變形、URL encoding、混合語言或攻擊者刻意改寫指令時，單純規則容易失效。

而LLM 的優勢是能整理 logs、code、network events 中的 sequence 與 context，但我們也不能把所有判斷都交給 LLM，因為 LLM 可能洩漏資料、被 prompt injection 影響，或產生沒有證據支持的敘述。綜合以上優缺點，於是我們建構了Zero-Trust Log-to-LLM 系統。

---

二、系統核心想法

本專題的設計重點不是讓 LLM 直接讀取 raw logs，而是將 raw logs 先經過多層安全處理，轉換為可控的 evidence records。主 LLM 只能看到經過 sanitizer、feature extractor、risk tagger、isolated classifier、validator 處理後的資料。

整體設計有四個核心原則：

1. Zero-Trust Input Handling
   所有 raw_message、URL query value、URL path、command_line、file_path、user-controlled text 預設為不可信，不直接送入主 LLM。

2. Deterministic Feature Extraction
   系統先用 rule-based / deterministic 方法抽取安全特徵，例如 contains_url、has_credential_terms、has_instruction_like_words、encoded_text_detected、contains_secret_pattern，而不是讓主 LLM 自己讀原文判斷。

3. Evidence-Gated Reasoning
   主 LLM 只能根據 evidence records 產生 timeline，每一個 timeline step 都必須引用 evidence_ids，避免產生無法追溯的 hallucination。

4. Output Validation
   LLM 輸出後會經過 validator / output gate 檢查 JSON 格式、evidence_id 是否存在、confidence 是否合理，以及是否洩漏 secret、raw IP、raw path 或 prompt injection 內容。

---

三、系統流程

本專題目前的 v2 pipeline 可以整理為：

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

對應到目前 repo 的主要資料流：

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

四、專案資料夾結構

目前專案主要結構如下：

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
├── notebooks/
│   ├── A_dataset_parser.ipynb
│   ├── B_preprocessing_sanitizer.ipynb
│   ├── C_risk_tagger_evidence.ipynb
│   └── D_llm_reasoning_evaluation.ipynb
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

五、主要模組說明

### 1. Dataset Parser

負責將原始 log 或 prototype dataset 轉換成統一欄位格式。

主要輸出：

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

設計重點是讓後續 sanitizer、risk tagger、evidence builder 可以使用同一套 schema，不會因資料來源不同而斷裂。

---

### 2. Zero-Trust Preprocessing / Sanitization

負責對 raw event table 進行敏感資料遮蔽與欄位安全處理。

主要輸出：

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

此階段的核心精神是：

```text
主 LLM 不看 raw logs，只看安全化欄位。
```

---

### 3. Field Policy v2

欄位安全政策定義於：

```text
rules/field_policy_v2.yml
```

此檔案用來定義不同欄位的處理方式，例如：

```text
forward_to_main_llm: false
allowed_transform: alias
allowed_transform: template
allowed_transform: feature_only
allowed_transform: suppress
```

例如：

| 欄位                                  | 主 LLM 是否可看原文  | 處理方式                     |
| ----------------------------------- | ------------- | ------------------------ |
| event_id                            | 可以            | 保留                       |
| timestamp                           | 可以            | 保留                       |
| event_type                          | 可以            | 保留                       |
| host                                | 不可看 raw value | alias                    |
| user                                | 不可看 raw value | alias                    |
| src_ip / dst_ip                     | 不可看 raw value | alias                    |
| raw_message                         | 不可            | suppress / feature_only  |
| URL query value                     | 不可            | 只保留 query parameter name |
| URL path                            | 不直接給          | template                 |
| token / password / cookie / API key | 不可            | suppress                 |

---

### 4. Feature Extraction

Feature extraction 由以下程式負責：

```text
src/feature_extractor.py
```

主要輸出：

```text
data/processed/text_feature_report.json
data/processed/feature_extraction_eval_report.csv
```

此階段不把危險文字送給主 LLM，而是轉成 deterministic features，例如：

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

這樣的設計可以降低 prompt injection 進入主 LLM 的風險。

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

主要輸出：

```text
data/processed/team_evidence.json
data/processed/team_evidence_v2.json
```

Evidence record 的目標是把事件轉換成主 LLM 可以安全使用的結構化資料。

範例格式：

```json
{
  "event_id": "E037",
  "timestamp": "2026-05-20T10:27:00",
  "event_type": "process_execution",
  "host": "HOST_001",
  "user": "USER_001",
  "src_ip": "",
  "dst_ip": "",
  "risk_tags": [
    "suspicious_command",
    "suspicious_powershell",
    "encoded_payload",
    "raw_text_suppressed"
  ],
  "risk_score": 1.0,
  "mitre_tactic_hint": "Execution",
  "safe_summary": "A suspicious command execution pattern was observed on HOST_001 by USER_001. The original command line was sanitized before LLM input.",
  "text_features": {
    "encoded_text_detected": true,
    "raw_text_forwarded": false,
    "raw_text_suppressed": true
  }
}
```

---

### 6. Isolated Classifier

本專題加入 isolated classifier 作為低權限分類器，負責判斷事件文字是否具有 credential request、phishing-like、prompt injection-like 或 malware delivery 等傾向。

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

允許的 intent_category 包含：

```text
benign
credential_request
phishing_like
prompt_injection_like
malware_delivery
unknown
```

這個 classifier 不負責產生事件結論，只負責分類。它的輸出還需要經過 schema validation 才能被後續 pipeline 使用。

主要輸出：

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

主要輸出：

```text
data/processed/team_evidence_v2_main_llm_input.json
data/processed/main_llm_input_selection_summary.json
```

此階段的目標是只把可以進入主 LLM 的 evidence records 選出來。若某些 evidence 被 classifier 或 safety policy 判定為不適合進入主 LLM，則會被排除或進入 rejected file。

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

其中：

* baseline prompt：作為對照組，用來模擬較直接的 log 分析方式。
* zero_trust_prompt_v2：正式系統使用，要求 LLM 只能根據 sanitized evidence 重建 timeline。
* strict_json_prompt：要求 LLM 只能輸出 JSON，不要輸出 Markdown 或額外說明。

正式輸出的 timeline 格式應符合：

```json
{
  "timeline": [
    {
      "step": 1,
      "time_range": "09:01-09:25",
      "stage": "Credential Access",
      "summary": "Multiple failed login attempts were followed by a successful login.",
      "evidence_ids": ["E001", "E002", "E021"],
      "confidence": 0.82,
      "recommended_action": "Review authentication logs and reset the affected account if necessary."
    }
  ]
}
```

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

相關測試資料與報告：

```text
data/processed/validator_attack_tests.json
data/processed/validator_eval_report.csv
data/processed/llm_eval_report.csv
```

---

六、資料集策略

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

這些資料用於測試：

```text
欄位格式是否一致
PII 是否被遮蔽
URL query value 是否被 suppress
raw_message 是否不進入主 LLM
risk_tags 是否能產生
classifier output 是否符合 schema
LLM input 是否只包含 validated evidence
validator 是否能攔截不安全輸出
```

若要換成真實 OTRF / Mordor 資料，只需要讓 parser 將原始資料轉換成相同欄位格式的 `team_events_raw.csv`，後續 pipeline 不需要大幅修改。

---

七、主要輸出檔案說明

### 1. Sanitization 類

```text
data/processed/adversarial_sanitization_tests.csv
data/processed/sanitization_eval_report.csv
```

用途：

```text
測試 sanitizer 是否能阻擋 prompt injection、URL query injection、secret、token、credential request 等高風險輸入。
```

---

### 2. Feature Extraction 類

```text
data/processed/text_feature_report.json
data/processed/feature_extraction_eval_report.csv
```

用途：

```text
檢查 feature_extractor 是否成功抽取 URL、credential terms、instruction-like words、encoded payload、secret pattern 等 deterministic features。
```

---

### 3. Risk Tagging 類

```text
data/processed/risk_tag_eval_report.csv
data/processed/team_evidence.json
data/processed/team_evidence_v2.json
```

用途：

```text
檢查 risk_tags、risk_score、MITRE tactic hint、safe_summary 是否正確產生。
```

---

### 4. Classifier Validation 類

```text
data/processed/classifier_validation_report.csv
data/processed/apply_classifier_validation_summary.json
data/processed/team_evidence_v2_validated.json
data/processed/team_evidence_v2_rejected_by_classifier.json
```

用途：

```text
檢查 isolated classifier 的輸出是否符合 classifier_output_schema.json。
```

---

### 5. Main LLM Input 類

```text
data/processed/team_evidence_v2_main_llm_input.json
data/processed/main_llm_input_selection_summary.json
```

用途：

```text
記錄最後被允許送入主 LLM 的 evidence records。
```

---

### 6. Validator / LLM Evaluation 類

```text
data/processed/validator_attack_tests.json
data/processed/validator_eval_report.csv
data/processed/llm_eval_report.csv
```

用途：

```text
檢查主 LLM 輸出是否符合 JSON schema、是否引用有效 evidence、是否洩漏敏感資訊。
```

---

八、如何執行

### 1. 安裝環境

建議使用 Python 3.10 以上。

```bash
pip install pandas pyyaml jsonschema python-dateutil
```

若在 Google Colab 上執行，可以使用：

```python
from google.colab import drive
drive.mount('/content/drive')
```

---

### 2. 執行 v2 report pipeline

目前 v2 pipeline 可以從 `src/run_v2_reports.py` 執行：

```bash
python src/run_v2_reports.py
```

若你的本地版本仍保留 `scripts/run_v2_reports.py`，也可以使用：

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

Windows PowerShell 可寫成：

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

Windows PowerShell 可寫成：

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

九、報告與展示時建議觀看順序

若要理解整個專題流程，建議依照以下順序查看檔案：

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

十、Evaluation Metrics

本專題的評估不是只看 LLM 回答好不好，而是分成多個可檢查的安全與資料品質指標。

### 1. Dataset Quality

```text
Field Completeness
Timestamp Parse Rate
Event Type Coverage
Ground Truth Stage Coverage
```

相關檔案：

```text
data/processed/dataset_quality_report.csv
```

---

### 2. Sanitization Evaluation

```text
Raw Text Exposure Rate
Query Value Exposure Rate
Secret Suppression Rate
Prompt Injection Suppression
PII Masking Coverage
```

相關檔案：

```text
data/processed/sanitization_eval_report.csv
```

---

### 3. Feature Extraction Evaluation

```text
URL Detection
Credential Term Detection
Instruction-like Word Detection
Encoded Payload Detection
Secret Pattern Detection
```

相關檔案：

```text
data/processed/feature_extraction_eval_report.csv
data/processed/text_feature_report.json
```

---

### 4. Risk Tagging Evaluation

```text
Tag Coverage
Risk Score Consistency
MITRE Tactic Mapping
High-risk Event Detection
```

相關檔案：

```text
data/processed/risk_tag_eval_report.csv
```

---

### 5. Classifier Validation

```text
JSON Schema Validity
Allowed Intent Category
Boolean Field Type Check
Reject Invalid Classifier Output
```

相關檔案：

```text
schemas/classifier_output_schema.json
data/processed/classifier_validation_report.csv
```

---

### 6. LLM Output Validation

```text
JSON Validity Rate
Evidence Validity Rate
Invalid Evidence ID Detection
Secret Leak Detection
Raw IP Leak Detection
Prompt Injection Leak Detection
Confidence Range Check
```

相關檔案：

```text
data/processed/validator_eval_report.csv
data/processed/llm_eval_report.csv
```

---

十一、Baseline Prompt 與 Zero-Trust Prompt 差異

### Baseline Prompt

Baseline prompt 的目的不是作為正式安全流程，而是作為 comparison baseline。它模擬直接讓 LLM 看較原始的 log 或較少限制的輸入，觀察模型是否可能：

```text
直接轉述 raw log
輸出敏感資訊
被 prompt injection 文字影響
產生沒有 evidence 支持的推論
```

相關檔案：

```text
prompts/baseline_prompt.txt
prompts/baseline_prompt_v2.txt
```

---

### Zero-Trust Prompt

Zero-trust prompt 是正式流程使用的 prompt。它限制主 LLM：

```text
只能使用 provided evidence
每個 timeline step 必須引用 valid evidence_ids
不能 invent evidence_ids
不能輸出 raw logs
不能 reveal secrets, tokens, passwords, cookies, API keys
如果 evidence insufficient，必須降低 confidence
只能輸出 JSON
```

相關檔案：

```text
prompts/zero_trust_prompt.txt
prompts/zero_trust_prompt_v2.txt
prompts/strict_json_prompt.txt
```

---

十二、安全設計重點

本專題的安全設計可以用以下方式總結：

```text
不要相信 raw log。
不要讓主 LLM 看 user-controlled text。
不要讓 classifier 的自由輸出直接進入主流程。
不要相信 LLM 輸出。
所有輸入要先轉成 evidence。
所有輸出要再經過 validator。
```

具體防護包含：

1. raw_message 預設 suppressed。
2. URL query value 不送入主 LLM，只保留 query parameter names。
3. URL path 進行 template 或 instruction-like segment abstraction。
4. raw user、raw host、raw IP 轉成 alias。
5. command_line 不直接傳給主 LLM，而是轉成 risk_tags、text_features、safe_summary。
6. classifier output 必須符合 JSON schema。
7. 主 LLM 只能讀 validated evidence。
8. LLM 輸出必須通過 output gate。
9. 每個 timeline step 必須有 evidence_ids。
10. confidence 必須在 0 到 1 之間。

---

十三、目前已完成項目

目前 repo 已包含以下 v2 pipeline 元件：

```text
Zero-Trust field policy
Adversarial sanitization tests
Sanitization evaluation report
Text feature extraction
Feature extraction evaluation report
Risk evidence building
Isolated classifier prompt
Classifier output schema
Classifier validation report
Main LLM evidence selection
Zero-trust prompt v2
Strict JSON prompt
Validator attack tests
Validator evaluation report
LLM evaluation report
```

這代表目前系統已經不只是單純的 log summarization prototype，而是具備一條完整的 Zero-Trust Log-to-LLM 安全資料流。

---

十四、限制與未來工作

目前系統仍有以下限制：

1. Prototype dataset 規模有限，後續可接入更多 OTRF / Mordor scenarios。
2. 目前主要使用 deterministic rules 與 schema validation，尚未整合大型 SIEM 平台。
3. LLM timeline output 仍需要人工或 API 實際產生後，才能完整比較 baseline 與 zero-trust prompt 的差異。
4. MITRE tactic mapping 目前以 rule-based hint 為主，未來可加入更細緻的 technique-level mapping。
5. 目前沒有執行自動封鎖 IP、停用帳號等 active response action，避免安全風險。
6. 尚未進行 large-scale fine-tuning，本專題重點放在 zero-trust pipeline、prompt pipeline 與 evaluation metrics。

未來可擴充方向：

```text
接入更多 Mordor attack scenarios
加入 MITRE ATT&CK technique-level labeling
加入 SIEM / EDR log adapter
建立 dashboard
加入 human-in-the-loop review
比較不同 LLM 在同一批 evidence 上的 hallucination rate
加入更完整的 prompt injection benchmark
```

---

十五、結論

本專題建立了一套 Zero-Trust Log-to-LLM Threat Timeline Reconstruction pipeline。它不是直接把 raw logs 丟給 LLM，而是先透過 field policy、sanitization、feature extraction、risk tagging、isolated classifier、classifier validation、main LLM input selection 等步驟，把不可信任的 log 轉換成安全、結構化、可追溯的 evidence records。

主 LLM 只根據 validated evidence 重建攻擊時間線，最後再由 output gate / validator 檢查 JSON 格式、evidence_id、confidence、secret leak、raw IP leak 與 prompt injection leak。這樣的設計可以降低敏感資料外洩、prompt injection、LLM hallucination 以及證據不可追溯等問題。
