# Zero-Trust Log-to-LLM v2 補檔與重跑流程

## 1. 放置位置
把本資料夾內的檔案複製到 GitHub repo 根目錄，保留相同路徑：

- `rules/field_policy_v2.yml`
- `data/processed/adversarial_sanitization_tests.csv`
- `src/feature_extractor.py`
- `prompts/*.txt`
- `src/validator_v2.py`
- `data/processed/validator_attack_tests.json`
- `scripts/run_v2_reports.py`

另外，請把你已有的 `team_evidence_v2.json` 放到：

```text
data/processed/team_evidence_v2.json
```

## 2. 安裝套件
此補檔只使用 Python 標準函式庫，不需要額外套件。若你的 notebook 會讀 CSV，可另外安裝 pandas。

```bash
python --version
```

建議 Python 3.10 以上。

## 3. 從頭重跑 v2 報告
在 repo 根目錄執行：

```bash
python scripts/run_v2_reports.py
```

會產生或更新：

- `data/processed/sanitization_eval_report.csv`
- `data/processed/text_feature_report.json`
- `data/processed/feature_extraction_eval_report.csv`
- `data/processed/validator_eval_report.csv`
- `data/processed/llm_eval_report.csv`

## 4. LLM 評估怎麼跑
`llm_eval_report.csv` 不會捏造 LLM 成績。第一次執行時，若找不到下列檔案，狀態會顯示 `not_run_missing_output_file`：

- `data/processed/baseline_llm_output_v2.json`
- `data/processed/zero_trust_llm_output_v2.json`

請先用：

- `prompts/baseline_prompt_v2.txt`
- `prompts/zero_trust_prompt_v2.txt`
- `prompts/strict_json_prompt.txt`

分別跑 baseline 與 zero-trust prompt，把 LLM 原始輸出存成上述兩個 JSON 檔，然後再次執行：

```bash
python scripts/run_v2_reports.py
```

`llm_eval_report.csv` 就會用 `validator_v2.py` 實際檢查 JSON、evidence_id、confidence、secret leak、raw IP leak、prompt injection leak 等項目。

## 5. 單獨執行 feature extractor

```bash
python src/feature_extractor.py \
  --input data/processed/adversarial_sanitization_tests.csv \
  --output data/processed/text_feature_report_from_tests.json
```

## 6. 單獨執行 validator attack tests

```bash
python src/validator_v2.py \
  --evidence data/processed/team_evidence_v2.json \
  --attack-tests data/processed/validator_attack_tests.json \
  --report data/processed/validator_eval_report.csv
```
