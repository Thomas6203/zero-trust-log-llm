# 🛡️ Zero-Trust Log-to-LLM Threat Timeline Reconstruction

> 中文：零信任 Log-to-LLM 資安事件時間線重建系統  
> A Zero-Trust Pipeline for Secure Evidence-Gated Threat Timeline Reconstruction with LLMs

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red)
![LLM](https://img.shields.io/badge/LLM-Evidence--Gated-purple)
![Status](https://img.shields.io/badge/Status-Prototype-orange)
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

## 🔍 專題一句話總結

> **LLM 負責整理與推理，但不直接接觸不可信任原文；所有輸入先 evidence-gated，所有輸出再 validator-gated。**

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