# Research Evaluation Plan

This document defines the research methodology, benchmark evaluation criteria, ablation studies, and statistical validation requirements for VibeGuard.

---

## 1. Primary Research Hypotheses

- **H1 (Intent Impact)**: Combining static authorization intent with dynamic multi-identity execution (AIAG) yields significantly higher precision and recall for BOLA/IDOR detection compared to dynamic-only scanning.
- **H2 (Runtime Impact)**: AIAG contradiction analysis achieves lower false-positive rates on complex web apps compared to static-only SAST analysis.
- **H3 (Deterministic Reasoning Impact)**: Deterministic graph contradiction rules outperform raw LLM security agent judgments in vulnerability verification accuracy.
- **H4 (GenAI Correlation)**: Tool AST discovery combined with injection probing detects agent abuse vectors missed by standalone prompt-injection scanners.

---

## 2. Experimental Design & Ablation Suite

| Experiment ID | Baseline / Variant | Purpose | Key Metric |
|---|---|---|---|
| **EXP-01** | AIAG vs. Dynamic-Only Scanner | Evaluate value of static intent extraction | BOLA Precision, Recall, F1 |
| **EXP-02** | AIAG vs. Static-Only SAST | Evaluate value of multi-identity dynamic execution | False Positive Rate (FPR) |
| **EXP-03** | AIAG vs. LLM-Only Agent | Evaluate deterministic proof vs. LLM judgment | Verification Accuracy |
| **EXP-04** | AIAG vs. Open-Source Benchmarks | Evaluate against standard benchmark apps | Detection Rate, Time to Scan |
| **EXP-05** | **Ablation Study**: <br>- w/o Graph<br>- w/o Static Intent<br>- w/o Multi-Identity Crawler<br>- w/o LLM Extractor | Quantify component contribution | Delta F1 Score |

---

## 3. Metrics & Statistical Validation

### Core Metrics
$$\text{Precision} = \frac{TP}{TP + FP}, \quad \text{Recall} = \frac{TP}{TP + FN}, \quad F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$

- **Time-to-Detection (TTD)**: Total elapsed seconds per verified vulnerability.
- **Cost per Application**: LLM token costs + compute resource overhead per scan.

### Statistical Rigor Protocol
1. **Raw Preservation**: All raw experiment trial JSON files, requests, and AST dumps are saved immutably in `experiments/data/<exp_id>/`.
2. **Replicability**: Each experiment run records random seeds, LLM model versions, and environmental parameters.
3. **Bootstrap Confidence Intervals**: Compute 95% non-parametric bootstrap confidence intervals over $N \ge 10$ independent trials:
   $$\text{CI}_{95\%} = [\text{Percentile}_{2.5\%}(\hat{\theta}^*), \text{Percentile}_{97.5\%}(\hat{\theta}^*)]$$

---

## 4. Claim-Evidence Mapping (`research/CLAIM_EVIDENCE_MATRIX.md`)

All paper claims must map directly to raw experiment outputs in this format:

```text
Claim: "AIAG reduces false positive BOLA findings by at least 40% compared to pure SAST."
├── Experiment ID: EXP-02
├── Raw Data Path: experiments/data/exp_02_sast_vs_aiag.json
├── Analysis Script: packages/evaluation/analyze_exp02.py
├── Ground Truth: benchmarks/ground_truth/vibe_bench_v1.json
└── Figure/Table: Table 2 in paper draft
```
