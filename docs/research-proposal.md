# RuleDistill — Trích xuất Security Rule từ Transformer Phân loại Syscall

---

## 1. Mục tiêu

Pipeline **RuleDistill** — dùng Transformer làm Teacher Oracle để distill tri thức phát hiện tấn công syscall thành **security rule dạng human-readable**, deployable trên eBPF enforcement engines.

- Transformer học offline, rule enforce online (không inference model lúc runtime).
- Soft labels từ Teacher cung cấp richer supervision hơn hard labels → surrogate học decision boundary tốt hơn train trực tiếp.
- Rule set mục tiêu: Fidelity >95% vs Teacher, FPR <1%, đủ ngắn gọn để analyst đọc hiểu.

---

## 2. Research Questions & Hypotheses

| RQ      | Câu hỏi                                                                        | Giả thuyết                                                                                |
| ------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| **RQ1** | Phương pháp nào đạt cân bằng tốt nhất giữa Fidelity, FPR, và Rule Complexity?  | H1: Decision Tree (B) và RuleFit (C) đạt Fidelity >95% với rule set compact.              |
| **RQ2** | Distillation có tạo rule tốt hơn train trực tiếp trên hard labels không?       | H2: Distillation cải thiện Attack-class Fidelity ≥3-5%, đặc biệt cho multi-stage attacks. |
| **RQ3** | Rich features (thread, timing, args) cải thiện bao nhiêu so với sequence-only? | H3: Tier 2 features cải thiện Fidelity trên LID-DS, đặc biệt cross-thread attacks.        |
| **RQ4** | Rule generalize cross-scenario/cross-domain đến mức nào?                       | H4: OOD fidelity thấp hơn nhưng Feedback Loop thu hẹp gap sau 2-3 chu kỳ.                 |

> RQ1-RQ2 là core (phải trả lời). RQ3-RQ4 là extension (trả lời nếu còn thời gian).

---

## 3. Pipeline Overview

```
[Offline]
  Syscall Traces → Feature Engineering → Transformer Teacher
                                               ↓
                                    Temperature-scaled Soft Labels
                                               ↓
                                        Rule Extraction (Exp B, C, ...)
                                               ↓
                                        Rule Set (human-readable)
                                               ↓
                                    eBPF-aware Rule Compiler
                                               ↓
                              Enforcement engine (Falco/Tetragon/Cedar/CEL)

[Online]
  eBPF collector → syscall stream → Rule evaluation → Alert/Block
                                               ↓ (uncertain cases)
                                    Userspace Teacher fallback (optional)
```

**Teacher:** Encoder-only Transformer, target F1 ≥ 90% (đủ tốt làm Teacher, không cần SOTA). Temperature scaling T ∈ [1,5] để tạo informative soft labels. So sánh với LSTM baseline — dùng model tốt hơn làm Teacher.

**eBPF constraints:** Rule phải thỏa eBPF verifier — không Turing-complete, stack ≤512 bytes, integer-only arithmetic, branching factor giới hạn. Constraints tích hợp vào training phase (max_depth, complexity penalty, rule length prior).

---

## 4. Datasets

| Tier   | Dataset     | Quy mô                           | Features                        |
| ------ | ----------- | -------------------------------- | ------------------------------- |
| Tier 1 | LID-DS-2021 | 17,190 recordings, 15 scenarios  | + exploit timestamps, pre-split |
| Tier 1 | DongTing    | 18,966 sequences                 | Syscall name only               |
| Tier 1 | LID-DS-2019 | ~11,000 recordings, 10 scenarios | + timestamp, thread_id, args    |

Tier 2 (multi-thread, rich features) chỉ trên LID-DS — extension goal.

**Lưu ý cross-domain (C6):** DongTing chỉ có syscall name → khi test cross-domain phải drop features của LID-DS Teacher xuống còn syscall name. Cần quyết định: train Teacher riêng mỗi dataset, hay dùng feature-reduced Teacher cho cross-domain test.

---

## 5. Scope: Core → Extension

### Core (phải hoàn thành — đủ cho thesis)

| #   | Nội dung                                                                                            | Trả lời      |
| --- | --------------------------------------------------------------------------------------------------- | ------------ |
| C1  | **Teacher training**, F1 ≥ 90%                                                                      | Prerequisite |
| C2  | **SHAP feature selection** — rank feature importance từ Teacher, chọn top-K làm input cho surrogate | RQ1          |
| C3  | **Exp B: Decision Tree Surrogate** — distilled vs direct, full features vs SHAP-selected            | RQ1, RQ2     |
| C4  | **Exp C: RuleFit** — distilled vs direct, full features vs SHAP-selected                            | RQ1, RQ2     |
| C5  | **Ablation study** distilled vs direct trên B, C                                                    | RQ2          |
| C6  | **Rule analysis** — 5-10 rules cụ thể, map MITRE ATT&CK, so sánh Falco                              | RQ1          |
| C7  | **Cross-domain validation** — train LID-DS → test DongTing (hoặc ngược lại)                         | RQ4 (basic)  |

> **SHAP role:** Không phải experiment độc lập — là preprocessing step cho C3/C4. Tạo thêm một ablation tự nhiên (full vs SHAP-selected features) mà không tốn nhiều công. Dùng `shap.TreeExplainer` hoặc `shap.DeepExplainer` tùy Teacher architecture.

Kết quả nào cũng là contribution:

- Distilled > Direct → validate KD pathway
- Distilled ≈ Direct → negative result có giá trị, community nên train trực tiếp
- Distilled < Direct → interesting finding, phân tích tại sao

### Extension Tier 1 (nếu core xong trước tháng 7)

| #   | Nội dung                                                                      | Trả lời     |
| --- | ----------------------------------------------------------------------------- | ----------- |
| E1  | **Exp D: BRL/CORELS** — thêm uncertainty routing angle                        | RQ1         |
| E2  | **Exp E: Anchors** — per-attack-type conditions, so sánh với C6 MITRE mapping | RQ1         |
| E3  | **Domain-informed priors** — MITRE/Falco structural priors cho surrogate B, C | RQ1         |
| E4  | **OOD evaluation** — cross-scenario trên LID-DS-2021 (web → DB scenarios)     | RQ4         |
| E5  | **Thêm ablations** — window size, temperature T, tree depth Pareto frontier   | RQ1, RQ2    |
| E6  | **eBPF Rule Compiler POC** — compile DT rules thành Falco/Tetragon format     | Engineering |

> **Anchors role:** Không thay thế DT/RuleFit (coverage thấp), nhưng complement tốt — tạo per-attack-type rules dạng `IF syscall_A AND syscall_B THEN attack (conf ≥ X%)`, dễ map sang MITRE hơn DT. Dùng `alibi` library. So sánh trực tiếp với rule set từ C6.

### Extension Tier 2 (nếu extension 1 xong trước tháng 9)

| #   | Nội dung                                                                     | Trả lời     |
| --- | ---------------------------------------------------------------------------- | ----------- |
| T1  | **Tier 2 features** — segment embeddings $E_{pid}$, multi-thread trên LID-DS | RQ3         |
| T2  | **Exp F: Temporal Logic Mining (LTL/STL)** — ordering constraints, SCARLET   | RQ1         |
| T3  | **Shadow Mode POC** — Teacher + Rules song song, monitor disagreement        | Engineering |
| T4  | **Exp G: Neuro-Symbolic** — exploratory, LTN/DeepProbLog                     | RQ1         |
| T5  | **Feedback Loop POC** — drift detection + incremental retrain                | RQ4         |

---

## 6. Metrics

| #   | Metric                                 | Target |
| --- | -------------------------------------- | ------ |
| 1   | Fidelity (rule vs Teacher)             | >95%   |
| 2   | Accuracy (vs ground truth)             | >93%   |
| 3   | FPR                                    | <1%    |
| 4   | Attack-class Fidelity                  | >90%   |
| 5   | Rule Complexity (rules × conditions)   | Thấp   |
| 6   | Interpretability Level (L1-L5)         | Thấp   |
| 7   | Distillation Gain (distilled - direct) | >0     |
| 8   | OOD Fidelity (cross-domain)            | >85%   |

Bổ sung (nếu relevant): weighted fidelity, class-conditional fidelity, eBPF deployability score.

---

## 7. Baselines

- **STIDE** — lower bound detection
- **LSTM/DeepLog** — so sánh Teacher architecture
- **Random Forest** — performance ceiling (~94% accuracy trực tiếp)
- **Hand-written Falco rules** — benchmark readability
- **Direct-trained surrogates** — baseline trực tiếp cho giá trị distillation

---

## 8. Key Design Decisions

- **Interpretability Taxonomy L1-L5:** L1 atomic boolean → L2 conjunctive → L3 ordered sequence → L4 probabilistic → L5 symbolic predicate. Mục tiêu: fidelity cao ở mức diễn giải thấp (L1-L2).
- **eBPF deployability:** DT, RuleFit, BRL → Yes (if-else chain). Anchors → Limited. LTL → Partial. Neuro-Symbolic → No.
- **Error propagation:** Deployed Error ≤ Teacher Error + Distillation Error. Class-conditional fidelity là metric bắt buộc vì imbalanced data.
- **Domain-informed priors (extension):** MITRE ATT&CK + Falco rules làm structural prior — feature weighting, cost-sensitive splitting.
- **Uncertainty routing (extension):** eBPF rules xử lý clear cases, uncertain cases escalate lên userspace.

---

## 9. Temperature Calibration (P2 checkpoint)

**Mục tiêu:** Tìm T tối ưu cho distillation, không chỉ calibrate probability.

**Quy trình:**

1. **Platt scaling** trên val set → T_calib (minimize NLL). Dùng làm starting point.
2. **Sweep T** ∈ [1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0] → train surrogate DT với mỗi T → đo Fidelity + Attack-class Fidelity → chọn T\* tại knee/peak của curve.
3. **Chọn T\*** dựa trên surrogate fidelity, không phải NLL. Validate trên test set một lần duy nhất.

**Checkpoint trước khi qua P3 — phải pass cả ba:**

```
☐ Soft label entropy của attack class > normal class
  (nếu ngược lại → Teacher chưa học tốt, debug trước)

☐ Reliability diagram: Teacher overconfident → T_calib > 1 (đúng hướng)

☐ DT fidelity tăng khi T tăng từ 1 → 3
  (nếu flat → surrogate không học được từ soft label → early warning cho RQ2)
```

---

## 10. Ablation Design (C5)

**Primary metric: Attack-class Fidelity** (overall fidelity bị dominated bởi normal class do imbalanced data).

**Framework so sánh — DT (tương tự cho RuleFit):**

| Method                        | Attack Fidel. | Overall Fidel. | FPR | #Rules | #Conds |
| ----------------------------- | ------------- | -------------- | --- | ------ | ------ |
| DT-Hard-Label (full features) |               |                |     |        |        |
| DT-Soft-T1 (full features)    |               |                |     |        |        |
| DT-Soft-T\* (full features)   |               |                |     |        |        |
| DT-Soft-T\* (SHAP-selected)   |               |                |     |        |        |
| RF-Direct (ceiling)           |               |                |     |        |        |

> Isolate 3 nguồn gain: Hard vs Soft-T1 → giá trị soft label. Soft-T1 vs Soft-T\* → giá trị temperature. Full vs SHAP-selected → giá trị feature selection (rule complexity có giảm không?)

**Quy tắc fix hyperparameter:** Luôn fix `max_depth` và các hyperparameter khác giống nhau giữa distilled và direct. Chỉ thay đổi label source. Nếu muốn sweep depth → làm riêng Pareto frontier plot, không mix vào ablation chính.

**Tiebreaker khi Fidelity ngang nhau:** FPR → Rule Complexity → prefer simpler.

---

## 11. Timeline

| Phase    | Thời gian   | Nội dung                                                          | Deliverable                   | Scope  | Status |
| -------- | ----------- | ----------------------------------------------------------------- | ----------------------------- | ------ | ------ |
| **P1**   | Tháng 1-2   | Data pipeline, EDA trên LID-DS-2021 + DongTing                    | Pipeline + EDA report         | Core   |        |
| **P1.5** | Tháng 2     | Pilot: DT distilled vs direct trên DongTing (early validation)    | Pilot results → quyết định    | Core   |        |
| **P2**   | Tháng 3-4   | Train Teacher, temperature calibration, LSTM baseline             | Calibrated Teacher checkpoint | Core   |        |
| **P3**   | Tháng 5-6   | Exp B + C, distilled vs direct, ablation study                    | Rule sets + Ablation report   | Core   |        |
| **P4**   | Tháng 7     | Rule analysis, cross-domain validation, **core thesis viết được** | Core results complete         | Core   |        |
| **P5**   | Tháng 7-8   | Exp D (BRL), domain priors, OOD eval, thêm ablations              | Extension 1 results           | Ext. 1 |        |
| **P6**   | Tháng 8-9   | eBPF Rule Compiler POC                                            | Compiler POC                  | Ext. 1 |        |
| **P7**   | Tháng 9-10  | Tier 2 features, Exp E/F/G, Shadow Mode                           | Extension 2 results           | Ext. 2 |        |
| **P8**   | Tháng 11-12 | Viết luận văn, bảo vệ                                             | Thesis draft                  | —      |        |

**Pivot point (P1.5):** Nếu distillation gain nhỏ → chuyển focus sang comparative study methods + domain-informed priors, giảm emphasis KD.

**Nguyên tắc:** Core xong trước tháng 7 → có 4 tháng buffer cho extensions + viết thesis. Không bao giờ hy sinh chất lượng core để chạy extension.

---

## 12. Đóng góp

### Core contribution (đủ cho thesis)

1. **First empirical study:** KD từ Transformer cho syscall-based HIDS rule extraction — bao gồm ablation distilled vs. direct training.
2. **Comparative study** Decision Tree vs RuleFit surrogate — fidelity, complexity, interpretability trade-offs.
3. **SHAP-informed feature selection** — ablation full features vs top-K SHAP features, đánh giá trade-off fidelity vs rule complexity.
4. **Rule quality analysis** — mapping rules sinh ra với MITRE ATT&CK, so sánh với hand-written Falco rules.

### Extended contributions (nếu kịp)

5. **Anchors comparison** — per-attack-type rules, so sánh coverage và MITRE alignment với DT/RuleFit.
6. **Thêm surrogate methods** — BRL/CORELS, Temporal Logic, Neuro-Symbolic.
7. **eBPF-aware rule optimization** — rule sinh ra thỏa eBPF verifier constraints.
8. **Multi-thread handling** — segment embeddings cho cross-thread pattern detection.
9. **Shadow Mode + Feedback Loop** — POC cho production deployment cycle.

**Ngoài phạm vi (future work):** Adversarial robustness (SCAR), production-grade deployment, user study quy mô lớn, Learnable KD.
