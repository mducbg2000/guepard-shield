# RuleDistill — Trích xuất Security Rule từ Transformer Phân loại Syscall

---

## 1. Mục tiêu

Pipeline **RuleDistill** — dùng Transformer làm Teacher Oracle để distill tri thức phát hiện tấn công syscall thành **security rule dạng human-readable**, deployable trên eBPF enforcement engines.

- Transformer học offline, rule enforce online (không inference model lúc runtime).
- Soft labels từ Teacher cung cấp richer supervision hơn hard labels → surrogate học decision boundary tốt hơn train trực tiếp.
- Rule set mục tiêu: Fidelity >95% vs Teacher, FPR <1%, đủ ngắn gọn để analyst đọc hiểu.

**Framing chính (security-oriented):** Nghiên cứu giải quyết gap giữa detection accuracy của neural model và deployability trong security operations — phần lớn bài báo syscall anomaly detection dừng ở accuracy table, không đi đến enforcement layer với latency measurement và rule auditability. RuleDistill bridge gap này bằng pipeline end-to-end từ model → interpretable rule → eBPF enforcement.

---

## 2. Threat Model

### 2.1 Scope

- **Đối tượng bảo vệ:** Linux host chạy server workload (web server, database, microservice).
- **Monitoring layer:** Syscall-level — lớp thấp nhất mà application phải đi qua để tương tác với kernel.
- **Deployment context:** Containerized và bare-metal Linux, enforce bằng eBPF (Falco/Tetragon).

### 2.2 Attacker Model

- **Capability:** Post-exploitation attacker đã có code execution trên host (qua vulnerability exploit, supply chain, hoặc credential compromise). Attacker thực hiện các hành vi như reverse shell, privilege escalation, data exfiltration, persistence installation — tất cả đều để lại syscall footprint.
- **Knowledge:** **Black-box** — attacker không biết cụ thể rule set nào đang enforce. Đây là assumption hợp lý vì rule được sinh tự động và thay đổi theo model/data, không phải static public ruleset.
- **Ngoài scope:** Adversarial evasion (attacker cố tình modify syscall sequence để bypass detection) — đây là threat thực nhưng thuộc future work, cần adversarial robustness analysis riêng (xem SCAR framework). Kernel-level rootkit cũng ngoài scope vì eBPF monitor có thể bị subvert.

### 2.3 Security Goal

- **Detection:** Phát hiện post-exploitation behavior qua syscall pattern bất thường.
- **Enforcement:** Block hoặc alert real-time với latency overhead chấp nhận được (< 2µs/syscall).
- **Auditability:** Rule sinh ra phải human-readable để security analyst review, approve, và map với threat intelligence (MITRE ATT&CK).

### 2.4 Assumptions

- Syscall tracing infrastructure (eBPF) là trusted và không bị tamper.
- Training data representative cho normal workload behavior (cần validate trên real workload — xem C10).
- Attack patterns trong dataset cover các MITRE technique phổ biến ở post-exploitation phase.

---

## 3. Research Questions & Hypotheses

| RQ      | Câu hỏi                                                                        | Giả thuyết                                                                                |
| ------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| **RQ1** | Phương pháp nào đạt cân bằng tốt nhất giữa Fidelity, FPR, và Rule Complexity?  | H1: Decision Tree (B) và RuleFit (C) đạt Fidelity >95% với rule set compact.              |
| **RQ2** | Distillation có tạo rule tốt hơn train trực tiếp trên hard labels không?       | H2: Distillation cải thiện Attack-class Fidelity ≥3-5%, đặc biệt cho multi-stage attacks. |
| **RQ3** | Rich features (thread, timing, args) cải thiện bao nhiêu so với sequence-only? | H3: Tier 2 features cải thiện Fidelity trên LID-DS, đặc biệt cross-thread attacks.        |
| **RQ4** | Rule generalize cross-scenario/cross-domain đến mức nào?                       | H4: OOD fidelity thấp hơn nhưng Feedback Loop thu hẹp gap sau 2-3 chu kỳ.                 |
| **RQ5** | Phase-aware rule set có giảm FPR so với single-policy không?                   | H5: Per-phase surrogate giảm FPR ≥15% so với single-policy trên cùng Teacher.             |
| **RQ6** | Rule sinh ra deploy được trên eBPF với overhead chấp nhận được không?          | H6: Latency < 2µs/syscall, FPR trên real workload < 5%.                                   |

> RQ1-RQ2 là core ML contribution. RQ5-RQ6 là core security contribution. RQ3-RQ4 là extension.

---

## 4. Pipeline Overview

```
[Offline]
  Syscall Traces → Feature Engineering → Transformer Teacher
                                               ↓
                              ┌─────────────────┴──────────────────┐
                              ↓                                    ↓
                    Temperature-scaled                    Phase Segmenter
                      Soft Labels                    (startup/active/idle/shutdown)
                              ↓                                    ↓
                              └─────────────┬──────────────────────┘
                                            ↓
                              Rule Extraction (Exp B, C, ...)
                              (single-policy + per-phase variants)
                                            ↓
                                    Rule Set (human-readable)
                                            ↓
                              eBPF-aware Rule Compiler (C9)
                                            ↓
                              Enforcement engine (Falco/Tetragon/Cedar/CEL)

[Online]
  eBPF collector → syscall stream → Rule evaluation → Alert/Block
                                            ↓ (uncertain cases)
                              Userspace Teacher fallback (optional)
```

**Teacher:** Encoder-only Transformer, target F1 ≥ 90% (đủ tốt làm Teacher, không cần SOTA). Temperature scaling T ∈ [1,5] để tạo informative soft labels. So sánh với LSTM baseline — dùng model tốt hơn làm Teacher.

**Phase Segmenter:** Sliding window trên syscall rate (events/100ms), phân lifecycle thành 4 phases:

- **Startup**: rate tăng nhanh (process initialization, library loading)
- **Active**: rate ổn định cao (main workload)
- **Idle**: rate thấp (waiting state)
- **Shutdown**: rate giảm về 0 (cleanup, resource release)

**Security motivation cho phase segmentation:** Startup phase có burst of `execve`, `open`, `mmap` — nếu dùng single-policy, các syscall này dễ trigger false positive vì giống exploitation pattern. Đồng thời, nhiều attack (reverse shell, persistence) xảy ra trong active phase — per-phase model có thể learn tighter boundary cho phase này mà không bị confound bởi startup noise. Validate assumption này bằng: (1) phân tích distribution of attack labels per phase trên dataset, (2) so sánh per-phase FPR.

**eBPF constraints:** Rule phải thỏa eBPF verifier — không Turing-complete, stack ≤512 bytes, integer-only arithmetic, branching factor giới hạn. Constraints tích hợp vào training phase (max_depth, complexity penalty, rule length prior).

---

## 5. Datasets

| Tier   | Dataset     | Quy mô                           | Features                        |
| ------ | ----------- | -------------------------------- | ------------------------------- |
| Tier 1 | LID-DS-2021 | 17,190 recordings, 15 scenarios  | + exploit timestamps, pre-split |
| Tier 1 | DongTing    | 18,966 sequences                 | Syscall name only               |
| Tier 1 | LID-DS-2019 | ~11,000 recordings, 10 scenarios | + timestamp, thread_id, args    |

Tier 2 (multi-thread, rich features) chỉ trên LID-DS — extension goal.

**Lưu ý cross-domain (C8):** DongTing chỉ có syscall name → khi test cross-domain phải drop features của LID-DS Teacher xuống còn syscall name. Cần quyết định: train Teacher riêng mỗi dataset, hay dùng feature-reduced Teacher cho cross-domain test.

### Dataset Limitations & Validity Argument

**Limitation:** Cả 3 dataset đều là academic benchmark, không phải production traffic. LID-DS dùng các exploit scenario cụ thể (CVE-2014-0160, CVE-2017-7529, ...), nhiều cái đã cũ. Không có containerized workload (Docker/K8s).

**Tại sao vẫn valid cho RQs:**

- RQ1-RQ2 so sánh _relative performance_ giữa methods trên cùng data → valid bất kể data có production-representative hay không.
- RQ5 đo _relative FPR reduction_ giữa single vs per-phase → cũng valid trên benchmark.
- RQ6 (eBPF latency) đo trên real kernel, không phụ thuộc dataset quality.
- C10 (real workload evaluation) bổ sung FPR measurement trên production-like traffic để address gap này.

---

## 6. Scope: Core → Extension

### Core (phải hoàn thành — đủ cho thesis)

| #   | Nội dung                                                                                            | Trả lời      |
| --- | --------------------------------------------------------------------------------------------------- | ------------ |
| C1  | **Teacher training**, F1 ≥ 90%                                                                      | Prerequisite |
| C2  | **SHAP feature selection** — rank feature importance từ Teacher, chọn top-K làm input cho surrogate | RQ1          |
| C3  | **Exp B: Decision Tree Surrogate** — distilled vs direct, full features vs SHAP-selected            | RQ1, RQ2     |
| C4  | **Exp C: RuleFit** — distilled vs direct, full features vs SHAP-selected                            | RQ1, RQ2     |
| C5  | **Ablation study** distilled vs direct trên B, C                                                    | RQ2          |
| C6  | **Phase-aware ablation** — single-policy vs per-phase surrogate trên cùng Teacher                   | RQ5          |
| C7  | **Rule analysis + MITRE mapping** — xem chi tiết bên dưới                                           | RQ1          |
| C8  | **Cross-domain validation** — train LID-DS → test DongTing (hoặc ngược lại)                         | RQ4 (basic)  |
| C9  | **eBPF Rule Compiler** — compile DT rules thành if-else chain, verify bằng BPF verifier, đo latency | RQ6          |
| C10 | **Real workload evaluation** — đo FPR và latency trên production-like application                   | RQ6          |

> **SHAP role:** Không phải experiment độc lập — là preprocessing step cho C3/C4. Tạo thêm một ablation tự nhiên (full vs SHAP-selected features) mà không tốn nhiều công. Dùng `shap.TreeExplainer` hoặc `shap.DeepExplainer` tùy Teacher architecture.

#### C7 — Rule Analysis & MITRE Mapping (chi tiết)

Đây là section quan trọng nhất cho security audience. Không chỉ là "5-10 rules cụ thể" — cần structured analysis:

**7a. MITRE ATT&CK Coverage Analysis:**

- Map mỗi attack scenario trong dataset → MITRE technique ID (VD: LID-DS CVE-2014-0160 → T1190 Exploit Public-Facing Application)
- Với mỗi technique, kiểm tra rule sinh ra có detect được không → tạo coverage matrix
- So sánh coverage với Falco default ruleset trên cùng technique set

**7b. Head-to-head Falco Comparison:**

- Lấy Falco default ruleset (falcosecurity/rules repo), chạy trên cùng test set
- So sánh: detection rate, FPR, số rules, rule complexity
- Qualitative: rule sinh ra có bắt được pattern mà Falco rules miss không? Và ngược lại?

**7c. Case Study (2-3 attack scenarios):**

- Chọn 2-3 CVE/attack cụ thể, walk through:
  - Syscall sequence của attack
  - Rule nào fire, tại sao
  - Rule có bắt đúng root cause hay chỉ bắt side effect?
  - So sánh với Falco rule tương ứng

**7d. Rule Auditability Assessment:**

- Mời 1-2 security practitioner (advisor, đồng nghiệp) review 10 rules → đánh giá:
  - Rule có dễ hiểu không? (scale 1-5)
  - Analyst có tin tưởng deploy rule này không?
  - Gợi ý chỉnh sửa gì?
- Không cần formal user study — informal feedback đủ cho thesis, note lại là limitation

#### C9 — eBPF Rule Compiler (chi tiết)

**Scope (giới hạn cho core):**

1. Lấy DT rules đã trích từ C3 → convert thành if-else chain dạng C
2. Compile thành eBPF program (sử dụng Aya framework / Rust)
3. Hook vào `tracepoint/raw_syscalls/sys_enter`
4. Load rule set vào BPF hash map
5. Đo latency overhead per syscall (mục tiêu < 2µs)
6. Đo FPR / FNR trên test set với live enforcement

**So sánh với seccomp-BPF:**

- seccomp-BPF: per-syscall allow/deny, không có state, không nhìn được cross-syscall pattern
- RuleDistill rules: encode sequential pattern (n-gram, transition) → richer policy
- Tradeoff: seccomp-BPF có latency thấp hơn (kernel-native), RuleDistill rules linh hoạt hơn
- Đưa so sánh này vào thesis discussion section

**Không thuộc core scope:** conflict resolution giữa multiple rule sources, dynamic rule reloading, uncertainty routing.

#### C10 — Real Workload Evaluation (chi tiết)

**Mục tiêu:** Validate rằng rules không gây excessive false positive trên production-like traffic.

**Setup:**

- Chạy 2-3 application phổ biến: nginx (web server), redis (cache), postgres (database)
- Thu thập syscall trace bằng eBPF trong 30-60 phút normal operation (benchmark traffic bằng wrk/pgbench)
- Apply rule set từ C3/C4 lên traces → đo FPR
- Apply cùng rule set qua eBPF enforcement → đo latency overhead dưới load

**Kỳ vọng:** FPR sẽ cao hơn trên real workload so với benchmark dataset (vì workload behavior đa dạng hơn training data). Target FPR < 5% — nếu cao hơn thì cần thảo luận vì sao và gợi ý cách cải thiện (fine-tuning, per-application model, ...).

**Effort:** ~1-2 tuần setup + measurement. Không cần infrastructure phức tạp — chạy trên VM hoặc container đủ.

Kết quả nào cũng là contribution:

- Distilled > Direct → validate KD pathway
- Distilled ≈ Direct → negative result có giá trị, community nên train trực tiếp
- Distilled < Direct → interesting finding, phân tích tại sao
- Phase-aware > Single-policy → validate lifecycle-aware enforcement
- Real workload FPR thấp → validate practical deployment
- Real workload FPR cao → honest assessment, propose mitigation

### Extension Tier 1 (nếu core xong trước tháng 7)

| #   | Nội dung                                                                                        | Trả lời  |
| --- | ----------------------------------------------------------------------------------------------- | -------- |
| E1  | **Exp D: BRL/CORELS** — thêm uncertainty routing angle                                          | RQ1      |
| E2  | **Exp E: Anchors** — per-attack-type conditions, so sánh với C7 MITRE mapping                   | RQ1      |
| E3  | **Domain-informed priors** — MITRE/Falco structural priors cho surrogate B, C                   | RQ1      |
| E4  | **OOD evaluation** — cross-scenario trên LID-DS-2021 (web → DB scenarios)                       | RQ4      |
| E5  | **Thêm ablations** — window size, temperature T, tree depth Pareto frontier                     | RQ1, RQ2 |
| E6  | **eBPF dynamic phase loading** — load per-phase rule set dựa trên proc.duration và syscall_rate | RQ5, RQ6 |

> **Anchors role:** Không thay thế DT/RuleFit (coverage thấp), nhưng complement tốt — tạo per-attack-type rules dạng `IF syscall_A AND syscall_B THEN attack (conf ≥ X%)`, dễ map sang MITRE hơn DT. Dùng `alibi` library. So sánh trực tiếp với rule set từ C7.

### Extension Tier 2 (nếu extension 1 xong trước tháng 9)

| #   | Nội dung                                                                     | Trả lời     |
| --- | ---------------------------------------------------------------------------- | ----------- |
| T1  | **Tier 2 features** — segment embeddings $E_{pid}$, multi-thread trên LID-DS | RQ3         |
| T2  | **Exp F: Temporal Logic Mining (LTL/STL)** — ordering constraints, SCARLET   | RQ1         |
| T3  | **Shadow Mode POC** — Teacher + Rules song song, monitor disagreement        | Engineering |
| T4  | **Exp G: Neuro-Symbolic** — exploratory, LTN/DeepProbLog                     | RQ1         |
| T5  | **Feedback Loop POC** — drift detection + incremental retrain                | RQ4         |
| T6  | **Hidden State Clustering** — cluster hidden states thành abstract features  | RQ1         |

---

## 7. Metrics

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
| 9   | Phase-aware FPR Reduction (vs single)  | >15%   |
| 10  | eBPF Latency Overhead (per syscall)    | <2µs   |
| 11  | MITRE ATT&CK Coverage (% techniques)   | Report |
| 12  | Real Workload FPR                      | <5%    |

Bổ sung (nếu relevant): weighted fidelity, class-conditional fidelity, eBPF deployability score, per-phase FPR breakdown, Falco head-to-head comparison metrics.

---

## 8. Baselines

- **STIDE** — lower bound detection
- **LSTM/DeepLog** — so sánh Teacher architecture
- **Random Forest** — performance ceiling (~94% accuracy trực tiếp)
- **Falco default ruleset** — head-to-head comparison trên cùng dataset: detection rate, FPR, rule count, complexity
- **seccomp-BPF** — so sánh enforcement mechanism: latency, expressiveness, deployment complexity
- **Direct-trained surrogates** — baseline trực tiếp cho giá trị distillation
- **Single-policy surrogate** — baseline cho giá trị phase-aware policy

---

## 9. Key Design Decisions

- **Interpretability Taxonomy L1-L5:** L1 atomic boolean → L2 conjunctive → L3 ordered sequence → L4 probabilistic → L5 symbolic predicate. Mục tiêu: fidelity cao ở mức diễn giải thấp (L1-L2).
- **eBPF deployability:** DT, RuleFit, BRL → Yes (if-else chain). Anchors → Limited. LTL → Partial. Neuro-Symbolic → No.
- **Error propagation:** Deployed Error ≤ Teacher Error + Distillation Error. Class-conditional fidelity là metric bắt buộc vì imbalanced data.
- **Domain-informed priors (extension):** MITRE ATT&CK + Falco rules làm structural prior — feature weighting, cost-sensitive splitting.
- **Uncertainty routing (extension):** eBPF rules xử lý clear cases, uncertain cases escalate lên userspace.
- **Phase segmentation:** Sliding window trên syscall rate — đơn giản, deterministic, không cần train thêm model. Security motivation: tách startup noise khỏi active-phase detection boundary.

---

## 10. Temperature Calibration (P2 checkpoint)

**Mục tiêu:** Tìm T tối ưu cho distillation, không chỉ calibrate probability.

**Quy trình:**

1. **Platt scaling** trên val set → T_calib (minimize NLL). Dùng làm starting point.
2. **Sweep T** ∈ [1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0] → train surrogate DT với mỗi T → đo Fidelity + Attack-class Fidelity → chọn T\* tại knee/peak của curve.
3. **Chọn T\*** dựa trên surrogate fidelity, không phải NLL. Validate trên test set một lần duy nhất.

**Checkpoint trước khi qua P3 — phải pass cả ba:**

- [ ] Soft label entropy của attack class > normal class
      (nếu ngược lại → Teacher chưa học tốt, debug trước)

- [ ] Reliability diagram: Teacher overconfident → T_calib > 1 (đúng hướng)

- [ ] DT fidelity tăng khi T tăng từ 1 → 3
      (nếu flat → surrogate không học được từ soft label → early warning cho RQ2)

---

## 11. Ablation Design (C5 + C6)

### 11.1 Distillation Ablation (C5)

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

### 11.2 Phase-aware Ablation (C6)

**Framework so sánh — trên cùng DT-Soft-T\* configuration:**

| Method                    | FPR (startup) | FPR (active) | FPR (idle) | FPR (shutdown) | FPR (overall) | Attack Fidel. | #Rules |
| ------------------------- | ------------- | ------------ | ---------- | -------------- | ------------- | ------------- | ------ |
| Single-policy             |               |              |            |                |               |               |        |
| Per-phase (4 surrogates)  |               |              |            |                |               |               |        |
| Per-phase + SHAP-selected |               |              |            |                |               |               |        |

**Quy tắc fix hyperparameter:** Luôn fix `max_depth` và các hyperparameter khác giống nhau giữa distilled và direct, giữa single-policy và per-phase. Chỉ thay đổi một biến tại một thời điểm. Nếu muốn sweep depth → làm riêng Pareto frontier plot, không mix vào ablation chính.

**Tiebreaker khi Fidelity ngang nhau:** FPR → Rule Complexity → prefer simpler.

### Lưu ý về class imbalance (1:1.3-1.5)

- Dùng `class_weight='balanced'` trong surrogate training
- Metric chính: F1 và FPR@fixed_FNR thay vì accuracy
- Attack-class Fidelity là primary metric cho ablation (tránh bị dominated bởi normal class)

---

## 12. Timeline

| Phase    | Thời gian   | Nội dung                                                                                                       | Deliverable                            | Scope  | Status |
| -------- | ----------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------- | ------ | ------ |
| **P1**   | Tháng 1-2   | Data pipeline, EDA, implement phase segmenter, MITRE mapping cho dataset scenarios                             | Pipeline + EDA + phase seg + MITRE map | Core   |        |
| **P1.5** | Tháng 2     | Pilot: DT distilled vs direct trên DongTing (early validation)                                                 | Pilot results → quyết định             | Core   |        |
| **P2**   | Tháng 3-4   | Train Teacher, temperature calibration, LSTM baseline                                                          | Calibrated Teacher checkpoint          | Core   |        |
| **P3**   | Tháng 5-6   | Exp B + C, ablation distilled vs direct (C5), phase-aware ablation (C6)                                        | Rule sets + Ablation report            | Core   |        |
| **P4**   | Tháng 6-7   | Rule analysis + MITRE + Falco comparison (C7), cross-domain (C8), eBPF compiler (C9), real workload eval (C10) | Core results complete + eBPF POC       | Core   |        |
| **P4.5** | Tháng 7     | **Paper draft** — đóng gói C1+C3/C4+C6+C7+C9+C10 cho security venue                                            | Paper draft ready for advisor review   | Paper  |        |
| **P5**   | Tháng 7-8   | BRL, domain priors, OOD eval, thêm ablations                                                                   | Extension 1 results                    | Ext. 1 |        |
| **P6**   | Tháng 8-9   | eBPF dynamic phase loading, Anchors comparison                                                                 | Extended eBPF + Anchors results        | Ext. 1 |        |
| **P7**   | Tháng 9-10  | Tier 2 features, Temporal Logic, Shadow Mode                                                                   | Extension 2 results                    | Ext. 2 |        |
| **P8**   | Tháng 11-12 | Viết luận văn, bảo vệ                                                                                          | Thesis draft                           | —      |        |

**Pivot point (P1.5):** Nếu distillation gain nhỏ → chuyển focus sang comparative study methods + phase-aware contribution, giảm emphasis KD.

**Paper submission target:** RAID (deadline ~tháng 4, có second cycle), ACSAC (~tháng 6-7), hoặc AsiaCCS workshop. Chọn venue phù hợp dựa trên kết quả thực tế tại P4.

**Nguyên tắc:** Core xong trước tháng 7 → có 4 tháng buffer cho extensions + viết thesis. Không bao giờ hy sinh chất lượng core để chạy extension.

---

## 13. Publication Strategy (Hướng A — Security Venue)

### Target venues (rank B+)

- **RAID** (International Symposium on Research in Attacks, Intrusions and Defenses) — rank A, competitive nhưng phù hợp nhất
- **ACSAC** (Annual Computer Security Applications Conference) — rank A, applied security focus
- **DIMVA** (Detection of Intrusions and Malware & Vulnerability Assessment) — rank B, European, acceptance ~25-30%
- **SecureComm** — rank B, practical security
- **AsiaCCS workshop track** — dễ nhất, tốt cho first publication

### Paper framing (KHÔNG frame là bài KD/XAI)

**Title direction:** _"From Neural Detection to Kernel Enforcement: Automated Security Policy Generation for Syscall-based HIDS"_ hoặc tương tự — emphasize enforcement gap, không emphasize distillation.

**Selling points theo thứ tự:**

1. **End-to-end pipeline** từ model → rule → eBPF enforcement — phần lớn bài báo dừng ở accuracy
2. **Phase-aware policy** giảm FPR bằng lifecycle segmentation — security-motivated novelty
3. **eBPF deployment** với latency measurement trên real workload — practical contribution
4. **MITRE coverage analysis** và head-to-head Falco comparison — grounded in security operations
5. **Distillation ablation** — technical contribution nhưng đặt sau security contributions

### Paper content mapping từ core

| Paper section | Lấy từ core item                            |
| ------------- | ------------------------------------------- |
| Introduction  | Threat model + gap statement                |
| System Design | Pipeline + C9 (eBPF)                        |
| Methodology   | C1 + C3 (hoặc C4) + C6                      |
| Evaluation    | C5 + C7 + C10                               |
| Case Study    | C7c (2-3 CVE walkthrough)                   |
| Discussion    | seccomp-BPF comparison, dataset limitations |

### Những thứ bỏ ra khỏi paper (giữ cho thesis)

- SHAP feature selection details → mention briefly, detail trong thesis
- RuleFit vs DT comparison nếu paper quá dài → chọn method tốt hơn
- Cross-domain validation → thesis only
- Temperature calibration details → thesis only

---

## 14. Đóng góp

### Core contribution (đủ cho thesis)

1. **KD empirical study:** Đầu tiên áp dụng KD từ Transformer cho syscall-based HIDS rule extraction — bao gồm ablation distilled vs. direct training.
2. **Comparative study** Decision Tree vs RuleFit surrogate — fidelity, complexity, interpretability trade-offs.
3. **SHAP-informed feature selection** — ablation full features vs top-K SHAP features, đánh giá trade-off fidelity vs rule complexity.
4. **Phase-aware rule extraction** — lifecycle segmentation (startup/active/idle/shutdown) cho per-phase surrogate, ablation single-policy vs per-phase, với security motivation.
5. **Rule quality analysis** — MITRE ATT&CK coverage matrix, head-to-head Falco comparison, case study trên CVE cụ thể, informal auditability assessment.
6. **eBPF deployment + real workload validation** — compile rules → BPF-verifiable program, đo latency, validate FPR trên nginx/redis/postgres.

### Paper contribution (subset, security-framed)

1. **End-to-end pipeline** từ neural detection đến kernel-level enforcement — bridge detection-deployment gap
2. **Phase-aware enforcement** — lifecycle-aware policy giảm FPR
3. **eBPF deployment** với latency measurement trên real workload
4. **MITRE-grounded evaluation** — coverage analysis + Falco head-to-head + case study

### Extended contributions (nếu kịp)

5. **Anchors comparison** — per-attack-type rules, so sánh coverage và MITRE alignment với DT/RuleFit.
6. **Thêm surrogate methods** — BRL/CORELS, Temporal Logic, Neuro-Symbolic.
7. **eBPF dynamic phase loading** — runtime phase detection + rule switching.
8. **Multi-thread handling** — segment embeddings cho cross-thread pattern detection.
9. **Shadow Mode + Feedback Loop** — POC cho production deployment cycle.
10. **Hidden State Clustering** — cluster Teacher hidden states thành abstract features bổ sung cho surrogate.

**Ngoài phạm vi (future work):** Adversarial evasion resistance, production-grade deployment, formal user study, Learnable KD, kernel-level attacker.
