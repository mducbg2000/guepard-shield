# Design: P2–P4.5 Experiments — Từ LID-DS Teacher đến Paper Submission

**Date:** 2026-03-28
**Target venue:** ACSAC (~June–July 2026)
**Status:** Approved, pending implementation

---

## 1. Context & Locked Decisions

Pilot (P1.5) đã hoàn thành trên DongTing. Kết quả xác nhận distillation pathway:

| Model                                 | Accuracy  | F1        | Attack Fidelity |
| ------------------------------------- | --------- | --------- | --------------- |
| Direct DT (no class weighting)        | 0.866     | 0.853     | —               |
| Direct DT + `class_weight='balanced'` | 0.840     | 0.840     | —               |
| Distilled DT (T=4.0)                  | **0.947** | **0.945** | **0.980**       |

> **Canonical pilot:** Direct DT không dùng class weighting (accuracy 0.866). Thử nghiệm `class_weight='balanced'` cho thấy balanced chỉ flip bias (normal recall 68% → 96%, nhưng attack recall giảm 99.8% → 75.2%) — không giải quyết được vấn đề. Kết quả này lock quyết định #5 bên dưới: không dùng `class_weight='balanced'` trong P3.

BiLSTM Teacher đạt val_accuracy = 97.0% — đủ tiêu chuẩn Teacher tốt.

**Decisions locked:**

| #   | Decision             | Choice                                                  |
| --- | -------------------- | ------------------------------------------------------- |
| 1   | Primary dataset      | LID-DS-2021                                             |
| 2   | Secondary dataset    | DongTing (cross-domain C8)                              |
| 3   | Teacher architecture | BiLSTM vs Transformer → compare → pick winner           |
| 4   | Approach             | Hybrid: shared `src/` modules + per-experiment scripts  |
| 5   | Surrogates           | Exp B (DT, HSTree, FIGS) + Exp C (RuleFit, BoostedRules) với SHAP feature selection |
| 6   | Phase segmentation   | syscall_rate từ timestamp → 4 phases                    |
| 7   | Scenario selection   | 5 in-dist + 3 OOD (xem §3)                              |

---

## 2. Codebase Structure — Additions

Chỉ liệt kê files mới cần thêm. Files hiện có không thay đổi interface.

```
src/guepard/
├── data_loader/
│   ├── lidds_corpus.py          # LID-DS .sc + .json parser, SequenceMeta extension
│   └── phase_segmenter.py       # timestamp → syscall_rate → phase labels
├── features/
│   └── shap_selector.py         # SHAP wrapper, top-K feature selection
├── models/
│   ├── surrogate_factory.py     # Unified factory: DT, HSTree, FIGS, RuleFit, BoostedRules via imodels
│   └── rule_extractor.py        # DT/HSTree/FIGS/RuleFit/BoostedRules → human-readable IF-THEN text
└── evaluation/
    ├── metrics.py               # fidelity, per-phase FPR, attack-class fidelity
    └── mitre_mapper.py          # scenario name → MITRE technique mapping

notebooks/
├── p2_teacher_lidds.py          # P2: Teacher training + temperature sweep
├── p3a_exp_b_dt.py              # P3: Exp B — DT ablation matrix
├── p3b_exp_c_rulefit.py         # P3: Exp C — RuleFit ablation matrix
├── p3c_phase_ablation.py        # P3: C6 — phase-aware vs single-policy
├── p4a_rule_analysis.py         # P4: C7 — rules + MITRE + Falco comparison
├── p4b_cross_domain.py          # P4: C8 — LID-DS → DongTing cross-domain
├── p4c_ebpf_compiler.py         # P4: C9 — eBPF rule compiler + latency
├── p4d_real_workload.py         # P4: C10 — nginx/redis real workload FPR
└── p45_paper_tables.py          # P4.5 — generate LaTeX tables + figures from artifacts
```

---

## 3. Scenario Selection (LID-DS-2021)

### In-distribution (training + validation)

| Scenario             | CVE/CWE                  | MITRE Technique                     |
| -------------------- | ------------------------ | ----------------------------------- |
| CVE-2014-0160        | Heartbleed               | T1190 Exploit Public-Facing App     |
| CVE-2017-7529        | Nginx OOB read           | T1190 + T1083 File Discovery        |
| CWE-89-SQL-injection | SQL Injection            | T1190 SQL Injection                 |
| Bruteforce_CWE-307   | Brute force auth         | T1110 Brute Force                   |
| EPS_CWE-434          | Unrestricted file upload | T1190 + T1105 Ingress Tool Transfer |

Mục tiêu: cover 4 MITRE tactic classes — Initial Access, Credential Access, Injection, File Upload.

### OOD (test only — không dùng cho training)

| Scenario      | CVE                    | Attack Type        |
| ------------- | ---------------------- | ------------------ |
| CVE-2020-9484 | Tomcat deserialization | Deserialization    |
| CVE-2019-5418 | Rails path traversal   | Path Traversal     |
| ZipSlip       | ZipSlip                | Archive Extraction |

OOD scenarios thuộc attack type khác in-dist → test generalization thực sự.

---

## 4. P2 — LID-DS Corpus Loader & Teacher Training

### 4.1 LID-DS Corpus Loader (`lidds_corpus.py`)

**Input format (.sc):**

```
timestamp_ns  thread_id  pid  process_name  pid  syscall_name  direction  [args]
1631610469545444381  0  821119  apache2  821119  select  <  res=0
```

**Design:**

- Chỉ giữ syscall exit events (`<`) — có `res=`, tránh duplicate tokens. Consistent với LID-DS literature.
- `SequenceMeta` extend: thêm `scenario: str`, `has_exploit: bool`, `exploit_time_ns: int | None` (từ `.json`).
- `iter_sequences()` → `(seq_id, label, tokens: List[str])` — Tier 1 (syscall names only)
- `iter_sequences_rich()` → `(seq_id, label, events: List[dict])` — Tier 2 (timestamp + syscall + thread)
- Split theo thư mục `training/`, `validation/`, `test/` trong mỗi scenario.

### 4.2 Phase Segmenter (`phase_segmenter.py`)

**Input:** List of `(timestamp_ns, syscall_name)` từ một recording
**Output:** Per-event phase label ∈ `{startup, active, idle, shutdown}`

**Algorithm:**

```
sliding window = 100ms → compute syscall_rate (events/window)
thresholds: P25 và P75 của rate distribution per recording (percentile-based, không hardcode)

startup:  first N consecutive windows until rate stabilizes (rate variance < threshold)
active:   rate > P75 và stable
idle:     rate < P25
shutdown: rate monotonically decreasing ở cuối recording
```

Percentile-based thresholds → tự adapt theo workload intensity, không cần tune per-dataset.

### 4.3 Teacher Training (`p2_teacher_lidds.py`)

**Bước 1 — Architecture Comparison:**

- Train BiLSTM và Transformer trên combined 5 in-dist scenarios
- Cùng: seed, train/val split (theo thư mục LID-DS), hyperparams từ `TeacherConfig`
- Metric: F1 trên val set — target ≥ 0.90
- Pick winner → Teacher chính thức cho P3+

**Bước 2 — Temperature Sweep:**

- Platt scaling trên val set → T_calib (minimize NLL) — starting point
- Sweep T ∈ {1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0}
- Với mỗi T: train DT-Soft-T (depth=5) → measure Attack Fidelity trên **val set**
- T\* = T tại peak Attack Fidelity trên val set
- **Final metrics (P3+) luôn dùng test set** — val set chỉ dùng để chọn T\*, không dùng cho final evaluation tránh bias
- Plot: T vs Attack Fidelity curve → figure cho thesis

**P2 Checkpoint — phải pass cả 3 trước khi tiếp P3:**

- [ ] Soft label entropy(attack class) > Soft label entropy(normal class)
- [ ] T_calib > 1.0 (Teacher overconfident → scaling đúng hướng)
- [ ] DT Attack Fidelity tăng khi T tăng từ 1.0 → 3.0

**Output artifacts:**

```
results/p2/
├── best_teacher_lidds.ckpt
├── teacher_comparison.json      # BiLSTM vs Transformer metrics
├── temperature_sweep.json       # T → Attack Fidelity mapping
└── p2_checkpoint.json           # pass/fail cho 3 checkpoint criteria
```

---

## 5. P3 — Experiments B, C & Ablations

### 5.1 Feature Selection (`shap_selector.py`)

- **Layer TF-IDF (surrogate features):** dùng `sklearn.inspection.permutation_importance` trên DT-Hard-Full — nhanh, không phụ thuộc backend, cho rank feature importance đáng tin cậy. `shap.KernelExplainer` với 1000 features quá chậm.
- **Layer embedding (Teacher interpretability, optional):** `shap.GradientExplainer` với PyTorch autograd nếu cần visualize attention pattern — chỉ dùng cho thesis discussion, không dùng cho feature selection pipeline.
- Top-K = top 100 features theo mean permutation importance trên val set
- K = 100 là default; K là ablation parameter nếu cần sensitivity analysis
- Đổi tên artifact: `perm_importance.npy` thay vì `shap_values.npy`

### 5.2 Exp B — Tree Family Ablation (`p3a_exp_b_dt.py`)

3 models trong tree family, tất cả từ `imodels`:

- **DT** (`DecisionTreeClassifier` — sklearn): baseline tree
- **HSTree** (`HSTreeClassifierCV`): hierarchical shrinkage regularization → giảm overfitting, kỳ vọng OOD fidelity tốt hơn DT
- **FIGS** (`FIGSClassifier`): sum of small trees — mỗi tree nhỏ (depth ≤ 3), tổng vẫn interpretable (L2). Kỳ vọng fidelity cao hơn single DT nhờ additive structure mà vẫn eBPF-deployable (compile mỗi tree thành if-else chain rồi cộng score)

Fix `max_depth=5` (DT, HSTree) / `max_rules=10` (FIGS). Không dùng `class_weight='balanced'` — window imbalance đã được xử lý ở data level bằng `max_windows_per_seq`; thêm class_weight khi attack là majority class sẽ up-weight nhầm class và gây FN cao. Ablation matrix (evaluate trên **test set**):

| Config                | Label Source | Features     | Metric: Attack Fidelity | Overall Fidelity | FPR | #Rules | #Conds |
| --------------------- | ------------ | ------------ | ----------------------- | ---------------- | --- | ------ | ------ |
| DT-Hard-Full          | hard labels  | full n-gram  |                         |                  |     |        |        |
| DT-Soft-T1-Full       | soft T=1.0   | full n-gram  |                         |                  |     |        |        |
| DT-Soft-T\*-Full      | soft T=T\*   | full n-gram  |                         |                  |     |        |        |
| DT-Soft-T\*-PERM      | soft T=T\*   | top-100 perm |                         |                  |     |        |        |
| HSTree-Soft-T\*-Full  | soft T=T\*   | full n-gram  |                         |                  |     |        |        |
| FIGS-Soft-T\*-Full    | soft T=T\*   | full n-gram  |                         |                  |     |        |        |
| RF-Direct (ceiling)   | hard labels  | full n-gram  |                         |                  |     |        |        |

3 nguồn gain được isolate (trên DT):

- Hard vs Soft-T1 → giá trị soft label
- Soft-T1 vs Soft-T\* → giá trị temperature calibration
- Full vs PERM-selected → trade-off fidelity vs rule complexity

Cross-method comparison (cùng Soft-T\*, full features):

- DT vs HSTree → giá trị shrinkage regularization
- DT vs FIGS → giá trị additive tree structure

**Mỗi config chạy 3 seeds** → report mean ± std → đủ để claim statistical significance khi kết quả gần nhau.

**Pareto frontier plot:** depth ∈ {3, 5, 7, 10} × Attack Fidelity vs #Rules → figure cho paper. FIGS thêm axis: `max_rules` ∈ {5, 10, 15, 20}.

### 5.3 Exp C — Rule Ensemble Ablation (`p3b_exp_c_rulefit.py`)

2 models trong rule ensemble family, cả hai từ `imodels`:

- **RuleFit** (`RuleFitClassifier`): learn linear combination of rules extracted from tree ensemble
- **BoostedRules** (`BoostedRulesClassifier`): boosted ensemble of simple rules — cách tiếp cận khác RuleFit, mỗi rule là boolean condition + weight

Cùng ablation matrix như Exp B (distilled vs direct, full vs PERM), áp dụng cho cả RuleFit và BoostedRules. Thêm metric:

- **Rule complexity** = tổng literals trên tất cả rules (lower = more interpretable)

So sánh DT/HSTree/FIGS vs RuleFit/BoostedRules side-by-side trong cùng table → trả lời RQ1 với 5 surrogate methods.

**Hyperparameter tiebreaker:** Khi Fidelity ngang nhau → prefer lower FPR → lower Rule Complexity.

### 5.4 C6 — Phase-Aware Ablation (`p3c_phase_ablation.py`)

Fix config = winner Soft-T\*-Full từ Exp B/C (DT, HSTree, FIGS, RuleFit, hoặc BoostedRules — chọn model có best Attack Fidelity). Cùng Teacher.

| Policy                   | FPR startup | FPR active | FPR idle | FPR shutdown | FPR overall | Attack Fidelity | #Rules |
| ------------------------ | ----------- | ---------- | -------- | ------------ | ----------- | --------------- | ------ |
| Single-policy            |             |            |          |              |             |                 |        |
| Per-phase (4 surrogates) |             |            |          |              |             |                 |        |
| Per-phase + SHAP         |             |            |          |              |             |                 |        |

Train 4 phase-specific surrogates độc lập trên windows được label bởi phase segmenter.

**Expected result:** Per-phase FPR(startup) < Single-policy FPR(startup) — startup burst syscall không confound active-phase boundary.

**Output artifacts:**

```
results/p3/
├── exp_b_results.json           # mean ± std across 3 seeds
├── exp_c_results.json           # mean ± std across 3 seeds
├── phase_ablation.json
├── perm_importance.npy          # permutation importance scores (thay shap_values.npy)
├── pareto_dt.png
└── ablation_table.csv
```

---

## 6. P4 — Rule Analysis, Cross-Domain, eBPF, Real Workload

### 6.1 C7 — Rule Analysis & MITRE Mapping (`p4a_rule_analysis.py`)

**Rule extraction format:**

```
IF syscall_execve_count > 2 AND syscall_open_count > 5 THEN ATTACK (conf=0.97, support=0.43)
```

**MITRE coverage matrix:** Per-scenario, per-rule → check detection. Compare với Falco default ruleset (offline simulation — load falcosecurity/rules YAML, match trên syscall traces).

**Falco comparison metrics:** detection rate, FPR, rule count, mean rule length.

**Case studies (2 CVEs):**

1. CVE-2014-0160 (Heartbleed) — well-known, good narrative cho paper
2. CWE-89 SQL Injection — common web threat, clear syscall footprint

Per case study: syscall sequence của attack → which rules fire → map to MITRE → so sánh Falco equivalent.

### 6.2 C8 — Cross-Domain Validation (`p4b_cross_domain.py`)

Teacher trained trên LID-DS → apply surrogate (DT-Soft-T\*) trên DongTing test set.

**Feature alignment:** Drop LID-DS features xuống syscall-name-only (chỉ giữ unigram features trong intersection vocabulary). Refit vectorizer trên shared vocab.

**Metrics:** OOD Fidelity, OOD Attack Fidelity. Expected: thấp hơn in-dist 5–15%. Không re-train — chỉ quantify gap và propose mitigation strategy trong discussion section.

### 6.3 C9 — eBPF Rule Compiler (`p4c_ebpf_compiler.py`)

**Scope (core only):**

1. Input: DT rules từ DT-Soft-T\*-SHAP config (depth ≤ 5, features đã là integer n-gram counts)
2. `rule_extractor.py` → generate C if-else chain (integer arithmetic only, no floats, no loops)
3. Compile thành eBPF program via Aya (Rust) — hook `tracepoint/raw_syscalls/sys_enter`
4. Sliding window counter per syscall → store trong BPF hash map (per-PID)
5. Latency measurement: `bpf_ktime_get_ns()` before/after rule evaluation → histogram

**eBPF constraints:**

- Stack ≤ 512 bytes → depth ≤ 5 tree với ~10 conditions × 8 bytes vừa đủ
- Integer-only arithmetic → TF-IDF float counts → discretize thành integer frequency bins trước compile
- No Turing-complete constructs — if-else chain là safe

**Discretization validation (bắt buộc trước khi compile):**

- Sau khi discretize float → int bins, re-evaluate DT trên test set với features đã discretize
- So sánh Attack Fidelity trước và sau discretization — nếu drop > 2% → tăng số bins
- Log kết quả vào `results/p4/discretization_validation.json` trước khi compile eBPF

**Target:** Latency < 2µs/syscall (median).

**seccomp-BPF comparison** (discussion): latency vs expressiveness trade-off — đưa vào thesis discussion, không cần implement seccomp version.

### 6.4 C10 — Real Workload Evaluation (`p4d_real_workload.py`)

**Setup:**

- nginx + wrk load generator trong Docker, 30 phút normal traffic
- Collect syscall trace via eBPF
- Apply rule set từ C9 → measure FPR

**Target:** FPR < 5%. Nếu cao hơn → phân tích false positive patterns (which syscall combinations trigger rules), propose threshold adjustment — không re-train.

**Output artifacts:**

```
results/p4/
├── rules_human_readable.txt
├── mitre_coverage_matrix.csv
├── falco_comparison.json
├── cross_domain_results.json    # bao gồm vocab_intersection_size
├── discretization_validation.json
├── ebpf_latency_histogram.json
└── real_workload_fpr.json
```

---

## 7. P4.5 — Paper Packaging

### Paper → Experiment Mapping

| Paper Section              | Source                     | Key Output                                |
| -------------------------- | -------------------------- | ----------------------------------------- |
| Introduction               | Threat model (proposal §2) | Gap statement: accuracy vs deployability  |
| System Design              | Pipeline diagram + C9      | Figure: end-to-end architecture           |
| Methodology                | P2 Teacher + C6 Phase seg  | Teacher comparison table                  |
| Evaluation §1: Ablation    | C5 (Exp B+C)               | Table: distilled vs direct, 5 surrogates (DT/HSTree/FIGS/RuleFit/BoostedRules) |
| Evaluation §2: Phase-aware | C6                         | Table: per-phase FPR breakdown            |
| Evaluation §3: Rules       | C7 MITRE + Falco           | Coverage matrix + head-to-head            |
| Case Study                 | C7c (2 CVEs)               | Syscall trace walkthrough                 |
| Deployment                 | C9 + C10                   | Latency histogram + real workload FPR     |
| Discussion                 | C8 OOD + seccomp-BPF       | Limitations + future work                 |

### Results Consolidation (`p45_paper_tables.py`)

Load tất cả JSON artifacts từ `results/p2/`, `results/p3/`, `results/p4/` → generate:

- LaTeX tables cho ablation (Exp B, C, phase ablation)
- Coverage matrix heatmap (matplotlib)
- Latency CDF plot
- Pareto frontier figure (depth vs Attack Fidelity)

Không manual copy-paste số — script regenerate từ artifacts.

### Sections bỏ khỏi paper (giữ trong thesis)

- SHAP details, full 5-method comparison (paper chỉ giữ top 2-3 methods)
- Temperature calibration details
- Cross-domain (C8) details
- Phase segmenter algorithm details

---

## 8. Timeline

| Phase | Deadline       | Nội dung                                   | Deliverable           |
| ----- | -------------- | ------------------------------------------ | --------------------- |
| P2    | Tháng 4 week 2 | LID-DS loader + Teacher training + T sweep | P2 checkpoint pass    |
| P3    | Tháng 5 week 2 | Exp B (DT/HSTree/FIGS) + C (RuleFit/BoostedRules) + Phase ablation | Ablation tables       |
| P4    | Tháng 6 week 1 | C7+C8+C9+C10                               | Core results complete |
| P4.5  | Tháng 6 week 3 | Paper draft                                | Submit to ACSAC       |

**Critical path:** P2 checkpoint → Exp B+C (5 surrogates, pick winner) → Phase ablation (dùng winner config) → C7 rules → C9 eBPF.

---

## 9. Dependencies

```
imodels          # Core: DT variants (HSTreeClassifierCV, FIGSClassifier), RuleFit, BoostedRules (Exp B+C)
                 # Extension: BayesianRuleListClassifier, GreedyRuleListClassifier, SLIMClassifier (Exp D+F)
shap             # GradientExplainer cho Teacher embedding (thesis discussion only)
cvxpy            # (optional, Extension) required by imodels.SLIMClassifier
corels           # (optional, Extension) required by imodels.OptimalRuleListClassifier
alibi            # (optional, Extension) Anchors
wrk              # HTTP load generator (C10)
falco            # rule comparison (C7) — offline mode
aya              # eBPF Rust framework (C9)
```

Thêm vào `guepard-shield-model/pyproject.toml`: `imodels`, `shap`. Extension deps (`cvxpy`, `corels`) chỉ thêm khi cần.

> **Lưu ý:** `shap` chỉ dùng cho Teacher embedding visualization, không dùng cho feature selection pipeline. Feature selection dùng `sklearn.inspection.permutation_importance` (đã có trong scikit-learn).
