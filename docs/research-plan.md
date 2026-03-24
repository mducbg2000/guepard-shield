# RuleDistill — Quick Reference

---

## 1. Mục tiêu

- Dùng Transformer làm Teacher Oracle, distill thành **human-readable security rules**, deploy trên eBPF.
- Transformer học offline, rule enforce online — không inference model lúc runtime.
- Target: Fidelity >95% vs Teacher, FPR <1%, rule đủ ngắn gọn để analyst đọc.
- **Security framing:** Bridge gap từ detection accuracy → enforcement deployability. Phần lớn bài syscall detection dừng ở accuracy table — RuleDistill đi đến eBPF enforcement + latency measurement + rule auditability.

---

## 2. Threat Model

- **Scope:** Linux host (web server, DB, microservice), monitor ở syscall layer.
- **Attacker:** Post-exploitation, đã có code execution. Black-box (không biết rule set cụ thể).
- **Behavior detect:** Reverse shell, privilege escalation, data exfiltration, persistence — đều có syscall footprint.
- **Ngoài scope:** Adversarial evasion, kernel-level rootkit (future work).
- **Assumption:** eBPF tracing trusted, training data representative, attack patterns cover MITRE post-exploitation techniques.

---

## 3. Research Questions

| RQ  | Câu hỏi                                                        | Core? | Loại     |
| --- | -------------------------------------------------------------- | ----- | -------- |
| RQ1 | Phương pháp nào cân bằng tốt nhất Fidelity / FPR / Complexity? | ✅    | ML       |
| RQ2 | Distillation có tốt hơn train trực tiếp trên hard labels?      | ✅    | ML       |
| RQ5 | Phase-aware rule set có giảm FPR so với single-policy?         | ✅    | Security |
| RQ6 | Rule deploy được trên eBPF với overhead chấp nhận được không?  | ✅    | Security |
| RQ3 | Rich features cải thiện bao nhiêu so với sequence-only?        | Ext.  | ML       |
| RQ4 | Rule generalize cross-domain đến mức nào?                      | Ext.  | ML       |

---

## 4. Phạm vi

### Core (phải xong — đủ cho thesis)

| #   | Nội dung                                                        | Trả lời | Cho paper? |
| --- | --------------------------------------------------------------- | ------- | ---------- |
| C1  | Train Teacher (Transformer), F1 ≥ 90%                           | Prereq  | ✅         |
| C2  | SHAP feature selection → top-K features cho surrogate           | RQ1     |            |
| C3  | Exp B: Decision Tree — distilled vs direct, full vs SHAP        | RQ1 RQ2 | ✅         |
| C4  | Exp C: RuleFit — distilled vs direct, full vs SHAP              | RQ1 RQ2 |            |
| C5  | Ablation: distilled vs direct (isolate soft label, T, SHAP)     | RQ2     | ✅         |
| C6  | Ablation: single-policy vs per-phase surrogate                  | RQ5     | ✅         |
| C7  | Rule analysis: MITRE coverage + Falco head-to-head + case study | RQ1     | ✅         |
| C8  | Cross-domain: train LID-DS → test DongTing                      | RQ4     |            |
| C9  | eBPF Rule Compiler: DT → if-else → BPF verify → đo latency      | RQ6     | ✅         |
| C10 | Real workload eval: FPR + latency trên nginx/redis/postgres     | RQ6     | ✅         |

### Extension (chỉ khi core xong trước T7)

- Ext 1: BRL/CORELS, Anchors, domain-informed priors, OOD eval, eBPF dynamic phase loading
- Ext 2: Multi-thread features, Temporal Logic Mining, Shadow Mode, Feedback Loop, Hidden State Clustering

---

## 5. Phương pháp

### 5.1 Pipeline

```
Syscall Traces → Feature Eng → Transformer Teacher
                                      ↓
                          Temperature-scaled Soft Labels
                                      ↓
                    ┌─────────────────┴─────────────────┐
                    ↓                                   ↓
              Single-policy                    Phase Segmenter
              Surrogate (DT/RuleFit)      → Per-phase Surrogates
                    ↓                                   ↓
                    └──────────┬────────────────────────┘
                               ↓
                    Rule Set (human-readable)
                               ↓
                    eBPF Rule Compiler (C9)
                               ↓
                    Enforcement (Falco/Tetragon)
```

### 5.2 Teacher

- Encoder-only Transformer, target F1 ≥ 90%
- Temperature scaling T ∈ [1, 5], chọn T\* dựa trên surrogate fidelity
- So sánh với LSTM baseline — dùng model tốt hơn làm Teacher

### 5.3 Phase Segmenter

- Sliding window trên syscall rate (events/100ms)
- 4 phases: startup / active / idle / shutdown
- **Security motivation:** Startup có burst `execve`/`open`/`mmap` → single-policy dễ FP vì giống exploitation. Attack (reverse shell, persistence) thường ở active phase → per-phase model learn tighter boundary.
- Validate: (1) thủ công 50 sample, (2) distribution of attack labels per phase

### 5.4 Distillation Ablation (C5)

| So sánh               | Đo giá trị của     |
| --------------------- | ------------------ |
| Hard label vs Soft-T1 | Soft label         |
| Soft-T1 vs Soft-T\*   | Temperature tuning |
| Full features vs SHAP | Feature selection  |

Primary metric: **Attack-class Fidelity**.

### 5.5 Phase-aware Ablation (C6)

| Variant                  | Mô tả                                  |
| ------------------------ | -------------------------------------- |
| Single-policy (baseline) | 1 surrogate cho toàn bộ lifecycle      |
| Per-phase (4 surrogates) | 1 surrogate/phase, cùng Teacher        |
| Per-phase + SHAP         | Per-phase + chỉ SHAP-selected features |

So sánh: FPR per phase, overall FPR, Attack-class Fidelity. Effort: ~1 tuần.

### 5.6 Rule Analysis & MITRE Mapping (C7)

- **MITRE coverage matrix:** Map mỗi attack scenario → technique ID → kiểm tra rule detect được không
- **Falco head-to-head:** Lấy Falco default ruleset, chạy trên cùng test set, so sánh detection rate / FPR / rule count
- **Case study:** 2-3 CVE cụ thể, walk through syscall sequence → rule fire → root cause vs side effect
- **Auditability:** 1-2 practitioner review 10 rules, đánh giá readability (informal, note limitation)

### 5.7 eBPF Compiler (C9)

- DT rules → if-else chain (C code) → compile eBPF (Aya/Rust)
- Hook `tracepoint/raw_syscalls/sys_enter`, load rules vào BPF hash map
- Đo latency (target < 2µs/syscall), đo FPR/FNR live enforcement
- **So sánh seccomp-BPF:** seccomp = per-syscall allow/deny, không có state. RuleDistill = sequential pattern, richer policy, nhưng latency cao hơn.

### 5.8 Real Workload Eval (C10)

- Chạy nginx, redis, postgres với benchmark traffic (wrk/pgbench)
- Thu syscall trace 30-60 phút → apply rules → đo FPR
- Apply qua eBPF enforcement → đo latency dưới load
- Target FPR < 5% (cao hơn benchmark dataset là expected)
- Effort: ~1-2 tuần

### 5.9 Temperature Calibration Checkpoint

Phải pass cả 3 trước khi chạy surrogates:

- [ ] Soft label entropy attack > normal
- [ ] Reliability diagram: T_calib > 1
- [ ] DT fidelity tăng khi T: 1 → 3 (nếu flat → early warning cho RQ2)

### 5.10 Datasets

| Dataset     | Quy mô      | Đặc điểm                      |
| ----------- | ----------- | ----------------------------- |
| LID-DS-2021 | 17,190 rec  | exploit timestamps, pre-split |
| DongTing    | 18,966 seq  | syscall name only             |
| LID-DS-2019 | ~11,000 rec | + timestamp, thread_id, args  |

**Limitation:** Academic benchmark, không phải production. Attack scenarios có CVE cũ. Không có container workload. **Nhưng valid cho RQs** vì đo relative performance giữa methods + C10 bổ sung real workload.

### 5.11 Metrics & Baselines

| Metric                    | Target |
| ------------------------- | ------ |
| Fidelity vs Teacher       | >95%   |
| FPR                       | <1%    |
| Attack-class Fidelity     | >90%   |
| Phase-aware FPR reduction | >15%   |
| eBPF latency/syscall      | <2µs   |
| MITRE coverage            | Report |
| Real workload FPR         | <5%    |

Baselines: STIDE, LSTM/DeepLog, RF (ceiling), **Falco default ruleset** (head-to-head), **seccomp-BPF** (enforcement comparison), direct-trained surrogates, single-policy surrogate.

---

## 6. Timeline

| Phase    | Thời gian | Nội dung                                                                         | Scope |
| -------- | --------- | -------------------------------------------------------------------------------- | ----- |
| **P1**   | T1-2      | Data pipeline, EDA, phase segmenter, MITRE mapping cho dataset                   | Core  |
| **P1.5** | T2        | Pilot: DT distilled vs direct trên DongTing → quyết định tiếp                    | Core  |
| **P2**   | T3-4      | Train Teacher, temperature calibration, LSTM baseline                            | Core  |
| **P3**   | T5-6      | Exp B + C, ablation distilled vs direct (C5), phase-aware (C6)                   | Core  |
| **P4**   | T6-7      | MITRE + Falco comparison (C7), cross-domain (C8), eBPF (C9), real workload (C10) | Core  |
| **P4.5** | T7        | **Paper draft** — đóng gói C1+C3+C6+C7+C9+C10 cho security venue                 | Paper |
| **P5**   | T7-8      | BRL, domain priors, OOD eval                                                     | Ext 1 |
| **P6**   | T8-9      | eBPF dynamic phase loading, Anchors                                              | Ext 1 |
| **P7**   | T9-10     | Tier 2 features, Temporal Logic, Shadow Mode                                     | Ext 2 |
| **P8**   | T11-12    | Viết luận văn, bảo vệ                                                            | —     |

**Pivot (P1.5):** Distillation gain nhỏ → chuyển focus sang comparative study + phase-aware, giảm emphasis KD.

**Paper target:** RAID / ACSAC (rank A) hoặc DIMVA / SecureComm (rank B). Chọn venue sau P4.

**Nguyên tắc:** Core xong trước T7. Không hy sinh core cho extension.

---

## 7. Publication Strategy (Hướng A — Security Venue)

**Framing:** KHÔNG frame là bài KD/XAI. Frame là bài **automated security policy generation with deployment guarantee**.

**Title direction:** _"From Neural Detection to Kernel Enforcement: Automated Security Policy Generation for Syscall-based HIDS"_

**Selling points (theo thứ tự):**

1. End-to-end pipeline model → rule → eBPF enforcement
2. Phase-aware policy giảm FPR — security-motivated novelty
3. eBPF deployment + latency trên real workload
4. MITRE coverage + Falco head-to-head + CVE case study
5. Distillation ablation (đặt sau security contributions)

**Paper content:** C1 + C3 (hoặc C4) + C5 (brief) + C6 + C7 + C9 + C10. Bỏ: SHAP details, RuleFit vs DT comparison chi tiết, cross-domain, temperature details → giữ cho thesis.

---

## 8. Đóng góp

### Core — Thesis (6 items)

1. **KD empirical study:** KD từ Transformer cho syscall HIDS rule extraction
2. **Surrogate comparison:** DT vs RuleFit — fidelity, complexity, interpretability
3. **SHAP feature selection:** Full vs top-K features cho rule complexity
4. **Phase-aware extraction:** Per-phase surrogate + security motivation + ablation
5. **Rule quality:** MITRE coverage matrix + Falco head-to-head + CVE case study + auditability
6. **eBPF deployment:** BPF-verifiable rules + latency measurement + real workload FPR

### Core — Paper (4 items, security-framed)

1. End-to-end pipeline detection → enforcement
2. Phase-aware enforcement giảm FPR
3. eBPF deployment + real workload validation
4. MITRE-grounded evaluation + Falco comparison

### Extension (nếu kịp)

Anchors, BRL/CORELS, Temporal Logic, eBPF dynamic phase loading, multi-thread, Shadow Mode, Feedback Loop, Hidden State Clustering.

**Future work:** Adversarial evasion, production deployment, formal user study, Learnable KD, kernel-level attacker.
