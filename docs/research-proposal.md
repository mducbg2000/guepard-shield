# Guepard Shield: A novel data breach detection mechanism using kernel-level information

---

## 1. Goal

Build an end-to-end pipeline that:

1. Trains a model that detects attack behavior in syscall sequences
2. Extracts human-readable security rules from the model's learned representations
3. Deploys rules as real-time enforcement on eBPF (Falco/Tetragon)

**Core thesis:** Bridge the gap between neural detection accuracy and operational deployability. Most syscall detection papers stop at accuracy tables. This work goes further: model → interpretable rule → kernel enforcement, with latency measurement and rule auditability.

**Why rules, not model inference:** Real-time inference on syscall sequences is infeasible at the kernel level. Rules derived from the model provide equivalent detection with microsecond latency.

---

## 2. Threat Model

- **Target:** Linux host running server workloads (web server, database, microservice)
- **Monitor layer:** Syscall-level — lowest layer before kernel interaction
- **Attacker:** Post-exploitation — has code execution, performs reverse shell / privilege escalation / exfiltration / persistence. Leaves syscall footprint.
- **Knowledge:** Black-box — attacker does not know the current rule set.
- **Out of scope:** Adversarial evasion, kernel-level rootkits.

---

## 3. Pipeline

```
EDA + Data Preprocessing
        ↓
Model Training
  (detect attack behavior in syscall sequences)
        ↓
Rule Extraction
  (distill model knowledge into human-readable rules)
        ↓
eBPF Enforcement
  (compile rules → kernel-level real-time matching)
```

Each phase's method is determined by results of the previous phase. Multiple approaches may be tried per phase; the best-performing one advances.

---

## 4. Phases

### Phase 1 — EDA + Data Preprocessing

**Goal:** Understand dataset structure, clean and represent syscall sequences in a form suitable for model training. Document key dataset properties.

**Success criteria:** Reproducible data pipeline. Key properties documented — sequence lengths, class distribution, thread structure, OOV syscalls, attack timing, syscall vocabulary coverage.

### Phase 2 — Model Training

**Goal:** Train a model that distinguishes attack behavior from normal syscall sequences. The trained model serves as a Teacher for rule extraction.

**Success criteria:** High AUROC and F1 on a labeled evaluation set.

### Phase 3 — Rule Extraction

**Goal:** Distill the Teacher model's learned decision boundary into a compact set of human-readable rules. Rules must be auditable by a security analyst and deployable on eBPF.

**Success criteria:** Rules achieve high fidelity vs. the Teacher (>95%), low FPR (<1%), and are sufficiently compact. Rules map to known MITRE ATT&CK techniques.

### Phase 4 — Deployment + Validation

**Goal:** Compile rules to eBPF programs, measure enforcement latency, validate FPR on real workloads.

**Success criteria:** Latency <2µs/syscall. FPR <5% on production-like workloads (nginx, redis, postgres).

---

## 5. Dataset

| Dataset     | Size                             | Notes                                       |
| ----------- | -------------------------------- | ------------------------------------------- |
| LID-DS-2021 | 17,190 recordings, 15 scenarios  | Primary. Pre-split train/val/test.          |
| LID-DS-2019 | ~11,000 recordings, 10 scenarios | Cross-domain validation.                    |
| DongTing    | 18,966 sequences                 | Cross-domain validation, syscall name only. |

---

## 6. Success Metrics

| Metric                    | Target       |
| ------------------------- | ------------ |
| Detection AUROC           | >0.95        |
| Detection F1              | >0.90        |
| Rule Fidelity vs. Teacher | >95%         |
| Rule FPR                  | <1%          |
| eBPF latency overhead     | <2µs/syscall |
| Real workload FPR         | <5%          |
| MITRE ATT&CK coverage     | Reported     |

---

## 7. Contributions

1. **End-to-end pipeline:** Neural detection → interpretable rules → eBPF kernel enforcement
2. **Detection model for syscall HIDS:** Model output as supervision signal for rule extraction
3. **Rule extraction study:** Compare rule extraction methods on fidelity/complexity trade-off
4. **eBPF deployment:** Compile rules to kernel-level enforcement with latency measurement on real workloads
5. **MITRE-grounded evaluation:** Coverage analysis + head-to-head comparison with Falco default rules

---

## 8. Timeline

| Phase  | Period      | Goal                                         |
| ------ | ----------- | -------------------------------------------- |
| P1     | Month 1-2   | EDA, data pipeline, dataset characterization |
| P2     | Month 3-4   | Detection model — high AUROC/F1              |
| P3     | Month 5-6   | Rule extraction — fidelity and FPR targets   |
| P4     | Month 6-7   | eBPF deployment, real workload validation    |
| Paper  | Month 7     | Paper draft for security venue               |
| Thesis | Month 11-12 | Final thesis write-up                        |

---

## 9. Publication Target

Security venue (RAID, ACSAC, IEEE Globecom/ICC). Framing: end-to-end pipeline from neural detection to kernel enforcement — not framed as XAI or knowledge distillation. Key selling points: enforcement gap, eBPF deployment, MITRE coverage, practical latency measurement.
