# Chapter 5 — Numerical Results

## 5.1 Evaluation Parameters

| Parameter | Description | Candidate Values |
|-----------|-------------|-----------------|
| `W` | Sliding window size (syscalls) | 64, 128 |
| `K` | Number of DFA states (K-Means clusters) | 100, 200, 500, 1000 |
| `θ` | Statistical pruning threshold (S4) | 0.95, 0.99, 0.999 |
| `\|Σ\|` | Composite token alphabet size | ~500–1000 |
| `d` | Transformer hidden dimension | TBD |
| `L` | Number of Transformer layers | TBD |

## 5.2 Datasets

| Dataset | Split | Use |
|---------|-------|-----|
| LID-DS-2021 | train / val / test (pre-split) | Primary evaluation |
| LID-DS-2019 | — | Cross-domain generalization |
| DongTing | — | Cross-domain generalization |

Window labels are derived from exploit timestamps in JSON metadata. No recording-level labels are used.

## 5.3 Evaluation Metrics

| Metric | Level | Target |
|--------|-------|--------|
| Detection AUROC | Window | > 0.95 |
| Detection F1 | Window | > 0.90 |
| DFA Fidelity vs. Teacher | Window | > 95% |
| DFA FPR | Window | < 1% |
| eBPF latency overhead | Per-syscall | < 2 µs |
| Real workload FPR | Window | < 5% |
| MITRE ATT&CK coverage | — | Reported |

## 5.4 Simulation Method

### 5.4.1 Phase 2 Baselines

Compare Teacher Transformer against:
- N-gram frequency model (n=5)
- LSTM next-token predictor (DeepLog-style)

Metric: window-level AUROC and F1 on LID-DS-2021 test set.

### 5.4.2 Phase 3 — Non-determinism Strategy Comparison

For each strategy S1–S4, measure:
- Conflict rate (fraction of ambiguous transitions)
- DFA state count (after resolution)
- Fidelity vs. Teacher on LID-DS-2021
- Window-level FPR on normal test windows

Grid search over K ∈ {100, 200, 500, 1000} and θ ∈ {0.95, 0.99, 0.999} for S4.

### 5.4.3 Phase 4 — Runtime Evaluation

Workloads: nginx, redis, postgres running on a Linux VM.
- Measure per-syscall eBPF overhead vs. baseline (no eBPF).
- Measure FPR (normal workload windows flagged as Edge or Reject).
- Inject LID-DS attack scenarios; measure TPR.

## 5.5 Phase 2 Results

*(To be filled after experiments.)*

## 5.6 Phase 3 Results — Non-determinism Strategy Comparison

*(To be filled. Expected: S4 with θ=0.99 achieves lowest FPR with minimal fidelity loss due to skewed syscall distributions.)*

## 5.7 Phase 3 Results — K Sensitivity

*(To be filled. Expected: K=200–500 provides best fidelity–compactness trade-off for LID-DS-2021.)*

## 5.8 Phase 4 Results — Runtime Latency

*(To be filled.)*

## 5.9 MITRE ATT&CK Coverage

*(To be filled. Map DFA rejecting-state patterns to MITRE techniques: T1059 Command and Scripting Interpreter, T1055 Process Injection, T1003 Credential Dumping, etc.)*
