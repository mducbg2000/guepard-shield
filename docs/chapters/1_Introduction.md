# Chapter 1 — Introduction

## 1.1 Problem Statement

Linux server workloads (web servers, databases, microservices) are frequent targets of post-exploitation attacks: reverse shells, privilege escalation, data exfiltration, and persistence. These attacks leave a systematic footprint at the syscall layer — the lowest software interface before kernel interaction.

Host-based Intrusion Detection Systems (HIDS) operating at the syscall level offer the most granular visibility into process behavior. However, existing approaches face a fundamental trade-off:

- **Deep learning models** (Transformers, LSTMs) achieve high detection accuracy but cannot run inside the kernel — inference latency is orders of magnitude above what real-time syscall interception allows.
- **Rule-based systems** (e.g., Falco default rules) run at kernel speed but are hand-crafted, brittle, and fail to capture the complex sequential patterns that characterize attacks.

No existing work closes this gap end-to-end: from a trained neural model to an automatically derived, kernel-enforced detection mechanism.

## 1.2 Background and Problems of Research

Current syscall-based HIDS research stops at accuracy tables. Key limitations:

| Approach | Strength | Limitation |
|----------|----------|------------|
| Transformer / LSTM anomaly detection | High AUROC on labeled benchmarks | Cannot run in kernel; no deployment path |
| N-gram / frequency-based rules | Fast, deployable | Misses sequential context; hand-tuned thresholds |
| Falco / Tetragon default rules | Production-ready | Written by humans, no learning from data |
| Automata extraction from RNNs | Bridges neural ↔ discrete | Not applied to syscall HIDS or eBPF deployment |

The enforcement gap — between what a model learns and what can execute at kernel speed — is the core unsolved problem.

## 1.3 Research Objectives and Conceptual Framework

**Primary objective:** Build an end-to-end pipeline that automatically converts a trained Transformer's learned knowledge into a Deterministic Finite Automaton (DFA) deployable as an eBPF kernel program.

**Runtime model:** The system operates on a continuous per-thread stream of syscalls. There is no concept of "recording" at runtime — only sliding windows of `W` syscalls. Each window is evaluated against the DFA state. An alert is raised when the DFA enters a rejecting state.

**Pipeline:**
```
Syscall stream (per thread)
        ↓
[Phase 1] EDA + Data Preprocessing
        ↓
[Phase 2] Decoder-only Transformer — Next-Token Prediction on syscall sequences
        ↓  (hidden states)
[Phase 3] DFA Extraction — K-Means clustering → transition table → non-determinism resolution
        ↓  (dfa_config.json)
[Phase 4] eBPF Enforcement — O(1) DFA lookup per syscall, per-thread state
```

**Why DFA, not model inference:** A DFA transition is an O(1) BPF map lookup. Transformer inference on a window is O(W·d²) — infeasible at kernel speed. The DFA encodes the model's learned decision boundary in a form the kernel can execute.

## 1.4 Planned Contributions

1. **End-to-end pipeline:** Syscall HIDS from neural anomaly detection → DFA extraction → eBPF kernel enforcement, with latency measurement on real workloads.
2. **DFA extraction from Transformer hidden states:** Formalization of the continuous-to-discrete mapping (K-Means on final-layer embeddings), including a study of non-determinism resolution strategies (S1–S4).
3. **Mimicry attack resilience via DFA structure:** Formal argument that padding-based mimicry attacks cause DFA pointer drift into edge states, from which recovery is not possible regardless of padding length.
4. **Evaluation on LID-DS and DongTing:** Window-level AUROC/F1 for the Teacher; fidelity and FPR for the DFA Student; enforcement latency on nginx, redis, postgres workloads.
5. **MITRE ATT&CK coverage analysis:** Mapping of DFA rejecting-state patterns to known attack techniques.

These are thesis targets, not completed outputs in the current repository state.

## 1.5 Organization of Thesis

*(To be written after all chapters are drafted.)*
