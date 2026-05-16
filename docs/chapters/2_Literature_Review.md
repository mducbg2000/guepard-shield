# Chapter 2 — Literature Review

## 2.1 Scope of Research

This thesis focuses on **syscall-level anomaly detection** for Linux hosts running server workloads. The scope is bounded by:

- **Monitor layer:** System call interface — lowest software layer before kernel.
- **Attacker model:** Post-exploitation (code execution assumed). Attacker performs reverse shell, privilege escalation, exfiltration, or persistence. Black-box: attacker does not know the current DFA.
- **Out of scope:** Adversarial evasion against the learning algorithm, kernel-level rootkits, network-layer intrusion detection.

**Datasets in scope:**

| Dataset | Size | Role |
|---------|------|------|
| LID-DS-2021 | 17,190 recordings, 15 scenarios | Primary — train/val/test |
| LID-DS-2019 | ~11,000 recordings, 10 scenarios | Cross-domain validation |
| DongTing | 18,966 sequences | Cross-domain validation |

## 2.2 Related Work

### 2.2.1 Syscall Anomaly Detection

- **STIDE / N-gram models:** Count syscall n-gram frequencies; flag deviations from training distribution. Fast but miss long-range dependencies. No sequential context beyond n.
- **HMM-based approaches:** Model syscall sequences as hidden Markov chains. Captures some sequential structure but limited expressiveness; expensive to scale vocabulary.
- **LSTM / GRU anomaly detection (DeepLog, etc.):** Next-token prediction on syscall sequences using recurrent networks. High AUROC on LID-DS-style benchmarks. Cannot deploy in kernel. No path to enforcement.
- **Transformer-based detection:** Attention mechanism captures longer context than LSTM. State of the art on LID-DS-2021. Same deployment gap as LSTM.

### 2.2.2 Automata Extraction from Neural Networks

- **Weiss et al. (2018) — Extracting Automata from RNNs:** Cluster RNN hidden states with k-means; build DFA from observed transitions. Works well for RNNs (natural recurrent state). Not applied to Transformers or syscall HIDS.
- **Subsequent work:** Extensions to LSTM, GRU, and attention models. Key finding: clustering quality determines DFA fidelity. Non-determinism resolution is the main open challenge.
- **Gap:** No prior work extracts DFAs from Transformer syscall models and deploys them to a kernel enforcement layer.

### 2.2.3 eBPF-based Security Enforcement

- **Falco:** Syscall monitoring via eBPF with hand-crafted YAML rules. Production-ready but rules are manually written; no learning from data.
- **Tetragon:** eBPF-based enforcement with policy-as-code. Similar gap — policies are human-authored.
- **Gap:** No existing tool automatically derives eBPF enforcement policies from a trained neural model.

## 2.3 Background: Decoder-only Transformer

A decoder-only Transformer with causal self-attention processes token sequences autoregressively. The causal mask ensures token $s_t$ attends only to $s_1, \ldots, s_{t-1}$. Trained with next-token prediction:

$$\mathcal{L} = -\sum_t \log P(s_{t+1} \mid s_1, \ldots, s_t)$$

The final-layer output $h_t \in \mathbb{R}^d$ at position $t$ encodes the full causal context — it is the closest analogue to an RNN hidden state and is the basis for DFA state extraction.

## 2.4 Background: Deterministic Finite Automaton

A DFA is a 5-tuple $(Q, \Sigma, \delta, q_0, F)$ where:
- $Q$: finite set of states
- $\Sigma$: finite input alphabet
- $\delta: Q \times \Sigma \to Q$: transition function
- $q_0 \in Q$: initial state
- $F \subseteq Q$: set of accepting (or, in this work, rejecting) states

A DFA processes input one symbol at a time in O(1) per step. This property makes DFA the natural target for eBPF deployment.

## 2.5 Background: eBPF

eBPF (Extended Berkeley Packet Filter) allows verified programs to run in the Linux kernel without a kernel module. Key properties:
- Programs are attached to tracepoints or LSM hooks — fires on every matching syscall.
- BPF maps (key-value stores shared between kernel and userspace) provide O(1) lookup.
- Stack limit: 512 bytes. All state must live in BPF maps.
- Atomic map updates allow hot-reload of DFA transitions without kernel restart.
