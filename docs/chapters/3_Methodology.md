# Chapter 3 — Methodology

## 3.1 Overview

Guepard Shield is a four-phase pipeline that converts raw syscall recordings into a kernel-enforced DFA:

```
[Phase 1] EDA + Data Preprocessing
          - Thread separation, composite tokenization, window labeling
          ↓
[Phase 2] Teacher: Decoder-only Transformer
          - Next-Token Prediction on normal syscall sequences
          - Evaluate: window-level NLL scores → AUROC / F1
          ↓
[Phase 3] Student: DFA Extraction
          - Collect final-layer hidden states h_t
          - K-Means clustering → K discrete states
          - Build transition table δ(q, token) → q'
          - Resolve non-determinism (strategies S1–S4)
          - Export dfa_config.json
          ↓
[Phase 4] Runtime Enforcement (eBPF)
          - Per-thread DFA traversal via BPF map lookup
          - Three-tier response: Normal / Edge / Rejecting
          - Suspect window feedback loop to offline Transformer
```

At runtime, there is no concept of "recording." The system processes a continuous per-thread syscall stream. Only sliding windows of size `W` exist.

The two operational sub-agents and their interaction:

```
                 CONTINUOUS SYSCALL STREAM (per thread)
                                  │
┌─────────────────────────────────▼──────────────────────────────────────┐
│                    eBPF SUB-AGENT  (Kernel Space)                      │
│                                                                        │
│  ┌──────────────────────────────────────┐                              │
│  │  Composite Tokenizer                 │                              │
│  │  (Syscall_ID, RetCode_Bucket) → token│                              │
│  └─────────────────┬────────────────────┘                              │
│                    │                                                   │
│  ┌─────────────────▼────────────────────┐                              │
│  │  DFA State Machine                   │                              │
│  │  transition_table[(state, token)]    │ ← BPF_MAP_TYPE_HASH          │
│  │  thread_state[TID]                   │ ← BPF_MAP_TYPE_HASH          │
│  └──────────┬──────────────┬────────────┘                              │
│             │              │              │                            │
│          NORMAL           EDGE         REJECT                          │
│          continue    capture window   BLOCK / KILL / ALERT             │
│                            │                                           │
└────────────────────────────│───────────────────────────────────────────┘
                             │  perf_event ring buffer
                             │  (suspect window + TID + state trace)
┌────────────────────────────▼───────────────────────────────────────────┐
│                    Rust Agent  (User Space)                            │
│            receive window → forward to Transformer                     │
└────────────────────────────┬───────────────────────────────────────────┘
                             │
┌────────────────────────────▼───────────────────────────────────────────┐
│              Transformer Sub-Agent  (Offline Analyzer)                 │
│                                                                        │
│   ┌─────────────────────┐                                              │
│   │  NLL scoring        │──── True Positive ──▶  ALERT / LOG           │
│   │  on suspect window  │                                              │
│   └─────────────────────┘──── False Positive ──▶ ┌──────────────────┐  │
│                                (legit new        │  Re-extract DFA  │  │
│                                 behavior)        │  add transitions │  │
│                                                  └────────┬─────────┘  │
└───────────────────────────────────────────────────────────│────────────┘
                                                            │
                                                   atomic BPF map update
                                                            │
                                                            ▼
                                                 ┌────────────────────────┐
                                                 │  DFA updated in-place  │
                                                 │  (no kernel reload)    │
                                                 └────────────────────────┘
```

---

## 3.2 Phase 1 — Data Preprocessing

### 3.2.1 Composite Tokenization

Each syscall event is mapped to a composite token:

$$\text{token} = (\text{Syscall\_ID},\ \text{ReturnCode\_Bucket})$$

Return codes are bucketed (e.g., success=0, EPERM, EAGAIN, other-error) to keep the alphabet size |Σ| finite and tractable. |Σ| is a hyperparameter.

**Rationale:** Raw syscall IDs alone discard argument context. Composite tokens enrich the alphabet without unbounded growth, satisfying the DFA requirement of a finite input alphabet.

### 3.2.2 Thread-level Separation

Syscall streams are partitioned by Thread ID (TID) before any windowing. Each TID produces an independent sequence.

**Rationale:** Interleaving syscalls from concurrent threads destroys causality. `h_t` for a token from thread A would encode context from thread B, producing meaningless hidden states and invalid DFA transitions.

### 3.2.3 Sliding Windows and Labeling

Each per-thread stream is segmented into overlapping sliding windows of `W` tokens. `W` is a hyperparameter (candidate range: 64–128).

Windows are labeled using exploit timestamps from dataset metadata (LID-DS JSON files): a window is **attack** if it overlaps the exploit interval, **normal** otherwise. This label is used only for offline evaluation — not for training.

**Rationale for small W:**

- Attack behavior (the exploit point) has high temporal locality — typically completes within tens of syscalls.
- Smaller W forces the Transformer to generalize, producing hidden states that cluster more cleanly.
- Smaller W → fewer DFA states → smaller eBPF map → lower kernel memory footprint.

---

## 3.3 Phase 2 — Teacher: Transformer Training

### 3.3.1 Architecture

Decoder-only Transformer with causal (lower-triangular) self-attention mask. Input: sequence of composite token IDs. Output: next-token probability distribution over Σ.

The causal mask ensures $h_t$ is computed using only $(s_1, \ldots, s_{t-1})$, matching the one-directional, real-time nature of the DFA at runtime.

### 3.3.2 Training Objective

Next-Token Prediction with Cross-Entropy Loss:

$$\mathcal{L} = -\frac{1}{N} \sum_{t=1}^{N} \log P_\theta(s_{t+1} \mid s_1, \ldots, s_t)$$

Trained on **normal sequences only** (unsupervised anomaly detection). The model learns $P(\text{normal behavior})$; anomalies manifest as low probability (high NLL) windows.

Teacher Forcing enables full-sequence parallel training on GPU.

### 3.3.3 Anomaly Score

For a window $[s_1, \ldots, s_W]$, the anomaly score is the mean per-token NLL:

$$\text{score}(w) = -\frac{1}{W} \sum_{t=1}^{W} \log P_\theta(s_{t+1} \mid s_1, \ldots, s_t)$$

Evaluation: window-level AUROC and F1 against exploit-timestamp labels. No recording-level aggregation.

---

## 3.4 Phase 3 — Student: DFA Extraction

### 3.4.1 Hidden State Definition

The **hidden state** is the final-layer output embedding of the **last token** in each forward pass:

$$h_t = \text{TransformerFinalLayer}(s_1, \ldots, s_t)[\text{position } t] \in \mathbb{R}^d$$

Due to causal self-attention, $h_t$ encodes the full causal context $(s_1, \ldots, s_{t-1})$. It is the closest analogue to an RNN hidden state and the most natural candidate for DFA state representation.

### 3.4.2 State Discretization via K-Means

Run the trained Transformer over all normal training windows. Collect all $h_t$ vectors — one per token per window. Apply K-Means clustering with $K$ clusters.

Each cluster centroid $c_k$ defines one DFA state $q_k \in Q$. A hidden state $h$ maps to state $q_k$ where $k = \arg\min_j \|h - c_j\|_2$.

$K$ is a hyperparameter governing the **fidelity–compactness trade-off**:

- Low K → coarse DFA, small eBPF map, higher non-determinism conflict rate, potential false positives.
- High K → fine DFA, larger map, lower conflict rate, risk of overfitting to training sequences.

### 3.4.3 Transition Construction

For each consecutive token pair $(s_t, s_{t+1})$ in training data:

1. Compute $h_t$ and $h_{t+1}$ via forward pass.
2. Map to states: $A = \text{cluster}(h_t)$, $B = \text{cluster}(h_{t+1})$.
3. Record candidate transition: $\delta(A,\ s_{t+1}) \to B$.

The raw result is a transition **relation** (NFA), not a function, because the same $(A, s)$ pair may map to different target states across different sequences.

### 3.4.4 Non-determinism Resolution

Non-determinism arises when the K-Means projection loses information: two sequences with different histories may land in the same cluster A, then diverge on input $s$. Four resolution strategies are evaluated experimentally:

| ID     | Strategy                | Mechanism                                                                                             | Trade-off                                                                            |
| ------ | ----------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| **S1** | NFA→DFA Determinization | Subset construction: DFA states are _sets_ of NFA states.                                             | Exact; may cause state explosion.                                                    |
| **S2** | Increase K              | Finer clustering reduces information loss at projection.                                              | Larger BPF map; K calibration needed.                                                |
| **S3** | Majority Voting         | For each $(A, s)$, keep the most frequent target state.                                               | Simple; minority branches silently dropped.                                          |
| **S4** | Statistical Pruning (θ) | Count branch frequencies. Keep only branches with frequency $\ge \theta$ (e.g., 99%). Prune the rest. | Compact graph; exploits strong skew of syscall distributions. **Primary candidate.** |

**Rationale for S4 as primary candidate:** Normal server workloads are highly repetitive. The distribution of transitions is strongly skewed: one branch dominates (happy path), while minority branches ($< \theta$) are K-Means quantization artifacts rather than genuine behavioral variation.

### 3.4.5 DFA Export

The finalized DFA is exported to `dfa_config.json` and loaded into eBPF maps:

| BPF Map            | Key                    | Value                    |
| ------------------ | ---------------------- | ------------------------ |
| `transition_table` | `(state_id, token_id)` | `next_state_id`          |
| `state_tier`       | `state_id`             | `{NORMAL, EDGE, REJECT}` |
| `thread_state`     | `TID`                  | `current_state_id`       |

---

## 3.5 Phase 4 — Runtime Enforcement (eBPF)

### 3.5.1 Per-syscall DFA Step

On every syscall event, the eBPF program:

1. Reads `current_state` from `thread_state[TID]`.
2. Computes composite token `(Syscall_ID, ReturnCode_Bucket)`.
3. Looks up `next_state = transition_table[(current_state, token)]`.
4. If no entry exists → **Rejecting State** (unknown transition).
5. Writes `next_state` to `thread_state[TID]`.
6. Reads `state_tier[next_state]` and acts accordingly.

Cost: two O(1) BPF map lookups per syscall. No context switch to userspace for normal transitions.

### 3.5.2 Tiered Response

| Tier                   | Criteria                                             | Action                                                                                   |
| ---------------------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| **Normal**             | `next_state` tier = NORMAL                           | Continue. No overhead beyond map update.                                                 |
| **Edge (Gray Zone)**   | `next_state` tier = EDGE, or token is OOV (not in Σ) | Capture window, send to Rust Agent → offline Transformer for deep analysis. No blocking. |
| **Rejecting (Attack)** | No entry in `transition_table` for `(state, token)`  | BLOCK / KILL / ALERT.                                                                    |

**Edge state definition:** States whose training-time visit frequency falls below a percentile threshold. These states represent rare but seen behavior during training — suspicious enough to warrant deep analysis, not immediately blocked.

### 3.5.3 Mimicry Attack Resilience

An attacker who pads an exploit sequence with benign-looking syscalls to stretch it across window boundaries will cause the DFA pointer to follow an atypical transition path. Because the DFA is a strict whitelist, even benign tokens in an unusual state context will lack valid transitions — the DFA rejects regardless of padding length. This property is a consequence of the DFA structure, not a separate rule.

### 3.5.4 Continuous Update Loop

If the Transformer determines a captured Edge window is a false positive (e.g., caused by a software update introducing new behavior):

1. The new transition pattern is added to the training set.
2. DFA is re-extracted (or incrementally updated).
3. New `transition_table` entries are atomically written to the BPF map.

No kernel reload required. The per-thread state pointer continues from its current position.
