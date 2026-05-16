# Chapter 4 — Theoretical Analysis

This chapter analyzes the expected properties of the proposed Phase 2 / Phase 3 / Phase 4 architecture. These arguments are theoretical scaffolding for future work, not validation of an already implemented pipeline in the current codebase.

## 4.1 Computational Complexity

### 4.1.1 Transformer Inference (Offline)

Forward pass on a window of W tokens with model dimension d and L layers:

$$O(L \cdot W^2 \cdot d)$$

Infeasible at runtime for typical values (W=128, d=256, L=6 → millions of FLOPs per window, millisecond-range latency).

### 4.1.2 DFA Traversal (Runtime)

Each syscall requires:
- 1 BPF hash map lookup for the transition: O(1)
- 1 BPF hash map lookup for the tier: O(1)
- 1 BPF hash map write for the new state: O(1)

Total: **O(1) per syscall**, regardless of sequence length or model size.

### 4.1.3 K-Means Extraction (Offline)

Collecting hidden states: one forward pass over training data — O(N · L · W² · d) where N is the number of training windows. K-Means convergence: O(N · K · d · I) where I is the number of iterations. Both are one-time offline costs.

---

## 4.2 DFA Size and eBPF Memory

The transition table has at most $K \times |\Sigma|$ entries. For K=500, |Σ|=1000: 500,000 entries. At 8 bytes per key and 4 bytes per value, this is ~6 MB — well within `BPF_MAP_TYPE_HASH` limits (default max_entries configurable up to millions).

In practice, the table is sparse: only transitions observed in training data are populated. Unobserved (A, token) pairs are implicitly rejecting.

---

## 4.3 Non-determinism Rate and Strategy Selection

Define the **conflict rate** of a DFA extraction as:

$$\text{conflict\_rate} = \frac{|\{(A, s) : |\{\delta(A,s)\}| > 1\}|}{|\{(A, s) : \delta(A,s) \neq \emptyset\}|}$$

**Claim:** For syscall data with strongly skewed transition distributions, conflict rate decreases monotonically with K and is further reduced by S4 pruning.

**Argument:** If two sequences reach cluster A via different histories but behave identically going forward (same next-state assignment), no conflict arises. Conflicts occur only when K-Means merges two histories that the Transformer distinguishes. Increasing K reduces such merges. S4 pruning eliminates conflicts caused by rare quantization noise (frequency < θ) without removing genuine transitions.

**Empirical validation plan:** Measure conflict rate across K ∈ {100, 200, 500, 1000} and θ ∈ {0.95, 0.99, 0.999} on LID-DS-2021. Report fidelity (DFA AUROC vs Teacher AUROC) and FPR as joint functions of (K, θ).

---

## 4.4 Mimicry Attack Resilience

**Threat:** Attacker knows the general approach (DFA whitelist) but not the specific DFA. Attacker inserts k padding syscalls between each exploit syscall to stretch the exploit sequence and avoid crossing a detection window.

**Claim:** Padding causes DFA state drift into edge or rejecting states independent of k.

**Argument:** Let $p_1, p_2, \ldots, p_k$ be padding syscalls. Each $p_i$ is a valid transition in the training distribution — but from the DFA's current state, not from the exploit path state. After the first padding syscall, the DFA transitions to a state $q'$ that was reached by observing $p_1$ from an exploit-path state. $q'$ was likely never observed during training (since exploit-path states were absent from the training data — the model was trained on normal only). Therefore $q'$ is either an edge state or has no outgoing transitions for subsequent tokens.

**Limitation:** This argument holds strictly when the exploit-path states are disjoint from normal-path states in the DFA. If K is too small and normal and exploit states merge into the same cluster, resilience degrades. This is one motivation for adequate K.

---

## 4.5 DFA Fidelity Bound

**Definition:** Fidelity = fraction of test windows where the DFA and Transformer agree on the anomaly verdict (above/below threshold).

**Upper bound:** Fidelity is bounded by the K-Means quantization error. Formally, if two windows $w_1, w_2$ produce identical DFA trajectories (same sequence of state IDs) but different Transformer NLL scores, they receive the same DFA verdict. Fidelity loss is proportional to the rate of such collisions.

Increasing K reduces collisions but increases map size. The optimal K minimizes FPR + (1 - Fidelity) subject to map size constraints.
