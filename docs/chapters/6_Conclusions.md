# Chapter 6 — Conclusions

## 6.1 Summary

*(To be written after experiments.)*

This thesis addresses the enforcement gap in syscall-based HIDS: trained neural models achieve high detection accuracy but cannot run in the kernel. Guepard Shield closes this gap by:

1. Training a decoder-only Transformer on normal syscall sequences using next-token prediction.
2. Extracting a DFA from the Transformer's final-layer hidden states via K-Means clustering and transition construction.
3. Resolving non-determinism in the extracted automaton, with Statistical Pruning (S4) as the primary strategy, justified by the skewed distribution of syscall transition frequencies.
4. Deploying the DFA as an O(1) eBPF BPF-map lookup, enforcing a per-thread whitelist on the continuous syscall stream with no concept of "recording" at runtime.

The system provides structural mimicry attack resilience: padding attacks that stretch exploit sequences cause DFA pointer drift into edge states from which recovery is not possible.

## 6.2 Limitations

- **Static DFA:** The DFA captures behavior observable in the training set. Novel legitimate software behavior (updates, new code paths) may trigger false positives until the DFA is updated.
- **K-Means convergence:** DFA quality depends on the quality of hidden state clustering. Transformer hidden states may not cluster cleanly for all LID-DS scenarios.
- **Composite token alphabet:** The bucket boundaries for return code discretization are manually chosen; suboptimal bucketing may degrade tokenization quality.
- **Thread lifecycle management:** Short-lived threads or threads with very few syscalls may not accumulate enough context for meaningful DFA state tracking.

## 6.3 Future Work

- **Online DFA update:** Incremental K-Means or online clustering to update DFA states without full retraining when new behavior patterns are observed.
- **Adversarial evaluation:** White-box mimicry attacks against a known DFA; study whether an attacker with knowledge of the DFA structure can craft valid transition paths through the automaton.
- **Multi-host DFA sharing:** Train a shared DFA from syscall traces across multiple hosts; measure generalization.
- **Alternative state representations:** Replace K-Means with learned quantization (VQ-VAE) for better cluster boundaries; compare fidelity vs. K-Means baseline.
- **Extend to container workloads:** Apply the pipeline to containerized microservices; evaluate per-container DFA policies.
