# Chapter 6 — Conclusions

## 6.1 Summary

*(Placeholder chapter. No conclusions should be drawn yet from Phase 2 / Phase 3 because those stages are not implemented in the current repository state.)*

At present, the defensible summary of the repository is narrower:

1. Phase 1 EDA and preprocessing have been completed.
2. The later Transformer, DFA extraction, and kernel-enforcement stages remain proposed work.
3. Any future conclusion about fidelity, runtime overhead, or mimicry resilience must wait for a fresh implementation and evaluation cycle.

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
