# Experimental Report: Guepard Shield Intrusion Detection System

## 1. Objective & Methodology
The project aims to bridge the gap between high-accuracy Deep Learning models (Transformer) and real-time kernel-level enforcement (eBPF).
- **Teacher:** A Causal Transformer model trained for anomaly detection in syscall sequences.
- **Student:** A set of human-readable, high-precision rules distilled from the Teacher's knowledge, designed for low-latency eBPF deployment.

## 2. Data Pipeline & Preprocessing (Phase 1)
- **Primary Dataset:** LID-DS-2021 (17,190 recordings).
- **Techniques:**
    - **Sliding Window:** Size of 1000 syscalls.
    - **Exact Deduplication:** Used `np.unique` to remove redundant windows, reducing training noise and OOM risks.
    - **Window-level Labeling:** Every window is labeled as Normal (0) or Attack (1) based on precise exploit timestamps from JSON metadata.

## 3. Teacher Model Training (Phase 2)
- **Architecture:** 4-layer Transformer Encoder, 8 Attention Heads, d_model=256.
- **Training Strategy:** **Dynamic Random Subsampling** (50 fresh windows per recording per epoch). This reduced epoch time from 1h50m to **~12 minutes** on an RTX 3060.
- **Experimental Results (LID-DS-2021 Test Set):**

| Metric | Window-level | Recording-level |
| :--- | :--- | :--- |
| **AUROC** | **0.8670** | **0.9835** |
| **Best F1-Score** | 0.8983 | 0.9749 |
| **F1 @ FPR=1%** | 0.8704 | 0.9666 |
| **Recall @ FPR=1%** | - | **94.1%** |

- **Key Finding:** Subsampling acts as an implicit regularizer, improving the model's ability to generalize to unseen anomalies despite higher validation loss.

## 4. Rule Distillation (Phase 3)
- **Method:** Greedy Decision Set (induction of unordered if-then rules maximizing precision).
- **Features:** 200 eBPF-friendly features (99 syscall frequencies, top 100 bigrams via Mutual Information, and 1 dangerous-syscall rate).
- **Extraction Results:** 12 security rules were learned (e.g., `epoll_create1 >= 110` for volume anomalies, `epoll_create1 -> mprotect` for shellcode patterns).
- **Performance on Test Set:**

| Metric | Window-level | Recording-level |
| :--- | :--- | :--- |
| **AUROC** | 0.7140 | **0.9255** |
| **Precision** | 0.9697 | **1.0000** |
| **Recall** | 0.4452 | 0.8509 |
| FPR | 1.72% | **0.00%** |

### 4.1. Extracted Rules List
The following 12 unordered if-then rules were distilled from the Teacher model:

1.  **Rule 1:** `IF epoll_create1 >= 110` THEN Anomaly (Volume anomaly)
2.  **Rule 2:** `IF epoll_create1→mprotect >= 1` THEN Anomaly (Shellcode/Memory pattern)
3.  **Rule 3:** `IF unlink→statfs >= 2` THEN Anomaly (File system manipulation)
4.  **Rule 4:** `IF execve >= 114` THEN Anomaly (Process spawning volume)
5.  **Rule 5:** `IF access >= 1` THEN Anomaly (Rare syscall presence, Prec=1.0)
6.  **Rule 6:** `IF getgid >= 37` THEN Anomaly (Privilege discovery)
7.  **Rule 7:** `IF lstat >= 31` THEN Anomaly (File discovery)
8.  **Rule 8:** `IF pipe >= 870` THEN Anomaly (IPC volume anomaly)
9.  **Rule 9:** `IF chmod >= 1` THEN Anomaly (Permissions change, Prec=1.0)
10. **Rule 10:** `IF wait4 >= 30` THEN Anomaly (Process management)
11. **Rule 11:** `IF kill >= 47` THEN Anomaly (Signaling/DoS pattern)
12. **Rule 12:** `IF arch_prctl >= 78` THEN Anomaly (Low-level architecture control)

- **Key Finding:** The rules achieved **zero false positives** at the recording level across the entire test set while maintaining an 85% detection rate. This makes the system highly suitable for production HIDS where alert fatigue is a concern.

## 5. MITRE ATT&CK Coverage
All 12 extracted rules map to real-world adversary techniques:
- **T1190 (Exploit Public-Facing Application):** Covered by all 12 rules.
- **T1078 (Valid Accounts):** Covered by Rules 1, 2, and 5.
- **T1110 (Brute Force):** Covered by Rule 3.

## 6. Implementation & Deployment (Phase 4)
- **Tech Stack:** Rust + Aya (eBPF framework).
- **Status:** 
    - Infrastructure for the userspace agent and kernel program is implemented.
    - Automated bridge (`rust_codegen.py`) exists to export Python-learned rules into Rust-compatible JSON.
- **Next Step:** Benchmarking enforcement latency (target <2µs/syscall) and overhead on production workloads (nginx/redis).
