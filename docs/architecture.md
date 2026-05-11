# Guepard Shield Architecture

Guepard Shield bridges the gap between Deep Learning accuracy and Kernel-level performance using a **Teacher-Student** distillation approach.

## 🏗️ System Overview

```text
       [ PHASE 2: TEACHER ]                 [ PHASE 3: STUDENT ]
   +---------------------------+        +---------------------------+
   |  SYSCALL TRANSFORMER      |        |   GREEDY DECISION SET     |
   | (Deep Anomaly Detection)   |        |   (Rule Distillation)     |
   +-------------+-------------+        +-------------+-------------+
                 |                                    ^
                 | 1. Evaluate Test Set               | 2. Guide Rule Learning
                 | (NLL Scores / Patterns)            | (Precision-focused)
                 v                                    |
   +--------------------------------------------------+-------------+
   |                 OFFLINE ANALYSIS / DISTILLATION                |
   |      (Feature Extraction: Syscall Counts & Bigrams)            |
   +----------------------------------+-----------------------------+
                                      |
                                      | 3. Export Rules
                                      v
                            [ rule_config.json ]
                                      |
======================================|======================================
                                      | 4. Deploy
       [ PHASE 4: REAL-TIME ]         v
+---------------------------------------------------------------------------+
|                          TARGET HOST (PRODUCTION)                         |
|                                                                           |
|   [ USERSPACE ]                                                           |
|   +-------------------------------------------------------------------+   |
|   |  Guepard Agent (Rust)                                             |   |
|   |  - Load rule_config.json                                          |   |
|   |  - Listen for Suspect Logs <----------------------------------+   |   |
|   +---------+-----------------------------------------------------|---+   |
|             |                                                     |       |
|   [ KERNEL ]| (Aya / eBPF)                                        |       |
|   +---------v-----------------------------------------------------|---+   |
|   |  eBPF Program                                                 |   |   |
|   |  +-------------------------+      +---------------------------+   |   |
|   |  |   Syscall Hook Point    |----->|   Suspect Logic           |   |   |
|   |  | (Tracepoints / LSM)     |      | (Gray zone / Rare Sycalls)|   |   |
|   |  +------------+------------+      +---------------------------+   |   |
|   |               |                                                   |   |
|   |               v                                                   |   |
|   |  +-------------------------+                                      |   |
|   |  |   RULE MATCHER          |                                      |   |
|   |  | (Fast IF-THEN / Maps)   |-----> [ ALERT / BLOCK / LOG ]        |   |
|   |  +-------------------------+                                      |   |
|   +-------------------------------------------------------------------+   |
|                                                                           |
+---------------------------------------------------------------------------+
```

## 🔄 Workflow Breakdown

### 1. Offline Preparation (Analysis Center)
*   **Training (Phase 2):** The Transformer is trained on **Normal** data only to learn the "language of system calls".
*   **Scoring:** The trained model evaluates a **Test Set** (Normal + Attack). It identifies exactly *when* and *why* a sequence is anomalous using Negative Log Likelihood (NLL).
*   **Distillation (Phase 3 - True Distillation):** 
    *   Instead of using ground truth labels, the `GreedyDecisionSet` algorithm uses the **Transformer's NLL scores** as the target.
    *   **Attack Zone:** Learned from windows where $NLL \ge T_{attack}$ (Teacher's 1% FPR threshold).
    *   **Gray Zone:** Extracted via soft-thresholding and rare-syscall detection guided by the Teacher's sensitivity ($NLL \ge T_{gray}$).
    *   This ensures the Student (Rules) accurately mimics the Teacher's (Transformer) expert knowledge.

### 2. Online Enforcement (Real-time)
*   **Deployment:** The extracted rules are exported to `rule_config.json` and loaded by the Rust Agent.
*   **In-Kernel Matching:** The eBPF program performs microsecond-latency checks on every syscall. It doesn't need the Transformer; it only needs the "distilled wisdom" in the form of thresholds.
*   **Suspect Feedback:** If eBPF encounters "Gray zone" activity (suspicious but not yet a rule match), it exports logs back to the Analysis Center for the Transformer to review, enabling automated rule updates for new attack patterns.

## 🧠 Suspect Logic & Gray Zone Mechanism

To balance between **Detection Recall** and **Performance**, Guepard Shield implements a tiered response logic:

1.  **Normal Zone (Low Risk):**
    *   **Criteria:** Syscall patterns are well within the learned "Normal" bounds (e.g., `mprotect < 80`).
    *   **Action:** Passive monitoring, zero overhead beyond counting.
2.  **Gray Zone (Suspect/Nghi ngờ):**
    *   **Criteria:** 
        *   **Soft Thresholds:** Features reach 70-90% of a rule's limit (e.g., `mprotect = 95`, where rule is 110).
        *   **Rare Syscalls:** Appearance of syscalls never seen in Training (e.g., `ptrace`, `kexec_load`).
        *   **Weight Accumulation:** Multiple features are slightly elevated, though none hit a hard rule.
    *   **Action:** **"Bấm chuông" (Ring the bell)**. The Agent captures the current 1000-syscall window and sends it to the Offline Transformer. This allows for deep analysis of potential Zero-day attacks without blocking legitimate users.
3.  **Attack Zone (Critical):**
    *   **Criteria:** Hard match on any Distilled Rule (e.g., `mprotect >= 110`).
    *   **Action:** **BLOCK / KILL / ALERT**. Immediate enforcement at the kernel level.
