# EDA Report — Syscall HIDS Datasets

**Generated:** 2026-04-13  
**Project:** Guepard Shield: A novel data breach detection mechanism using kernel-level information  
**Datasets:** LID-DS-2021 (primary), LID-DS-2019 (cross-domain), DongTing (cross-domain)

---

## Table of Contents

1. [Dataset Overview](#1-dataset-overview)
2. [LID-DS-2021 (Primary)](#2-lid-ds-2021-primary)
3. [LID-DS-2019 (Cross-Domain Validation)](#3-lid-ds-2019-cross-domain-validation)
4. [DongTing (Cross-Domain Validation)](#4-dongtingdt2022-cross-domain-validation)
5. [Cross-Dataset Analysis](#5-cross-dataset-analysis)
6. [Implications for Phase 2 (Model Training)](#6-implications-for-phase-2-model-training)

---

## 1. Dataset Overview

| Property                  | LID-DS-2021           | LID-DS-2019           | DongTing                   |
|---------------------------|-----------------------|-----------------------|----------------------------|
| Total recordings          | 17,190                | 11,368                | 18,965                     |
| Scenarios / classes       | 15 CVE/CWE            | 10 CVE/CWE            | Kernel bugs (26 sources)   |
| Train/val/test split      | Pre-defined           | None (flat)           | Pre-defined                |
| Attack label granularity  | Recording-level       | Recording-level       | Recording-level            |
| Syscall representation    | Timestamped trace     | Timestamped trace     | Name-only sequence         |
| Thread information        | Yes (`thread_id`)     | Yes (`thread_id`)     | No                         |
| Attack timing metadata    | Yes (`exploit_times`) | Yes (`exploit_start`) | No                         |
| Unique syscall vocab      | 99 real + `<unknown>` | 100                   | 330                        |

Artifact directories: `results/eda_lidds2021/`, `results/eda_lidds2019/`, `results/eda_dongting/`, `results/eda_cross_dataset/`

---

## 2. LID-DS-2021 (Primary)

### 2.1 Recording Counts

| Split | Normal | Exploit | Total  |
|-------|--------|---------|--------|
| train | 3,149  | 0       | 3,149  |
| val   | 885    | 0       | 885    |
| test  | 11,341 | 1,815   | 13,156 |
| **Total** | **15,375** | **1,815** | **17,190** |

**Key observations:**
- Exploit recordings are **test-only** — train and val contain exclusively normal traffic. This imposes a semi-supervised learning framing: learn a normality model from clean sequences, detect deviations at test time.
- Class imbalance at test: 86% normal / 14% exploit. Threshold selection on the val split (all-normal) requires held-out normal data as the reference distribution.

### 2.2 Sequence Lengths

| Split | p50    | p90     | p99     | max       |
|-------|--------|---------|---------|-----------|
| train | 95,429 | 716,697 | 935,972 | 1,104,985 |
| val   | 75,721 | 706,368 | 932,592 | 1,021,478 |
| test  | 91,505 | 745,804 | 997,338 | 6,216,251 |

**Key observations:**
- Median recording is ~95K exit-syscall events — these are long sequences.
- High variance: p50→p90 spans ~8×, driven by long-running containerized workloads under load.
- One test outlier at 6.2M syscalls (6× the training max) — fixed-length-input models need a windowing strategy.
- Train and val distributions are consistent; the test outlier is exploit-class-only.

### 2.3 Syscall Vocabulary

| Split | Vocab size |
|-------|-----------|
| train | 100 (99 real + `<unknown>`) |
| val   | 100       |
| test  | 114       |

**OOV syscalls in test but not train (14):**
`chown`, `faccessat`, `fadvise64`, `getgroups`, `getpgrp`, `getpriority`, `mremap`, `prlimit`, `pselect6`, `sendmsg`, `setpgid`, `setpriority`, `setsid`, `vfork`

**Top-10 syscalls by frequency (train):**
`futex`, `epoll_wait`, `sched_yield`, `read`, `lstat`, `fcntl`, `stat`, `fstat`, `lseek`, `newfstatat`

**Key observations:**
- Compact 99-syscall vocabulary dominated by web-server I/O primitives, consistent with containerized Apache/nginx workloads.
- Several OOV syscalls are classic post-exploitation indicators: `vfork` (process spawning), `mremap` (memory remapping for shellcode), `sendmsg` (socket-based C2 communication), `setpgid`/`setsid` (detaching from terminal — daemonization).
- `futex` + `epoll_wait` together account for ~30% of all events — reflects multi-threaded, I/O-bound server workloads.
- `<unknown>` appears in training traces: sysdig-captured syscalls with unresolved names (likely kernel version mismatches). Treat as a valid vocabulary token.

### 2.4 Thread Structure

| Split | Median threads | Max | Min |
|-------|---------------|-----|-----|
| train | 1.0           | 4   | 0   |
| val   | 1.0           | 3   | 1   |
| test  | 1.0           | 4   | 1   |

**Key observations:**
- Recordings are effectively **single-threaded** per container (median = 1). The monitoring captures isolated container activity, not host-wide thread pools.
- Max 4 threads suggests occasional worker-pool patterns (e.g. pre-fork Apache).
- Low thread count simplifies sequence modeling: no need for complex multi-stream alignment or thread interleaving logic.
- One training recording has 0 threads (no exit events — likely an empty/failed container start); filter before training.

### 2.5 Attack Timing

Based on 2,173 exploit timestamps across test recordings (some recordings have multiple events):

| Metric     | Median | p90   | Max    |
|------------|--------|-------|--------|
| Offset (s) | 11.1 s | 17.2s | 53.4s  |
| Fraction   | 0.48   | 0.71  | 186.96 |

**Key observations:**
- Attacks start ~11s after warmup ends — consistently in the first half of the recording.
- Median fraction 0.48: the exploit arrives halfway through the trace, meaning the pre-attack normal segment is roughly equal in length to the post-attack segment.
- Max fraction of 186.96 (far beyond 1.0) is a **metadata timing artifact** — some exploit timestamps are recorded after the trace has ended. Do not use fraction as a feature; use syscall-count position instead.
- The compact 11–17s attack window (90th percentile) means a model with a sliding window of ~1,000 syscalls should be able to isolate the attack context.

---

## 3. LID-DS-2019 (Cross-Domain Validation)

### 3.1 Recording Counts

| Label   | Count  |
|---------|--------|
| normal  | 10,206 |
| exploit | 1,162  |
| **Total** | **11,368** |

Per scenario (10 scenarios, ~1,063–1,395 each):

| Scenario              | Count |
|-----------------------|-------|
| Bruteforce_CWE-307    | 1,092 |
| CVE-2012-2122         | 1,395 |
| CVE-2014-0160         | 1,100 |
| CVE-2017-7529         | 1,157 |
| CVE-2018-3760         | 1,221 |
| CVE-2019-5418         | 1,079 |
| EPS_CWE-434           | 1,071 |
| PHP_CWE-434           | 1,112 |
| SQL_Injection_CWE-89  | 1,078 |
| ZipSlip               | 1,063 |

**Key observations:**
- No predefined train/val/test split — use for cross-domain evaluation only, never for training.
- Exploit ratio 10.2% (vs 13.8% in LID-DS-2021 test) — similar class balance.
- Scenarios are well-balanced (~1,100 each), enabling fair per-scenario evaluation.
- 10 of the 15 LID-DS-2021 scenarios appear here, providing direct comparison ground.

### 3.2 Sequence Lengths

| Label   | p50    | p90     | p99     | max     |
|---------|--------|---------|---------|---------|
| normal  | 12,485 | 154,978 | 315,037 | 326,852 |
| exploit | 17,357 | 148,724 | 318,865 | 333,639 |

**Key observations:**
- Sequences are **7–8× shorter** than LID-DS-2021 (p50: 12K vs 95K). Both datasets monitor containerized web servers, so the difference reflects different recording durations or monitoring scopes.
- Exploit recordings are slightly *longer* than normal at the median — the extra attack-phase syscalls inflate the trace.
- Tight max (~326K vs 1.1M in LID-DS-2021) indicates more uniform, controlled recording conditions.
- If applying a LID-DS-2021-trained window-based model to LID-DS-2019, window coverage is similar but absolute sequence positions differ — position-invariant detection is preferable.

### 3.3 Syscall Vocabulary

| Label   | Vocab size |
|---------|-----------|
| normal  | 93        |
| exploit | 100       |
| **Total** | **100** |

**Syscalls in exploit but not in normal (7):**
`fdatasync`, `fstatfs`, `getgroups`, `kill`, `mremap`, `rmdir`, `sendmmsg`

**Top-10 syscalls by frequency (normal):**
`futex`, `write`, `read`, `mprotect`, `open`, `gettid`, `fstat`, `close`, `mmap`, `newfstatat`

**Key observations:**
- Normal vocab (93) is a strict subset of exploit vocab (100). The 7 exploit-exclusive syscalls are attack-phase indicators: `kill` (process signaling), `mremap` (memory manipulation), `rmdir`/`fdatasync` (post-exploitation file operations).
- Top-10 is near-identical to LID-DS-2021 — both datasets use the same class of containerized web-server targets.
- The full dataset vocab (100) matches LID-DS-2021 train (99) almost exactly — only 11 syscalls differ across both sets combined (see Section 5.1).

### 3.4 Thread Structure

| Label   | Median threads | Max  | Min |
|---------|---------------|------|-----|
| normal  | 34.0          | 1004 | 2   |
| exploit | 40.0          | 1021 | 2   |

**Key observations:**
- **Critical structural difference from LID-DS-2021**: median 34 threads vs median 1. LID-DS-2019 captures the entire host, not an isolated container.
- Up to 1,021 threads in an exploit recording — may reflect a fork-bomb or high-concurrency attack pattern.
- For cross-domain evaluation, per-thread sequences must either be flattened (concatenate all thread syscalls by timestamp) or aggregated into per-process-group streams. Raw application of a single-thread model from LID-DS-2021 requires preprocessing.

### 3.5 Attack Timing

| Metric     | Median | p90  | Max  |
|------------|--------|------|------|
| Offset (s) | 14.0 s | 27.0s| 38.0s|
| Fraction   | 0.40   | 0.69 | 0.76 |

**Key observations:**
- Attacks start slightly earlier (fraction 0.40 vs 0.48 in LID-DS-2021) and the max fraction is bounded at 0.76 — no timing artifacts.
- Wider offset range (14–27s at 90th percentile) vs LID-DS-2021's 11–17s — more variable experimental conditions.

---

## 4. DongTing (DT2022) — Cross-Domain Validation

### 4.1 Recording Counts

| Split | Normal | Abnormal | Total  |
|-------|--------|----------|--------|
| train | 5,486  | 9,356    | 14,842 |
| val   | 685    | 1,127    | 1,812  |
| test  | 678    | 1,633    | 2,311  |
| **Total** | **6,849** | **12,116** | **18,965** |

**Key observations:**
- **Inverted class balance**: abnormal sequences outnumber normal (64% vs 36%). Unlike LID-DS-2021/2019 where normal dominates, DongTing trains on imbalanced data.
- "Abnormal" here means kernel bug PoC syscall traces — not live network exploit sessions. Different threat model.
- Use stratified sampling when computing metrics on this dataset.

### 4.2 Sequence Lengths

| Split / Label   | p50 | p90       | p99        | max          |
|-----------------|-----|-----------|------------|--------------|
| train / normal  | 61  | 330       | 245,235    | 4,645,272    |
| train / abnormal| 85  | 1,083,313 | 20,884,597 | 59,268,103   |
| val / normal    | 61  | 220       | 77,656     | 3,421,266    |
| val / abnormal  | 36  | 2,077,562 | 36,852,890 | **100,000,000** |
| test / normal   | 61  | 196       | 504,068    | 14,397,021   |
| test / abnormal | 33  | 12,657    | 8,368,234  | 51,265,024   |

**Key observations:**
- **Extreme bimodality**: normal sequences are very short (p50 = 61 syscalls), reflecting quick kernel test invocations. Abnormal sequences have enormous variance — PoCs range from a few dozen to 59M syscalls.
- The `val/abnormal` max of 100,000,000 is a **hard-capped truncation artifact** — exclude or clip sequences at a sensible maximum (e.g. 50M).
- Normal p50 = 61 vs LID-DS-2021 train p50 = 95,429 — a 1,500× difference. The distributions do not overlap; any model trained on LID-DS-2021 will need domain adaptation before evaluation on DongTing normals.
- Sequence length alone cannot discriminate: abnormal p50 (33–85) overlaps with normal p50 (61). Do not use raw length as a feature.

### 4.3 Syscall Vocabulary

| Split | Vocab size |
|-------|-----------|
| train | 326       |
| val   | 244       |
| test  | 246       |
| **Full corpus** | **330** |

**OOV syscalls in test but not train (3):**
`set_mempolicy`, `time`, `utimes`

**Top-10 syscalls by frequency (train):**
`close`, `wait4`, `socket`, `nanosleep`, `setsockopt`, `mmap`, `clone`, `prctl`, `setpgid`, `exit_group`

**Syscalls exclusive to Abnormal_data (not in Normal_data) — 15:**
`eventfd`, `fork`, `get_mempolicy`, `kexec_load`, `mbind`, `migrate_pages`, `mknod`, `nanosleep`, `pkey_mprotect`, `restart_syscall`, `seccomp`, `semop`, `set_mempolicy`, `setrlimit`, `utimes`

**Key observations:**
- Vocabulary is 3× larger than LID-DS-2021 (330 vs 99) due to kernel-level test coverage.
- `socket`, `nanosleep`, `clone`, `prctl`, `setpgid`, `exit_group` in the top-10 are absent or rare in LID-DS-2021 — fundamentally different syscall distribution.
- Abnormal-exclusive syscalls include NUMA primitives (`mbind`, `migrate_pages`, `get_mempolicy`), security interfaces (`seccomp`, `pkey_mprotect`), and low-level process management (`kexec_load`, `fork`) — specific to kernel exploit PoCs.
- Low OOV at test (3 syscalls) indicates stable intra-dataset vocabulary coverage.

### 4.4 Source Distribution

| Source          | Count | Notes                            |
|-----------------|-------|----------------------------------|
| glibc           | 2,884 | Normal — glibc test suite        |
| ltp             | 2,561 | Normal — Linux Test Project      |
| posixtest       | 1,235 | Normal — POSIX conformance tests |
| kselftest       | 170   | Normal — kernel self-tests       |
| kernel_v4.15    | 1,540 | Abnormal — per-version PoCs      |
| kernel_v5.3     | 907   | Abnormal                         |
| kernel_v4.16    | 727   | Abnormal                         |
| … (26 sources total) | … |                                 |

**Key observations:**
- Normal recordings come from systematic POSIX/glibc test suites — controlled, well-characterised baselines.
- Abnormal recordings span kernel versions 4.13–5.9, tied to specific vulnerability PoCs per kernel release.
- Version coverage enables evaluation of robustness across kernel generations; a model should not memorise version-specific syscall patterns.

---

## 5. Cross-Dataset Analysis

*All vocab figures confirmed by full corpus scans.*  
Detailed artifacts: `results/eda_cross_dataset/`

### 5.1 Vocabulary Overlap

| Comparison                           | A    | B   | ∩   | Only A | Only B |
|--------------------------------------|------|-----|-----|--------|--------|
| LID-DS-2021 train vs LID-DS-2019     | 99   | 100 | **94** | 5   | 6      |
| LID-DS-2021 train vs DongTing        | 99   | 330 | **96** | 3   | 234    |
| LID-DS-2019 vs DongTing              | 100  | 330 | **97** | 3   | 233    |
| **All three**                        |      |     | **91** |     |        |

**Syscalls in LID-DS-2021 train but NOT in LID-DS-2019 (5):**
`bind`, `epoll_pwait`, `fchown`, `tgkill`, `utimensat`

**Syscalls in LID-DS-2019 but NOT in LID-DS-2021 train (6):**
`fstatfs`, `getgroups`, `mremap`, `rmdir`, `rt_sigsuspend`, `sendmsg`

**Syscalls in LID-DS-2021 train but NOT in DongTing (3):**
`pread`, `pwrite`, `utime`

**Syscalls in DongTing but NOT in LID-DS-2021 (234):**
`accept4`, `acct`, `add_key`, `adjtimex`, `alarm`, `bpf`, `capget`, `capset`, `chown`, `chroot`, `clock_gettime`, `clock_nanosleep`, `clone3`, `close_range`, `copy_file_range`, `delete_module`, `dup2`, `dup3`, `epoll_create`, `eventfd`, `eventfd2`, `execveat`, `exit`, `exit_group`, `faccessat`, `fork`, `get_mempolicy`, `kexec_load`, `mbind`, `migrate_pages`, … (full list: `results/eda_cross_dataset/vocab_dongting_full.txt`)

**Key observations:**
- **LID-DS-2021 ↔ LID-DS-2019**: 94% vocab overlap (94/99). The 11-syscall delta reflects minor instrumentation differences between dataset versions (different sysdig releases). Generalisation from 2021 to 2019 is largely vocabulary-transparent.
- **LID-DS-2021 ↔ DongTing**: 97% of LID-DS-2021 syscalls appear in DongTing (`pread`/`pwrite`/`utime` are legacy POSIX aliases covered by `read`/`write`/`utimensat`). But DongTing adds 234 kernel-specific syscalls as OOV.
- The 3 missing LID-DS-2021 syscalls in DongTing (`pread`, `pwrite`, `utime`) are semantic duplicates of `read`/`write`/`utimensat` — not a meaningful gap.
- **OOV strategy for DongTing**: map 234 unseen syscalls to `<unk>`. The model will still see 96% of syscall tokens it was trained on; detection should degrade gracefully rather than fail.

### 5.2 Structural Comparison

| Dimension              | LID-DS-2021       | LID-DS-2019          | DongTing               |
|------------------------|-------------------|----------------------|------------------------|
| Monitoring scope       | Per-container     | Whole-host           | Whole-host (test suites)|
| Thread count           | 1–4 (median 1)    | 2–1,021 (median 34)  | N/A (no thread info)   |
| Attack label type      | Live CVE exploit  | Live CVE exploit     | Kernel bug PoC         |
| Seq length (p50/p99)   | 95K / 936K        | 12K / 315K           | 61 / 500K (bimodal)    |
| Temporal metadata      | Yes               | Yes                  | No                     |
| Class balance (all)    | 89% normal        | 90% normal           | 64% abnormal           |

**Key structural incompatibilities:**
1. **Thread scope mismatch**: LID-DS-2021 trains on single-container, single-threaded streams. LID-DS-2019 captures host-level multi-threaded activity (median 34 threads). Applying a LID-DS-2021 model to raw LID-DS-2019 recordings requires thread-stream aggregation (e.g. merge by timestamp, or evaluate per-process-group).
2. **Attack definition mismatch**: LID-DS-2021/2019 measure exploitation of running services; DongTing measures kernel crash/misbehavior. Cross-domain results reveal whether the model learns general anomaly patterns vs service-specific deviation.
3. **Sequence length mismatch**: DongTing normal sequences (p50 = 61) are 1,500× shorter than LID-DS-2021 normals. Sliding-window models will produce mostly-empty windows on DongTing normals, making direct score comparison unreliable. Evaluate separately with per-dataset thresholds.

### 5.3 Attack Signal Characteristics

| Dataset     | Attack offset (median) | Fraction (median) | Fraction bounded? |
|-------------|------------------------|-------------------|-------------------|
| LID-DS-2021 | 11.1 s                 | 0.48              | No (artifact up to 187) |
| LID-DS-2019 | 14.0 s                 | 0.40              | Yes (max 0.76)    |
| DongTing    | N/A                    | N/A               | N/A               |

- Both LID-DS datasets place the attack in the middle of the recording. A model evaluated on a fixed suffix window will systematically miss the attack for recordings in the earliest-attack quartile.
- Use syscall-count position (not time-fraction) for positioning within a recording, to avoid the LID-DS-2021 timing artifact.

---

## 6. Implications for Phase 2 (Model Training)

### 6.1 Input Representation

| Decision | Finding | Recommendation |
|---|---|---|
| Vocabulary size | 99 real + `<unknown>` in train | Use 101-token vocab: 99 real + `<unknown>` + `<unk>` for OOV |
| OOV handling | DongTing adds 234 unseen syscalls | `<unk>` token; evaluate embedding robustness at test time |
| Thread aggregation | LID-DS-2021: 1–4 threads; LID-DS-2019: up to 1,021 | Merge threads by timestamp for LID-DS-2019 evaluation |
| Sequence windowing | Median 95K, max 6.2M | Sliding window ≤ 10K syscalls; stride ~50% |
| Empty recordings | 1 train recording with 0 syscalls | Filter before training |

### 6.2 Class Imbalance Strategy

| Dataset          | Setup                              | Implication                          |
|------------------|------------------------------------|--------------------------------------|
| LID-DS-2021 train/val | Normal-only                   | One-class or reconstruction-based loss |
| LID-DS-2021 test | 86% normal / 14% exploit          | AUROC primary metric; threshold from val |
| LID-DS-2019      | 90% normal / 10% exploit (no split) | Cross-domain AUROC; no threshold tuning |
| DongTing         | 36% normal / 64% abnormal         | Stratified evaluation; report per-class F1 |

### 6.3 Cross-Domain Evaluation Protocol

1. **Train** on LID-DS-2021 train (3,149 normal recordings only).
2. **Threshold** on LID-DS-2021 val (885 normal recordings; set working point at target FPR).
3. **Primary eval** on LID-DS-2021 test (AUROC, F1 at chosen threshold).
4. **Cross-domain A**: apply to LID-DS-2019 — aggregate multi-thread streams by timestamp; map 6 missing LID-DS-2021 tokens to `<unk>`; evaluate AUROC.
5. **Cross-domain B**: apply to DongTing — map 234 OOV syscalls to `<unk>`; use separate threshold (DongTing sequence lengths differ drastically); evaluate AUROC. Interpret results qualitatively given the structural mismatches.

### 6.4 Known Data Quality Issues

| Issue | Dataset | Recommended action |
|---|---|---|
| Attack fraction > 1.0 (timing drift) | LID-DS-2021 | Use syscall-count position; discard time-fraction metadata |
| `val/abnormal` max = 100M (truncation cap) | DongTing | Clip or exclude sequences above 50M syscalls |
| `<unknown>` token in train traces | LID-DS-2021 | Retain as a valid vocabulary token |
| 1 recording with 0 syscalls | LID-DS-2021 | Filter from training set |
| No predefined split | LID-DS-2019 | Use as cross-domain eval only — never for training or threshold selection |
| Thread-level vs container-level scope | LID-DS-2019 vs LID-DS-2021 | Document explicitly in cross-domain results |

---

*Per-dataset diagnostic plots and tables are in `results/eda_lidds2021/`, `results/eda_lidds2019/`, `results/eda_dongting/`. Cross-dataset vocabulary files are in `results/eda_cross_dataset/`.*
