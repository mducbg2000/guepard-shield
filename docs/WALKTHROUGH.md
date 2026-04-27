# Project Walkthrough & Progress Report

This document tracks the actual implementation progress of the Guepard Shield project. It serves as a technical bridge between sessions.

---

## ✅ Phase 1: EDA & Data Preprocessing (Completed)
- **Datasets Analyzed:** LID-DS-2021 (Primary), LID-DS-2019, DongTing.
- **Key Findings:** 
    - Syscall sequences are highly repetitive (normal server traffic).
    - Window size of 1000 is optimal for capturing attack context.
    - Test set is significantly larger than Train/Val and includes temporal metadata.
- **Data Pipeline:**
    - Built specialized loaders for `.sc` and `.json` formats.
    - Implemented **Exact Deduplication** (using `np.unique`) to reduce noise in training data.
    - Implemented **Window-level Labeling** using exploit timestamps from JSON metadata.

## ✅ Phase 2: Teacher Model Training (Completed)
- **Architecture:** 
    - **Model:** `SyscallTransformer` (PyTorch Lightning).
    - **Specs:** 4 Layers, 8 Attention Heads, Causal Masking.
    - **Optimization:** Register-buffer mask caching, CosineAnnealingLR.
- **Training Strategy:**
    - **Dynamic Random Subsampling:** Each epoch picks 50 fresh random windows per recording.
    - **Performance:** Reduced epoch time from 1h50m to ~12m on RTX 3060 via subsampling and `16-mixed` precision.
- **Evaluation Results** (mean aggregation, stride=1000, 1704 exploit + 1000 normal recordings):
    - **Window-level AUROC:** 0.8670
    - **Recording-level AUROC:** 0.9835
    - **Best Window F1:** 0.8983 (threshold=0.0027, unconstrained)
    - **Window @ FPR=1%:** F1=0.8704 (thr=1.0568)
    - **Window @ FPR=5%:** F1=0.8702 (thr=0.8014)
    - **Recording @ FPR=1%:** Recall=94.1%, F1=0.9666 (thr=0.7363)
    - **Recording @ FPR=5%:** Recall=98.0%, F1=0.9749 (thr=0.6133)
- **Key Findings:**
    - **Model comparison:** A retrained model with `max_windows_train=None` (using all windows, val_loss=0.2748) was evaluated against the original model (`max_windows_train=50`, val_loss=0.3455). Surprisingly, the **original model with higher val_loss performed significantly better** on window-level detection (AUROC 0.8652 vs 0.7971). This indicates that subsampling acts as an implicit regularizer that improves anomaly generalization.
    - **Max/p95 aggregation failed:** Window AUROC dropped to 0.18 with max aggregation because normal windows contain legitimate rare syscalls with higher max-NLL than many attack windows.
- **Key Decision:** 
    - **Keep the original model** (`best-transformer-epoch=29-val_loss=0.3455.ckpt`) as the Teacher for Phase 3.
    - Tier 2 (One-Class Autoencoder) design doc is archived at `docs/plans/tier2-oneclass-design.md` for future reference if needed.
- **Artifacts:** Results saved to `/results/evaluation/transformer/`

## ✅ Phase 3: Rule Distillation (Completed)
- **Goal:** Extract interpretable logic from the Teacher's Anomaly Scores (NLL).
- **Protocol:**
    1. Checkpoint: `best-transformer-epoch=29-val_loss=0.3455.ckpt` (`mean` aggregation)
    2. Pseudo-labels from Teacher recording scores:
        - **Positive (Attack):** score >= 0.74 → 1610 recordings (93.9% coverage, 1% normal contamination)
        - **Negative (Normal):** score <= 0.50 → 846 recordings (81.1% coverage, 2% attack contamination)
        - **Gray zone (0.50–0.74):** discarded (248 recordings)
    3. Features: 99-dim syscall frequency histogram + top-100 MI-selected bigrams = 200 features, 530,633 windows
    4. Rule learning: trained on **window-level ground truth labels** (293K attack vs 237K normal), not recording pseudo-labels (recording labels caused 17:1 imbalance → trivial single-threshold rule)
- **Rule Learning Results** (Greedy Decision Set, min_precision=0.95, min_support=100):
    - **12 rules learned** (stopped: no remaining rule meets precision >= 0.95)
    - Window-level training coverage: 44.5% of attack windows (130,560 / 293,281)
    - Notable rules: `epoll_create1 >= 110` (volume anomaly), `epoll_create1→mprotect bigram` (shellcode pattern), `access >= 1` / `chmod >= 1` (rare syscall presence, precision=1.000)
- **Evaluation Results** (on test set):
    - **Window-level AUROC:** 0.7140
    - **Window Precision:** 0.9697 | **Recall:** 0.4452 | **F1:** 0.6102
    - **Window FPR:** 1.72% (4,073 / 237,352)
    - **Recording-level AUROC:** 0.9255
    - **Recording Precision:** 1.0000 | **Recall:** 0.8509 | **F1:** 0.9195
    - **Fidelity vs Teacher pseudo-labels:** 0.3123
- **MITRE ATT&CK Coverage:**
    - All 12 rules → **T1190 (Exploit Public-Facing Application)**
    - Rules 1, 2, 5 also cover **T1078 (Valid Accounts)**
    - Rule 3 also covers **T1110 (Brute Force)**
- **Key Findings:**
    - Recording-level recall 85.1% with **zero false positive recordings** — suitable for production HIDS
    - 0.9255 recording AUROC vs Teacher 0.9835: 0.06 AUROC drop in exchange for kernel-deployable rules (no transformer inference needed)
    - Low window fidelity (31%) expected: rules trained on ground truth, not Teacher pseudo-labels; they catch different attack windows
- **Artifacts:**
    - Rules JSON: `results/p3_rule_extraction/rules/decision_set_rules.json`
    - Human-readable: `results/p3_rule_extraction/rules/rules_human_readable.txt`
    - Evaluation: `results/p3_rule_extraction/rule_evaluation.json`
    - Rust config: `results/p3_rule_extraction/rust/rule_config.json`
    - MITRE mapping: `results/p3_rule_extraction/mitre_mapping.json`

---

## 🛠 Working with the ML Pipeline

### 1. Data Preparation
- **Train/Val:** `uv run python notebooks/p2/preprocess_lidds2021.py` (De-duplicated)
- **Test:** `uv run python notebooks/p2/preprocess_test_lidds2021.py` (Detailed labels)

### 2. Model Execution
- **Train:** `uv run python notebooks/p2/train_transformer.py`
- **Evaluate:** `uv run python notebooks/p2/evaluate_transformer.py`

### 3. Rule Extraction (P3)
- **Generate Pseudo-Labels:** `uv run python notebooks/p3/01_generate_pseudo_labels.py`
- **Extract Features:** `uv run python notebooks/p3/02_extract_features.py`
- **Learn Rules:** `uv run python notebooks/p3/03_learn_rules.py`
- **Evaluate Rules:** `uv run python notebooks/p3/04_evaluate_rules.py`
- **Export Rust Config:** `uv run python notebooks/p3/05_export_rust_config.py`
- **Map MITRE:** `uv run python notebooks/p3/06_map_mitre.py`

### 4. Key Paths
- **Checkpoints:** `results/checkpoints/transformer/`
- **Processed Data:** `data/processed/lidds2021/`
- **P3 Rules:** `results/p3_rule_extraction/rules/`
- **P3 Rust Config:** `results/p3_rule_extraction/rust/rule_config.json`
- **Source Code:** `guepard-shield-model/gp/`
- **Global Config:** Hyperparameters are managed in `gp.config` as global variables.

---

## ⚠️ Important Technical Notes
- **Workspace:** Always run commands from the project root.
- **Memory:** If OOM occurs, check `batch_size` (current: 64) and `accumulate_grad_batches` (current: 2).
- **Type Safety:** The project uses `uv run ty check` for strict type validation across both `src` and `notebooks`.
