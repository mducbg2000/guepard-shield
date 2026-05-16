# Project Walkthrough & Progress Report

This document tracks the actual implementation progress of the Guepard Shield project. It serves as a technical bridge between sessions.

---

## ✅ Phase 1: EDA & Data Preprocessing (Completed)

- **Datasets Analyzed:** LID-DS-2021 (Primary), LID-DS-2019, DongTing.
- **Key Findings:**
  - Syscall sequences are highly repetitive (normal server traffic).
  - Window size `W` is a key hyperparameter for capturing attack context.
  - Test set is significantly larger than Train/Val and includes temporal metadata.
- **Data Pipeline:**
  - Built specialized loaders for `.sc` and `.json` formats.
  - Implemented **Exact Deduplication** (using `np.unique`) to reduce noise in training data.
  - Implemented **Window-level Labeling** using exploit timestamps from JSON metadata.

---

## ⏳ Phase 2: Teacher Model — Planned

Source code removed. To be reimplemented.

---

## ⏳ Phase 3: Rule Distillation — Planned

Source code removed. Depends on Phase 2 completion.

---

## ⏳ Phase 4: Deployment — Planned

eBPF enforcement. Depends on Phase 3 completion.
