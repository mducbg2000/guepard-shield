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

## ⏳ Phase 2: Teacher Model — Not Implemented In Current Tree

The repository currently does **not** contain a maintained Transformer training pipeline. Any earlier experiments should be considered deprecated. Current docs under `docs/chapters/` describe the **new intended architecture**, not an implemented Phase 2 baseline.

---

## ⏳ Phase 3: Rule Distillation — Not Implemented In Current Tree

No maintained rule-distillation or DFA-extraction code is present in this checkout. The thesis chapters describe the current design direction only.

---

## ⏳ Phase 4: Deployment — Planned

The Rust / Aya code in this repo is still a scaffold. It is not yet connected to a trained Phase 2 model or a distilled Phase 3 artifact.
