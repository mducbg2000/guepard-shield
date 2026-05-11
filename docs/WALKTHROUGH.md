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
