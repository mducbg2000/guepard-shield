"""Shared project paths for Guepard Shield.

At the moment, the maintained workflow in this repository is Phase 1
exploration and preprocessing. Keep this module focused on filesystem paths
used by those scripts rather than on stale Phase 2 / Phase 3 experiment
hyperparameters.
"""

from __future__ import annotations
from pathlib import Path

# ===========================================================================
# Base Paths
# ===========================================================================

PROJECT_ROOT = Path.cwd() # Root: guepard-shield/
DATA_ROOT = PROJECT_ROOT / "data"
RESULTS_DIR = PROJECT_ROOT / "results"

# Extracted data paths
EXTRACTED_DATA_DIR = DATA_ROOT / "extracted"
DONGTING_DIR = EXTRACTED_DATA_DIR / "DongTing"
LIDDS_2019_DIR = EXTRACTED_DATA_DIR / "LID-DS-2019"
LIDDS_2021_DIR = EXTRACTED_DATA_DIR / "LID-DS-2021"

# Processed data paths
PROCESSED_DATA_DIR = DATA_ROOT / "processed"
SPLITS_DIR = DATA_ROOT / "splits"

# Syscall table
TBL_PATH = DONGTING_DIR / "syscall_64.tbl"

# Common output paths reused by Phase 1 scripts and derived artifacts
npy_dir: Path = PROCESSED_DATA_DIR / "lidds2021"
vocab_path: Path = RESULTS_DIR / "p1" / "vocab_lidds2021_train.txt"
