"""Configuration module for guepard-shield-model.

Defines data paths and hyperparameters as global variables.
Notebooks and library functions import these directly.

Example (notebook)::

    from gp import config
    config.d_model = 512        # override before training
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

# ===========================================================================
# Hyperparameters
# ===========================================================================

# ── Data pipeline ────────────────────────────────────────────────────
window_size: int = 1000  # syscalls per window
stride_train: int = 1000  # Increased to 1000 (no overlap) for faster training
stride_eval: int = 1000  # non-overlapping for test
max_windows_train: int = 500  # cap per recording in train split
max_windows_eval: int | None = None  # None = all windows
max_syscalls_train: int = 251_000
max_syscalls_eval: int = 50_000
vocab_min_freq: int = 2

# ── Model architecture ───────────────────────────────────────────────
d_model: int = 256
nhead: int = 8
num_layers: int = 4 # Optimized for speed
dim_feedforward: int = 1024
dropout: float = 0.1

# ── Training ─────────────────────────────────────────────────────────
epochs: int = 150
batch_size: int = 16  # physical batch
eval_batch_size: int = 16
grad_accum_steps: int = 8 
use_mixed_precision: bool = True
learning_rate: float = 1e-3
weight_decay: float = 1e-4
patience: int = 5
threshold: float = 0.5

# ── Output Paths ─────────────────────────────────────────────────────
ar_dir: Path = PROCESSED_DATA_DIR / "lidds2021_ar"
npy_dir: Path = PROCESSED_DATA_DIR / "lidds2021"
vocab_path: Path = RESULTS_DIR / "eda_cross_dataset" / "vocab_lidds2021_train.txt"
ckpt_path: Path = RESULTS_DIR / "checkpoints" / "transformer" / "best"
metrics_path: Path = RESULTS_DIR / "p2_transformer_metrics.json"
history_plot_path: Path = RESULTS_DIR / "p2_train_history.png"
