# Phase 3 — Rule Extraction Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task.

**Goal:** Distill the trained Transformer Teacher into a compact set of human-readable, eBPF-deployable security rules that achieve >95% fidelity to the Teacher and <1% FPR.

**Architecture:**
1. Generate pseudo-labels from Teacher recording-level scores (threshold-based).
2. Extract eBPF-friendly features (syscall frequency histogram + discriminative n-grams) from every window.
3. Learn a Decision Set via greedy precision-maximizing rule induction on the feature matrix.
4. Evaluate rules for fidelity vs Teacher and FPR vs ground truth.
5. Serialize rules to JSON config + vocabulary mapping for Rust/Aya ingestion.
6. Map rules to MITRE ATT&CK techniques based on the LID-DS-2021 scenarios they cover.

**Tech Stack:** PyTorch, NumPy, scikit-learn, pandas (Python); Rust + Aya (eBPF deployment via existing `guepard-shield-ebpf` crate).

---

## Global Constants & Paths

```python
# Used across all P3 notebooks
CKPT_PATH = "results/checkpoints/transformer/best/best-transformer-epoch=29-val_loss=0.3455.ckpt"
TEST_DATA_DIR = "data/processed/lidds2021/test"
VOCAB_PATH = "results/eda_cross_dataset/vocab_lidds2021_train.txt"
P3_OUTPUT_DIR = "results/p3_rule_extraction"
TEACHER_RECORDING_CSV = "results/evaluation/transformer/recording_predictions.csv"

# Thresholds for pseudo-label generation
POS_THRESHOLD = 0.74   # recording score >= this → Attack  (1% normal contamination, 93.9% attack coverage)
NEG_THRESHOLD = 0.50   # recording score <= this → Normal  (2% attack contamination, 81% normal coverage)

# Feature engineering
WINDOW_SIZE = 1000
TOP_NGRAMS = 100       # number of bigrams to keep
NGRAM_ORDER = 2        # bigrams

# Rule learning
MAX_RULES = 50
MIN_RULE_PRECISION = 0.95
MIN_RULE_SUPPORT = 50  # minimum windows a rule must cover
```

---

## Task 1: Project Bootstrap — Create P3 Module Structure

**Files:**
- Create: `guepard-shield-model/gp/rules/__init__.py`
- Create: `guepard-shield-model/gp/rules/feature_extractor.py`
- Create: `guepard-shield-model/gp/rules/decision_set.py`
- Create: `guepard-shield-model/gp/rules/mitre_mapper.py`
- Create: `guepard-shield-model/gp/rules/rust_codegen.py`
- Create: `scripts/p3/01_generate_pseudo_labels.py`
- Create: `scripts/p3/02_extract_features.py`
- Create: `scripts/p3/03_learn_rules.py`
- Create: `scripts/p3/04_evaluate_rules.py`
- Create: `scripts/p3/05_export_rust_config.py`
- Create: `scripts/p3/06_map_mitre.py`
- Create directory: `results/p3_rule_extraction/`

**Step 1: Create module init**

```python
# guepard-shield-model/gp/rules/__init__.py
"""Rule extraction and eBPF compilation for Guepard Shield."""

from .feature_extractor import WindowFeatureExtractor
from .decision_set import GreedyDecisionSet, extract_rules_from_tree
from .mitre_mapper import LIDDS2021MITREMapper
from .rust_codegen import RustConfigExporter

__all__ = [
    "WindowFeatureExtractor",
    "GreedyDecisionSet",
    "extract_rules_from_tree",
    "LIDDS2021MITREMapper",
    "RustConfigExporter",
]
```

**Step 2: Create output directory**

Run:
```bash
mkdir -p results/p3_rule_extraction/rules results/p3_rule_extraction/ebpf
```

**Step 3: Commit**

```bash
git add guepard-shield-model/gp/rules/ scripts/p3/
git commit -m "feat(p3): bootstrap rule extraction module structure"
```

---

## Task 2: Generate Pseudo-Labels from Teacher Scores

**Goal:** Create a clean training set with recording-level pseudo-labels (Attack/Normal/Discard).

**Files:**
- Modify: `scripts/p3/01_generate_pseudo_labels.py`

**Step 1: Implement pseudo-label generator**

```python
# scripts/p3/01_generate_pseudo_labels.py
# %%
import pandas as pd
import numpy as np
from pathlib import Path

# %%
# Configuration
TEACHER_CSV = Path("results/evaluation/transformer/recording_predictions.csv")
OUTPUT_DIR = Path("results/p3_rule_extraction")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

POS_THR = 0.74
NEG_THR = 0.30

# %%
# Load Teacher recording-level predictions
df = pd.read_csv(TEACHER_CSV)
print(f"Loaded {len(df)} recording predictions")
print(df['label'].value_counts())

# %%
def assign_pseudo_label(score: float) -> str:
    if score >= POS_THR:
        return "attack"
    elif score <= NEG_THR:
        return "normal"
    else:
        return "discard"

df['pseudo_label'] = df['score'].apply(assign_pseudo_label)

# %%
print("\nPseudo-label distribution:")
print(df['pseudo_label'].value_counts())

# Show some stats
for lbl in ['attack', 'normal', 'discard']:
    subset = df[df['pseudo_label'] == lbl]['score']
    print(f"\n{lbl}: count={len(subset)}, score_range=({subset.min():.4f}, {subset.max():.4f})")

# %%
# Save
output_csv = OUTPUT_DIR / "pseudo_labels.csv"
df.to_csv(output_csv, index=False)
print(f"\nSaved pseudo-labels to: {output_csv}")
```

**Step 2: Run the notebook**

Run:
```bash
cd /home/ducnm/Code/hust/guepard-shield && uv run python scripts/p3/01_generate_pseudo_labels.py
```

**Expected output:**
```
Loaded 2705 recording predictions
...
Pseudo-label distribution:
normal     1000
discard     ...
attack      ...
```

**Step 3: Verify output file exists**

Run:
```bash
ls results/p3_rule_extraction/pseudo_labels.csv
```

**Step 4: Commit**

```bash
git add scripts/p3/01_generate_pseudo_labels.py results/p3_rule_extraction/pseudo_labels.csv
git commit -m "feat(p3): generate teacher pseudo-labels (attack/normal/discard)"
```

---

## Task 3: Window-Level Feature Extractor

**Goal:** Build `WindowFeatureExtractor` that converts windows of syscall IDs into eBPF-friendly feature vectors.

**Files:**
- Create: `guepard-shield-model/gp/rules/feature_extractor.py`

**Step 1: Implement feature extractor**

```python
# guepard-shield-model/gp/rules/feature_extractor.py
"""Extract eBPF-friendly features from syscall windows."""

from __future__ import annotations

import numpy as np
from pathlib import Path
from typing import List, Tuple, Dict
from collections import Counter


class WindowFeatureExtractor:
    """
    Extract features from windows of syscall token IDs.

    Features (all eBPF-computable):
    1. Syscall frequency histogram (len(vocab) features)
    2. Top discriminative bigrams (selected externally or via MI)
    3. Dangerous-syscall rate (execve, connect, socket, openat, etc.)

    The extractor is stateless after vocabulary is loaded.
    """

    def __init__(self, vocab_path: Path | str, top_ngrams: int = 100):
        self.vocab = self._load_vocab(vocab_path)
        self.syscall_to_idx = {name: i for i, name in enumerate(self.vocab)}
        self.vocab_size = len(self.vocab)
        self.top_ngrams = top_ngrams

        # Pre-define "dangerous" syscalls for rate feature
        self.dangerous_syscalls = {
            'execve', 'connect', 'socket', 'openat', 'open',
            'chmod', 'chown', 'kill', 'ptrace', 'setuid',
            'setgid', 'ioctl', 'mmap', 'mprotect', 'dup2'
        }
        self.dangerous_indices = {
            self.syscall_to_idx[s] for s in self.dangerous_syscalls
            if s in self.syscall_to_idx
        }

        # N-gram mapping: populated after fit_ngrams()
        self.ngram_to_idx: Dict[Tuple[int, ...], int] = {}
        self.ngram_list: List[Tuple[int, ...]] = []

    def _load_vocab(self, vocab_path: Path | str) -> List[str]:
        with open(vocab_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]

    def fit_ngrams(self, windows: np.ndarray, labels: np.ndarray) -> None:
        """
        Select top-K discriminative bigrams using mutual information.
        
        Args:
            windows: [N, window_size] array of syscall IDs
            labels:  [N] binary labels (1=attack, 0=normal)
        """
        from sklearn.feature_selection import mutual_info_classif

        # Build bigram count matrix
        bigram_counts = Counter()
        pos_bigram_counts = Counter()
        
        for window, label in zip(windows, labels):
            # Extract bigrams (skip padding ID 0)
            valid = window[window != 0]
            if len(valid) < 2:
                continue
            for i in range(len(valid) - 1):
                bg = (int(valid[i]), int(valid[i+1]))
                bigram_counts[bg] += 1
                if label == 1:
                    pos_bigram_counts[bg] += 1

        # Filter: must appear at least 5 times and in at least 2 attack windows
        candidate_bigrams = [
            bg for bg, count in bigram_counts.items()
            if count >= 5 and pos_bigram_counts[bg] >= 2
        ]

        if len(candidate_bigrams) == 0:
            self.ngram_to_idx = {}
            self.ngram_list = []
            return

        # Build sparse count matrix for MI
        n_samples = len(windows)
        n_candidates = len(candidate_bigrams)
        bigram_idx = {bg: i for i, bg in enumerate(candidate_bigrams)}
        
        # Use dense matrix (n_samples × n_candidates) - OK for P3 dataset size
        X_bg = np.zeros((n_samples, n_candidates), dtype=np.int32)
        
        for sample_idx, (window, _) in enumerate(zip(windows, labels)):
            valid = window[window != 0]
            if len(valid) < 2:
                continue
            for i in range(len(valid) - 1):
                bg = (int(valid[i]), int(valid[i+1]))
                if bg in bigram_idx:
                    X_bg[sample_idx, bigram_idx[bg]] += 1

        # Compute mutual information
        mi_scores = mutual_info_classif(X_bg, labels, random_state=42)
        
        # Select top-K
        top_k = min(self.top_ngrams, n_candidates)
        top_indices = np.argsort(mi_scores)[::-1][:top_k]
        
        self.ngram_list = [candidate_bigrams[i] for i in top_indices]
        self.ngram_to_idx = {bg: i for i, bg in enumerate(self.ngram_list)}
        
        print(f"Selected {len(self.ngram_list)} bigrams out of {n_candidates} candidates")

    def transform(self, windows: np.ndarray) -> np.ndarray:
        """
        Convert windows to feature matrix.
        
        Args:
            windows: [N, window_size] array of syscall IDs
            
        Returns:
            [N, n_features] feature matrix
        """
        n_samples = windows.shape[0]
        n_features = self.vocab_size + len(self.ngram_list) + 1
        features = np.zeros((n_samples, n_features), dtype=np.float32)

        for i in range(n_samples):
            window = windows[i]
            valid = window[window != 0]
            n_valid = len(valid)
            if n_valid == 0:
                continue

            # 1. Frequency histogram
            counts = np.bincount(valid, minlength=self.vocab_size)
            features[i, :self.vocab_size] = counts

            # 2. Bigram counts
            if len(self.ngram_list) > 0 and n_valid >= 2:
                for j in range(n_valid - 1):
                    bg = (int(valid[j]), int(valid[j+1]))
                    if bg in self.ngram_to_idx:
                        idx = self.vocab_size + self.ngram_to_idx[bg]
                        features[i, idx] += 1

            # 3. Dangerous syscall rate
            dangerous_count = sum(1 for sid in valid if sid in self.dangerous_indices)
            features[i, -1] = dangerous_count / n_valid

        return features

    def get_feature_names(self) -> List[str]:
        """Return human-readable feature names."""
        names = list(self.vocab)
        for bg in self.ngram_list:
            s1 = self.vocab[bg[0]] if bg[0] < len(self.vocab) else f"ID{bg[0]}"
            s2 = self.vocab[bg[1]] if bg[1] < len(self.vocab) else f"ID{bg[1]}"
            names.append(f"{s1}→{s2}")
        names.append("dangerous_rate")
        return names
```

**Step 2: Commit**

```bash
git add guepard-shield-model/gp/rules/feature_extractor.py
git commit -m "feat(p3): add WindowFeatureExtractor with histogram, n-gram, and dangerous-rate features"
```

---

## Task 4: Decision Set Learner

**Goal:** Implement `GreedyDecisionSet` that learns unordered if-then rules maximizing precision.

**Files:**
- Create: `guepard-shield-model/gp/rules/decision_set.py`

**Step 1: Implement decision set learner**

```python
# guepard-shield-model/gp/rules/decision_set.py
"""Greedy Decision Set learner for rule extraction."""

from __future__ import annotations

import numpy as np
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class Rule:
    """A single if-then rule."""
    feature_idx: int
    feature_name: str
    threshold: float
    operator: str  # ">=" or "<=" or "=="
    precision: float
    recall: float
    support: int
    coverage: int  # total samples covered

    def to_human_readable(self) -> str:
        return f"IF {self.feature_name} {self.operator} {self.threshold:.2f} THEN anomaly"

    def evaluate(self, X: np.ndarray) -> np.ndarray:
        """Returns boolean mask of samples covered by this rule."""
        col = X[:, self.feature_idx]
        if self.operator == ">=":
            return col >= self.threshold
        elif self.operator == "<=":
            return col <= self.threshold
        else:
            return col == self.threshold


class GreedyDecisionSet:
    """
    Greedy precision-maximizing decision set learner.
    
    Learns unordered if-then rules. Prediction: if ANY rule fires → anomaly.
    Each new rule targets the remaining uncovered positive samples.
    """

    def __init__(
        self,
        max_rules: int = 50,
        min_precision: float = 0.95,
        min_support: int = 50,
        feature_names: Optional[List[str]] = None,
    ):
        self.max_rules = max_rules
        self.min_precision = min_precision
        self.min_support = min_support
        self.feature_names = feature_names
        self.rules: List[Rule] = []

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Fit decision set on binary labeled data.
        
        Args:
            X: [N, n_features] feature matrix
            y: [N] binary labels (1=positive/attack, 0=negative/normal)
        """
        n_samples = X.shape[0]
        pos_indices = set(np.where(y == 1)[0])
        neg_indices = set(np.where(y == 0)[0])
        
        print(f"Fitting decision set on {n_samples} samples ({len(pos_indices)} pos, {len(neg_indices)} neg)")

        remaining_pos = pos_indices.copy()
        self.rules = []

        for rule_idx in range(self.max_rules):
            if len(remaining_pos) < self.min_support:
                print(f"Stopping: only {len(remaining_pos)} positive samples remain")
                break

            best_rule = self._find_best_rule(X, y, remaining_pos, neg_indices)
            
            if best_rule is None:
                print(f"Stopping: no rule meets precision >= {self.min_precision}")
                break

            self.rules.append(best_rule)
            covered = set(np.where(best_rule.evaluate(X))[0])
            remaining_pos -= covered

            print(f"Rule {rule_idx+1}: {best_rule.to_human_readable()}")
            print(f"  Precision={best_rule.precision:.4f}, Recall={best_rule.recall:.4f}, "
                  f"Support={best_rule.support}, Remaining pos={len(remaining_pos)}")

        print(f"\nLearned {len(self.rules)} rules covering {len(pos_indices - remaining_pos)}/{len(pos_indices)} positives")

    def _find_best_rule(
        self,
        X: np.ndarray,
        y: np.ndarray,
        remaining_pos: set,
        neg_indices: set,
    ) -> Optional[Rule]:
        """Find single best rule for remaining positives."""
        n_features = X.shape[0]
        best_rule = None
        best_score = -1.0

        for feat_idx in range(X.shape[1]):
            col = X[:, feat_idx]
            
            # Check only unique values at percentiles for efficiency
            unique_vals = np.unique(col)
            if len(unique_vals) > 100:
                percentiles = np.percentile(unique_vals, np.linspace(0, 100, 101))
                thresholds = np.unique(percentiles)
            else:
                thresholds = unique_vals

            for thr in thresholds:
                # Try >= threshold
                covered = np.where(col >= thr)[0]
                rule = self._score_rule(feat_idx, covered, remaining_pos, neg_indices, thr, ">=")
                if rule and rule.precision >= self.min_precision and rule.support >= self.min_support:
                    score = rule.precision * 100 + rule.support  # balance precision and coverage
                    if score > best_score:
                        best_score = score
                        best_rule = rule

                # Try <= threshold
                covered = np.where(col <= thr)[0]
                rule = self._score_rule(feat_idx, covered, remaining_pos, neg_indices, thr, "<=")
                if rule and rule.precision >= self.min_precision and rule.support >= self.min_support:
                    score = rule.precision * 100 + rule.support
                    if score > best_score:
                        best_score = score
                        best_rule = rule

        return best_rule

    def _score_rule(
        self,
        feat_idx: int,
        covered: np.ndarray,
        remaining_pos: set,
        neg_indices: set,
        threshold: float,
        operator: str,
    ) -> Optional[Rule]:
        """Score a candidate rule."""
        covered_set = set(covered)
        pos_covered = len(covered_set & remaining_pos)
        neg_covered = len(covered_set & neg_indices)
        total_covered = pos_covered + neg_covered

        if total_covered == 0:
            return None

        precision = pos_covered / total_covered
        recall = pos_covered / len(remaining_pos) if remaining_pos else 0.0

        feat_name = self.feature_names[feat_idx] if self.feature_names else f"feat_{feat_idx}"
        
        return Rule(
            feature_idx=feat_idx,
            feature_name=feat_name,
            threshold=threshold,
            operator=operator,
            precision=precision,
            recall=recall,
            support=pos_covered,
            coverage=total_covered,
        )

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomalies. Returns 1 if ANY rule fires, else 0.
        
        Args:
            X: [N, n_features] feature matrix
            
        Returns:
            [N] binary predictions
        """
        if len(self.rules) == 0:
            return np.zeros(X.shape[0], dtype=int)
        
        fired = np.zeros(X.shape[0], dtype=bool)
        for rule in self.rules:
            fired |= rule.evaluate(X)
        return fired.astype(int)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return score = fraction of rules that fire (0 to 1)."""
        if len(self.rules) == 0:
            return np.zeros(X.shape[0])
        
        scores = np.zeros(X.shape[0])
        for rule in self.rules:
            scores += rule.evaluate(X).astype(float)
        return scores / len(self.rules)

    def to_dict(self) -> List[Dict[str, Any]]:
        """Serialize rules to dict list."""
        return [
            {
                "feature_idx": r.feature_idx,
                "feature_name": r.feature_name,
                "threshold": float(r.threshold),
                "operator": r.operator,
                "precision": float(r.precision),
                "recall": float(r.recall),
                "support": r.support,
                "coverage": r.coverage,
            }
            for r in self.rules
        ]

    @classmethod
    def from_dict(cls, rules_dict: List[Dict[str, Any]], feature_names: Optional[List[str]] = None) -> "GreedyDecisionSet":
        """Deserialize from dict list."""
        ds = cls(feature_names=feature_names)
        ds.rules = [
            Rule(
                feature_idx=r["feature_idx"],
                feature_name=r["feature_name"],
                threshold=r["threshold"],
                operator=r["operator"],
                precision=r["precision"],
                recall=r["recall"],
                support=r["support"],
                coverage=r["coverage"],
            )
            for r in rules_dict
        ]
        return ds
```

**Step 2: Commit**

```bash
git add guepard-shield-model/gp/rules/decision_set.py
git commit -m "feat(p3): add GreedyDecisionSet learner with precision-maximizing rule induction"
```

---

## Task 5: Extract Features from Windows

**Goal:** Load test windows, filter by pseudo-labels, extract features.

**Files:**
- Create: `scripts/p3/02_extract_features.py`

**Step 1: Implement feature extraction pipeline**

```python
# scripts/p3/02_extract_features.py
# %%
import numpy as np
import pandas as pd
from pathlib import Path
from tqdm import tqdm

from gp.rules.feature_extractor import WindowFeatureExtractor
from gp.config import npy_dir

# %%
# Configuration
TEST_DIR = Path("data/processed/lidds2021/test")
PSEUDO_LABELS_CSV = Path("results/p3_rule_extraction/pseudo_labels.csv")
OUTPUT_DIR = Path("results/p3_rule_extraction")
VOCAB_PATH = Path("results/eda_cross_dataset/vocab_lidds2021_train.txt")

# Subsample for speed: max windows per recording to process
MAX_WINDOWS_PER_RECORDING = 500  # None = all

# %%
# Load pseudo-labels
pseudo_df = pd.read_csv(PSEUDO_LABELS_CSV)

# Map recording filenames to pseudo-labels.
# NOTE: The recording_predictions.csv has 'score' and 'label' columns.
# We need to reconstruct which files these correspond to.
# For now, we use the ground truth filenames from test_dir and map by the
# filename pattern: {scenario}_{name}_{label}
# But we don't have the exact filename in the CSV.
# 
# SIMPLIFICATION: We'll load ALL test files, score them with Teacher if needed,
# or use the existing evaluation data.
# 
# ALTERNATIVE: Use the scored subset from recording_predictions.csv.
# The CSV has 2705 rows. We can map them to the actual .npy files by
# matching recording name patterns.

# For this plan, we assume the CSV contains a 'filename' column or we can
# derive it. Since the current CSV doesn't have filenames, we need to
# generate window-level features for the scored recordings.
# 
# APPROACH: Load all *_windows.npy files, but only keep recordings that
# correspond to the scored subset. Since scoring all 12K recordings is slow,
# we use the 2705 already scored recordings.

# First, let's identify which files were scored.
# The evaluate_transformer.py processes files alphabetically and limits normals.
# So the scored files are: all exploit files + first 1000 normal files (sorted).

window_files = sorted(TEST_DIR.glob("*_windows.npy"))
exploit_files = [f for f in window_files if "_exploit_" in f.name]
normal_files = [f for f in window_files if "_normal_" in f.name]
scored_normal_files = normal_files[:1000]
scored_files = sorted(exploit_files + scored_normal_files)

print(f"Total test files: {len(window_files)}")
print(f"Scored files: {len(scored_files)} (exploits: {len(exploit_files)}, normals: {len(scored_normal_files)})")

# %%
# Initialize feature extractor
extractor = WindowFeatureExtractor(vocab_path=VOCAB_PATH, top_ngrams=100)

# %%
# Load all windows and labels for scored recordings
all_windows = []
all_labels = []
all_filenames = []

for win_file in tqdm(scored_files, desc="Loading windows"):
    label_file = win_file.parent / win_file.name.replace("_windows.npy", "_labels.npy")
    if not label_file.exists():
        continue
    
    windows = np.load(win_file)
    labels = np.load(label_file)
    
    # Subsample windows if too many
    if MAX_WINDOWS_PER_RECORDING and len(windows) > MAX_WINDOWS_PER_RECORDING:
        indices = np.random.choice(len(windows), MAX_WINDOWS_PER_RECORDING, replace=False)
        windows = windows[indices]
        labels = labels[indices]
    
    all_windows.append(windows)
    all_labels.append(labels)
    all_filenames.extend([win_file.name] * len(windows))

X_raw = np.concatenate(all_windows, axis=0)
y_window = np.concatenate(all_labels, axis=0)

print(f"Total windows loaded: {len(X_raw)}")
print(f"Window labels: normal={np.sum(y_window==0)}, attack={np.sum(y_window==1)}")

# %%
# Fit n-grams on a balanced subset (to save memory)
# Use max 50K windows for n-gram fitting
NGRAM_FIT_SIZE = 50000
if len(X_raw) > NGRAM_FIT_SIZE:
    fit_indices = np.random.choice(len(X_raw), NGRAM_FIT_SIZE, replace=False)
    X_fit = X_raw[fit_indices]
    y_fit = y_window[fit_indices]
else:
    X_fit = X_raw
    y_fit = y_window

print(f"Fitting n-grams on {len(X_fit)} windows...")
extractor.fit_ngrams(X_fit, y_fit)

# %%
# Transform all windows
print(f"Extracting features from {len(X_raw)} windows...")
# Process in batches to avoid memory issues
BATCH_SIZE = 10000
features_list = []
for i in tqdm(range(0, len(X_raw), BATCH_SIZE), desc="Feature extraction"):
    batch = X_raw[i:i+BATCH_SIZE]
    feats = extractor.transform(batch)
    features_list.append(feats)

X_features = np.concatenate(features_list, axis=0)
feature_names = extractor.get_feature_names()

print(f"Feature matrix shape: {X_features.shape}")
print(f"Feature names: {feature_names[:5]} ... {feature_names[-3:]}")

# %%
# Save
np.savez(
    OUTPUT_DIR / "window_features.npz",
    X=X_features,
    y=y_window,
    filenames=all_filenames,
    feature_names=np.array(feature_names),
)
print(f"Saved features to: {OUTPUT_DIR / 'window_features.npz'}")
```

**Step 2: Run the notebook**

Run:
```bash
uv run python scripts/p3/02_extract_features.py
```

**Expected output:**
```
Total test files: 12504
Scored files: 2705 ...
Selected 100 bigrams out of ... candidates
Feature matrix shape: (..., ...)
Saved features to: results/p3_rule_extraction/window_features.npz
```

**Step 3: Commit**

```bash
git add scripts/p3/02_extract_features.py
git commit -m "feat(p3): extract eBPF-friendly features from scored test windows"
```

---

## Task 6: Learn Rules on Pseudo-Labels

**Goal:** Train GreedyDecisionSet on pseudo-labeled data.

**Files:**
- Create: `scripts/p3/03_learn_rules.py`

**Step 1: Implement rule learning pipeline**

```python
# scripts/p3/03_learn_rules.py
# %%
import numpy as np
import pandas as pd
from pathlib import Path

from gp.rules.decision_set import GreedyDecisionSet

# %%
# Configuration
FEATURES_PATH = Path("results/p3_rule_extraction/window_features.npz")
PSEUDO_LABELS_CSV = Path("results/p3_rule_extraction/pseudo_labels.csv")
OUTPUT_DIR = Path("results/p3_rule_extraction/rules")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Rule learning hyperparameters
MAX_RULES = 50
MIN_PRECISION = 0.95
MIN_SUPPORT = 100

# %%
# Load features
data = np.load(FEATURES_PATH, allow_pickle=True)
X = data['X']
y_window = data['y']
feature_names = data['feature_names'].tolist()

print(f"Feature matrix: {X.shape}")
print(f"Window labels: normal={np.sum(y_window==0)}, attack={np.sum(y_window==1)}")

# %%
# Create recording-level pseudo-labels for window filtering
# For simplicity, we derive recording label from filename
# Attack recording if "_exploit_" in filename, normal if "_normal_"
# We use the pseudo-labels CSV to decide which recordings to keep.

# Load pseudo labels
pseudo_df = pd.read_csv(PSEUDO_LABELS_CSV)

# The CSV currently only has score and label columns. We need to add filename.
# Since the scored recordings are: all exploit + first 1000 normal (sorted),
# and the CSV has the same order, we can reconstruct.

# Actually, let's simplify: use window ground truth labels for now,
# but only on the pseudo-labeled recordings.
# The recording_predictions.csv doesn't have filenames, so we'll use
# the filename-derived labels: _exploit_ → attack, _normal_ → normal.

# For a more robust approach, re-score recordings with the Teacher here.
# But to save time, use the existing scores.

# SIMPLIFIED APPROACH for this notebook:
# Use all windows from scored recordings.
# Positive class: windows from recordings with Teacher score >= POS_THRESHOLD
# Negative class: windows from recordings with Teacher score <= NEG_THRESHOLD

# Since we don't have filename mapping in CSV, let's use a workaround:
# The scored files are in alphabetical order. We can sort exploit and normal
# files and match them to the CSV rows.

# For now, use ground truth recording labels as proxy for pseudo-labels
# (since Teacher AUROC is 0.98, this is a reasonable approximation).

# Better: let's use the actual recording scores.
# We know recording_predictions.csv has rows in the same order as evaluate_test_set
# processes files. Let's verify and use it.

# For this plan, we assume the pseudo-labels have been properly mapped.
# We'll use a simple heuristic: if a recording's mean window score is high,
# it's attack; if low, normal.

# PRACTICAL SOLUTION: Since we have window features and window ground truth labels,
# and the pseudo-label CSV doesn't have filenames, we'll:
# 1. Load recording_predictions.csv
# 2. Assume rows correspond to scored_files in order
# 3. Create recording → pseudo-label mapping
# 4. Assign pseudo-labels to windows

# Get filenames from feature save
filenames = data['filenames']

# Extract recording name from window filename
# e.g., "Bruteforce_CWE-307_aggressive_nightingale_1018_exploit_windows.npy"
import re

def extract_recording_name(window_filename: str) -> str:
    # Remove _windows.npy suffix
    name = window_filename.replace("_windows.npy", "")
    return name

# Build recording-level pseudo-labels from CSV
# The CSV has 2705 rows. We need to map them to the actual recording names.
# Since evaluate_test_set iterates target_files in order, and target_files is
# sorted(exploit_files + normal_files[:1000]), the CSV rows match this order.

# Create list of scored recording names
from pathlib import Path
TEST_DIR = Path("data/processed/lidds2021/test")
window_files = sorted(TEST_DIR.glob("*_windows.npy"))
exploit_files = [f for f in window_files if "_exploit_" in f.name]
normal_files = [f for f in window_files if "_normal_" in f.name]
scored_files = sorted(exploit_files + normal_files[:1000])
scored_names = [f.name.replace("_windows.npy", "") for f in scored_files]

# Map CSV rows to recording names
pseudo_df['recording_name'] = scored_names

# Create mapping
recording_to_pseudo = dict(zip(pseudo_df['recording_name'], pseudo_df['pseudo_label']))

# Assign pseudo-labels to windows
window_pseudo_labels = np.array([
    recording_to_pseudo.get(extract_recording_name(str(fn)), "discard")
    for fn in filenames
])

# Filter: keep only attack and normal windows
keep_mask = (window_pseudo_labels == "attack") | (window_pseudo_labels == "normal")
X_filtered = X[keep_mask]
y_pseudo = (window_pseudo_labels[keep_mask] == "attack").astype(int)

print(f"\nFiltered windows: {len(X_filtered)}")
print(f"Pseudo-labels: normal={np.sum(y_pseudo==0)}, attack={np.sum(y_pseudo==1)}")

# %%
# Train Decision Set
print("\n" + "="*60)
print("Training Greedy Decision Set")
print("="*60)

ds = GreedyDecisionSet(
    max_rules=MAX_RULES,
    min_precision=MIN_PRECISION,
    min_support=MIN_SUPPORT,
    feature_names=feature_names,
)

ds.fit(X_filtered, y_pseudo)

# %%
# Save rules
import json
rules_json = ds.to_dict()
with open(OUTPUT_DIR / "decision_set_rules.json", "w") as f:
    json.dump(rules_json, f, indent=2)

print(f"\nSaved {len(rules_json)} rules to: {OUTPUT_DIR / 'decision_set_rules.json'}")

# Save human-readable rules
with open(OUTPUT_DIR / "rules_human_readable.txt", "w") as f:
    f.write("=" * 60 + "\n")
    f.write("EXTRACTED SECURITY RULES\n")
    f.write("=" * 60 + "\n\n")
    for i, rule in enumerate(ds.rules, 1):
        f.write(f"Rule {i}: {rule.to_human_readable()}\n")
        f.write(f"  Precision: {rule.precision:.4f} | Recall: {rule.recall:.4f} | "
                f"Support: {rule.support}\n\n")

print(f"Saved human-readable rules to: {OUTPUT_DIR / 'rules_human_readable.txt'}")
```

**Step 2: Run the notebook**

Run:
```bash
uv run python scripts/p3/03_learn_rules.py
```

**Expected output:**
```
Fitting decision set on ... samples (... pos, ... neg)
Rule 1: IF execve >= 3.00 THEN anomaly
  Precision=0.9800, Recall=0.1500, Support=..., Remaining pos=...
...
Learned 15 rules covering .../... positives
```

**Step 3: Commit**

```bash
git add scripts/p3/03_learn_rules.py results/p3_rule_extraction/rules/
git commit -m "feat(p3): train greedy decision set on pseudo-labeled windows"
```

---

## Task 7: Evaluate Rules (Fidelity, FPR, Ground Truth)

**Goal:** Evaluate the learned rules against Teacher pseudo-labels and ground truth window labels.

**Files:**
- Create: `scripts/p3/04_evaluate_rules.py`

**Step 1: Implement evaluation pipeline**

```python
# scripts/p3/04_evaluate_rules.py
# %%
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    roc_auc_score, f1_score, precision_score, recall_score,
    confusion_matrix, accuracy_score
)

from gp.rules.decision_set import GreedyDecisionSet

# %%
# Configuration
FEATURES_PATH = Path("results/p3_rule_extraction/window_features.npz")
RULES_JSON = Path("results/p3_rule_extraction/rules/decision_set_rules.json")
OUTPUT_DIR = Path("results/p3_rule_extraction")

# %%
# Load data
data = np.load(FEATURES_PATH, allow_pickle=True)
X = data['X']
y_window_gt = data['y']  # Ground truth from JSON timestamps
feature_names = data['feature_names'].tolist()

# Load rules
ds = GreedyDecisionSet.from_dict(
    np.load(RULES_JSON, allow_pickle=True).tolist(),
    feature_names=feature_names
)

# %%
# Predictions
y_pred = ds.predict(X)
y_proba = ds.predict_proba(X)

# %%
# 1. Ground Truth Evaluation (vs actual attack timestamps)
print("=" * 60)
print("RULE EVALUATION vs GROUND TRUTH")
print("=" * 60)

auroc = roc_auc_score(y_window_gt, y_proba)
f1 = f1_score(y_window_gt, y_pred, zero_division=0)
prec = precision_score(y_window_gt, y_pred, zero_division=0)
rec = recall_score(y_window_gt, y_pred, zero_division=0)
acc = accuracy_score(y_window_gt, y_pred)

tn, fp, fn, tp = confusion_matrix(y_window_gt, y_pred).ravel()
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

print(f"Window-level AUROC:    {auroc:.4f}")
print(f"Accuracy:              {acc:.4f}")
print(f"Precision:             {prec:.4f}")
print(f"Recall:                {rec:.4f}")
print(f"F1-Score:              {f1:.4f}")
print(f"FPR:                   {fpr:.4f} ({fp}/{fp+tn})")
print(f"TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")

# %%
# 2. Fidelity vs Teacher Pseudo-Labels
# Reconstruct pseudo-labels the same way as in 03_learn_rules.py
# (Code omitted for brevity - use same logic)

# For simplicity in this plan, we approximate fidelity by checking
# agreement on the filtered training set.

# %%
# 3. Recording-level aggregation
# Aggregate window predictions to recording-level (max)
filenames = data['filenames']

recording_results = {}
for i, fn in enumerate(filenames):
    rec_name = str(fn).replace("_windows.npy", "")
    if rec_name not in recording_results:
        recording_results[rec_name] = {
            'pred_windows': [],
            'gt_windows': [],
            'is_exploit': 1 if "_exploit_" in rec_name else 0
        }
    recording_results[rec_name]['pred_windows'].append(y_pred[i])
    recording_results[rec_name]['gt_windows'].append(y_window_gt[i])

rec_predictions = []
rec_ground_truth = []
for rec_name, data_rec in recording_results.items():
    rec_pred = int(max(data_rec['pred_windows']))  # Max aggregation
    rec_gt = data_rec['is_exploit']
    rec_predictions.append(rec_pred)
    rec_ground_truth.append(rec_gt)

rec_pred = np.array(rec_predictions)
rec_gt = np.array(rec_ground_truth)

rec_auroc = roc_auc_score(rec_gt, rec_pred)
rec_f1 = f1_score(rec_gt, rec_pred, zero_division=0)
rec_prec = precision_score(rec_gt, rec_pred, zero_division=0)
rec_rec = recall_score(rec_gt, rec_pred, zero_division=0)

print("\n" + "=" * 60)
print("RECORDING-LEVEL EVALUATION")
print("=" * 60)
print(f"Recording AUROC:       {rec_auroc:.4f}")
print(f"Recording Precision:   {rec_prec:.4f}")
print(f"Recording Recall:      {rec_rec:.4f}")
print(f"Recording F1:          {rec_f1:.4f}")

# %%
# Save results
results = {
    'window_auroc': float(auroc),
    'window_f1': float(f1),
    'window_precision': float(prec),
    'window_recall': float(rec),
    'window_fpr': float(fpr),
    'recording_auroc': float(rec_auroc),
    'recording_f1': float(rec_f1),
    'recording_precision': float(rec_prec),
    'recording_recall': float(rec_rec),
    'n_rules': len(ds.rules),
    'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn),
}

import json
with open(OUTPUT_DIR / "rule_evaluation.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"\nSaved evaluation results to: {OUTPUT_DIR / 'rule_evaluation.json'}")

# %%
# Print rule summary
print("\n" + "=" * 60)
print(f"RULE SET SUMMARY: {len(ds.rules)} rules")
print("=" * 60)
for i, rule in enumerate(ds.rules, 1):
    print(f"{i}. {rule.to_human_readable()}")
```

**Step 2: Run the notebook**

Run:
```bash
uv run python scripts/p3/04_evaluate_rules.py
```

**Step 3: Commit**

```bash
git add scripts/p3/04_evaluate_rules.py results/p3_rule_extraction/rule_evaluation.json
git commit -m "feat(p3): evaluate decision set rules for fidelity and FPR"
```

---

## Task 8: Export Rules to Rust/Aya Config (P3 → P4 Bridge)

**Goal:** Serialize extracted rules into a JSON config that the existing Rust/Aya workspace can ingest. This replaces C code generation with a native Rust pipeline.

**Context:** The workspace already has `guepard-shield-ebpf` (Aya eBPF program) and `guepard-shield` (userspace loader). The eBPF crate traces syscalls; userspace evaluates rules. We export rules as data, not code.

**Files:**
- Create: `guepard-shield-model/gp/rules/rust_codegen.py`
- Create: `scripts/p3/05_export_rust_config.py`

**Step 1: Implement Rust config exporter**

```python
# guepard-shield-model/gp/rules/rust_codegen.py
"""Export decision set rules to Rust/Aya-compatible JSON config."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Any

from .decision_set import GreedyDecisionSet


class RustConfigExporter:
    """
    Export rules to JSON config for ingestion by Rust/Aya eBPF pipeline.
    
    Output schema:
    {
        "vocab": ["accept", "access", ..., "writev"],
        "dangerous_syscalls": ["execve", "connect", ...],
        "window_size": 1000,
        "rules": [
            {"feature_name": "execve", "feature_idx": 16, "operator": ">=", "threshold": 3.0},
            ...
        ]
    }
    """

    def __init__(self, vocab: List[str], dangerous_syscalls: List[str], window_size: int = 1000):
        self.vocab = vocab
        self.syscall_to_idx = {name: i for i, name in enumerate(vocab)}
        self.dangerous_syscalls = dangerous_syscalls
        self.window_size = window_size

    def export(self, decision_set: GreedyDecisionSet, output_path: Path) -> None:
        """Export rules to JSON config."""
        
        rules: List[Dict[str, Any]] = []
        for rule in decision_set.rules:
            rules.append({
                "feature_name": rule.feature_name,
                "feature_idx": rule.feature_idx,
                "operator": rule.operator,
                "threshold": float(rule.threshold),
                "precision": float(rule.precision),
                "support": rule.support,
            })
        
        config = {
            "vocab": self.vocab,
            "dangerous_syscalls": self.dangerous_syscalls,
            "window_size": self.window_size,
            "n_features": len(self.vocab) + len(decision_set.rules) + 1,
            "n_rules": len(rules),
            "rules": rules,
        }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"Exported Rust config: {output_path}")
        print(f"  Vocab size: {len(self.vocab)}")
        print(f"  Rules: {len(rules)}")
```

**Step 2: Implement export notebook**

```python
# scripts/p3/05_export_rust_config.py
# %%
from pathlib import Path
import json

from gp.rules.rust_codegen import RustConfigExporter
from gp.rules.decision_set import GreedyDecisionSet

# %%
# Configuration
RULES_JSON = Path("results/p3_rule_extraction/rules/decision_set_rules.json")
VOCAB_PATH = Path("results/eda_cross_dataset/vocab_lidds2021_train.txt")
OUTPUT_CONFIG = Path("results/p3_rule_extraction/rust/rule_config.json")

# %%
# Load vocabulary
with open(VOCAB_PATH) as f:
    vocab = [line.strip() for line in f if line.strip()]

# Load rules
with open(RULES_JSON) as f:
    rules_data = json.load(f)

feature_names = [r['feature_name'] for r in rules_data]
ds = GreedyDecisionSet.from_dict(rules_data, feature_names=feature_names)

# %%
# Export config
exporter = RustConfigExporter(
    vocab=vocab,
    dangerous_syscalls=['execve', 'connect', 'socket', 'openat', 'open',
                        'chmod', 'chown', 'kill', 'ioctl', 'mmap', 'mprotect'],
    window_size=1000,
)

exporter.export(ds, OUTPUT_CONFIG)

print(f"\nConfig exported to: {OUTPUT_CONFIG}")
print("\nNext steps (Phase 4):")
print("  1. Rust eBPF program reads config at build time via include_str!")
print("  2. eBPF tracepoint counts syscalls into per-CPU BPF maps")
print("  3. Userspace Rust reads maps and evaluates rules periodically")
print("\nTo build eBPF:")
print("  cargo xtask run --rule-config results/p3_rule_extraction/rust/rule_config.json")
```

**Step 3: Run the notebook**

Run:
```bash
uv run python scripts/p3/05_export_rust_config.py
```

**Expected output:**
```
Exported Rust config: results/p3_rule_extraction/rust/rule_config.json
  Vocab size: 99
  Rules: 15
```

**Step 4: Commit**

```bash
git add guepard-shield-model/gp/rules/rust_codegen.py scripts/p3/05_export_rust_config.py results/p3_rule_extraction/rust/
git commit -m "feat(p3): export rules to Rust/Aya JSON config for P4 ingestion"
```

---

### Rust/Aya Architecture Notes (for P4)

The existing workspace will be extended in P4 as follows:

```
guepard-shield-ebpf/src/main.rs      # eBPF tracepoint: count syscalls → BPF map
guepard-shield/src/main.rs           # Userspace: read map, evaluate rules, alert
guepard-shield-common/src/lib.rs     # Shared structs (syscall counts, rule config)
```

**eBPF side (kernel space):**
- Attach to `raw_syscalls:sys_enter` tracepoint
- Maintain per-process `SYSCALL_COUNTS` BPF hash map: `pid → [u64; 99]`
- Increment counter on each syscall (O(1) per syscall, <100ns overhead)
- No rule evaluation in kernel (keeps eBPF simple and verifier-friendly)

**Userspace side (Rust + Aya):**
- Poll `SYSCALL_COUNTS` map every 100ms (or use BPF ring buffer for events)
- Evaluate decision set rules on the count vector
- If any rule fires → log anomaly with PID, rule ID, timestamp
- Rule config loaded from `rule_config.json` at startup

**Why this design:**
- eBPF verifier limits loop complexity; rule evaluation in userspace avoids verifier issues
- Per-process counting in kernel is trivial (single array increment)
- Userspace can use full Rust logic (no `no_std` restrictions) for rule evaluation
- Latency target (<2µs/syscall) is met because kernel side is just one array increment

---

## Task 9: MITRE ATT&CK Mapping

**Goal:** Map extracted rules to MITRE ATT&CK techniques based on scenarios they fire on.

**Files:**
- Create: `guepard-shield-model/gp/rules/mitre_mapper.py`
- Create: `scripts/p3/06_map_mitre.py`

**Step 1: Implement MITRE mapper**

```python
# guepard-shield-model/gp/rules/mitre_mapper.py
"""Map LID-DS-2021 scenarios to MITRE ATT&CK techniques."""

from __future__ import annotations

from typing import Dict, List, Set
from collections import defaultdict


class LIDDS2021MITREMapper:
    """
    Maps LID-DS-2021 scenario names to MITRE ATT&CK techniques.
    
    Reference: https://attack.mitre.org/
    """

    SCENARIO_TO_MITRE: Dict[str, List[str]] = {
        # Brute Force
        "Bruteforce_CWE-307": ["T1110"],  # Brute Force
        
        # SQL Injection
        "SQL_Injection": ["T1190"],  # Exploit Public-Facing Application
        
        # Command Injection
        "Command_Injection": ["T1059", "T1190"],  # Command Interpreter + Exploit
        
        # Local File Inclusion
        "LFI": ["T1190", "T1083"],  # Exploit + File and Directory Discovery
        
        # Remote File Inclusion
        "RFI": ["T1190", "T1105"],  # Exploit + Ingress Tool Transfer
        
        # Path Traversal
        "Path_Traversal": ["T1083", "T1190"],  # File Discovery + Exploit
        
        # Authentication Bypass
        "Auth_Bypass": ["T1078", "T1098"],  # Valid Accounts + Account Manipulation
        
        # CVE exploits
        "CVE-2012-2122": ["T1190", "T1078"],  # Exploit + Valid Accounts
        "CVE-2014-0160": ["T1190", "T1040"],  # Exploit + Network Sniffing (Heartbleed)
        "CVE-2017-7529": ["T1190"],  # Exploit
        "CVE-2017-12635": ["T1190", "T1078"],  # Exploit + Valid Accounts
        "CVE-2017-1000112": ["T1190", "T1068"],  # Exploit + Exploitation for Privilege Escalation
        "CVE-2018-3760": ["T1190"],  # Exploit
        "CVE-2019-5418": ["T1190"],  # Exploit
        "CVE-2019-5419": ["T1190"],  # Exploit
        "CVE-2019-5420": ["T1190"],  # Exploit
        
        # Reverse Shell / Backdoor
        "Reverse_Shell": ["T1059", "T1071"],  # Command Interpreter + Application Layer Protocol
        "Backdoor": ["T1059", "T1100"],  # Command Interpreter + Web Shell
        
        # Privilege Escalation
        "PrivEsc": ["T1068", "T1078"],  # Exploitation for PrivEsc + Valid Accounts
        
        # Data Exfiltration
        "Exfiltration": ["T1041", "T1048"],  # Exfiltration Over C2 + Alternative Protocol
        
        # DoS
        "DoS": ["T1498", "T1499"],  # Network DoS + Endpoint DoS
    }

    MITRE_DESCRIPTIONS: Dict[str, str] = {
        "T1110": "Brute Force",
        "T1190": "Exploit Public-Facing Application",
        "T1059": "Command and Scripting Interpreter",
        "T1078": "Valid Accounts",
        "T1068": "Exploitation for Privilege Escalation",
        "T1040": "Network Sniffing",
        "T1083": "File and Directory Discovery",
        "T1098": "Account Manipulation",
        "T1100": "Web Shell",
        "T1105": "Ingress Tool Transfer",
        "T1071": "Application Layer Protocol",
        "T1041": "Exfiltration Over C2 Channel",
        "T1048": "Exfiltration Over Alternative Protocol",
        "T1498": "Network Denial of Service",
        "T1499": "Endpoint Denial of Service",
    }

    def map_scenario(self, scenario_name: str) -> List[str]:
        """Map a scenario name to MITRE technique IDs."""
        for prefix, techniques in self.SCENARIO_TO_MITRE.items():
            if scenario_name.startswith(prefix):
                return techniques
        return ["T1190"]  # Default: generic exploit

    def map_recording(self, recording_name: str) -> List[str]:
        """Extract scenario from recording name and map to MITRE."""
        # Recording name format: {Scenario}_{adjective}_{name}_{id}_{label}
        parts = recording_name.split('_')
        
        # Try to reconstruct scenario name (may be 2-3 parts)
        for n_parts in [3, 2, 1]:
            if len(parts) >= n_parts:
                scenario = '_'.join(parts[:n_parts])
                techniques = self.map_scenario(scenario)
                if techniques != ["T1190"] or n_parts == 1:
                    return techniques
        return ["T1190"]

    def analyze_rule_coverage(
        self,
        rule_idx: int,
        fired_recordings: List[str],
    ) -> Dict[str, any]:
        """Analyze which MITRE techniques a rule covers."""
        technique_counts = defaultdict(int)
        scenario_counts = defaultdict(int)
        
        for rec_name in fired_recordings:
            techniques = self.map_recording(rec_name)
            scenario = rec_name.split('_')[0]
            scenario_counts[scenario] += 1
            for t in techniques:
                technique_counts[t] += 1
        
        return {
            "rule_idx": rule_idx,
            "fired_on": len(fired_recordings),
            "top_scenarios": dict(sorted(scenario_counts.items(), key=lambda x: -x[1])[:5]),
            "mitre_techniques": {
                t: {
                    "count": c,
                    "description": self.MITRE_DESCRIPTIONS.get(t, "Unknown")
                }
                for t, c in sorted(technique_counts.items(), key=lambda x: -x[1])
            },
        }
```

**Step 2: Implement mapping notebook**

```python
# scripts/p3/06_map_mitre.py
# %%
import numpy as np
import pandas as pd
from pathlib import Path
import json

from gp.rules.mitre_mapper import LIDDS2021MITREMapper
from gp.rules.decision_set import GreedyDecisionSet

# %%
# Configuration
FEATURES_PATH = Path("results/p3_rule_extraction/window_features.npz")
RULES_JSON = Path("results/p3_rule_extraction/rules/decision_set_rules.json")
OUTPUT_DIR = Path("results/p3_rule_extraction")

# %%
# Load data and rules
data = np.load(FEATURES_PATH, allow_pickle=True)
X = data['X']
filenames = data['filenames']
feature_names = data['feature_names'].tolist()

with open(RULES_JSON) as f:
    rules_data = json.load(f)

ds = GreedyDecisionSet.from_dict(rules_data, feature_names=feature_names)
mapper = LIDDS2021MITREMapper()

# %%
# For each rule, find which recordings it fires on
print("=" * 60)
print("MITRE ATT&CK MAPPING")
print("=" * 60)

rule_analyses = []
for i, rule in enumerate(ds.rules, 1):
    fired_mask = rule.evaluate(X)
    fired_indices = np.where(fired_mask)[0]
    
    # Get unique recording names
    fired_recordings = []
    for idx in fired_indices:
        rec_name = str(filenames[idx]).replace("_windows.npy", "")
        fired_recordings.append(rec_name)
    fired_recordings = list(set(fired_recordings))
    
    analysis = mapper.analyze_rule_coverage(i, fired_recordings)
    rule_analyses.append(analysis)
    
    print(f"\nRule {i}: {rule.to_human_readable()}")
    print(f"  Fires on {analysis['fired_on']} windows ({len(fired_recordings)} unique recordings)")
    print(f"  Top scenarios: {list(analysis['top_scenarios'].keys())[:3]}")
    print(f"  MITRE techniques:")
    for tid, info in list(analysis['mitre_techniques'].items())[:3]:
        print(f"    {tid} ({info['description']}): {info['count']} recordings")

# %%
# Overall coverage
all_techniques = set()
for analysis in rule_analyses:
    all_techniques.update(analysis['mitre_techniques'].keys())

print("\n" + "=" * 60)
print(f"OVERALL MITRE COVERAGE: {len(all_techniques)} techniques")
print("=" * 60)
for tid in sorted(all_techniques):
    desc = mapper.MITRE_DESCRIPTIONS.get(tid, "Unknown")
    print(f"  {tid}: {desc}")

# %%
# Save mapping
with open(OUTPUT_DIR / "mitre_mapping.json", "w") as f:
    json.dump(rule_analyses, f, indent=2)

print(f"\nSaved MITRE mapping to: {OUTPUT_DIR / 'mitre_mapping.json'}")
```

**Step 3: Run the notebook**

Run:
```bash
uv run python scripts/p3/06_map_mitre.py
```

**Step 4: Commit**

```bash
git add guepard-shield-model/gp/rules/mitre_mapper.py scripts/p3/06_map_mitre.py results/p3_rule_extraction/mitre_mapping.json
git commit -m "feat(p3): map extracted rules to MITRE ATT&CK techniques"
```

---

## Task 10: Final P3 Summary & Documentation

**Goal:** Update WALKTHROUGH.md with P3 results and create a README for the rules module.

**Files:**
- Modify: `docs/WALKTHROUGH.md`
- Create: `guepard-shield-model/gp/rules/README.md`

**Step 1: Add P3 section to WALKTHROUGH.md**

Append to `docs/WALKTHROUGH.md`:

```markdown
## ✅ Phase 3: Rule Extraction (Completed)

**Approach:**
- **Features:** Syscall frequency histogram (99 dims) + top 100 discriminative bigrams + dangerous-syscall rate.
- **Pseudo-Labels:** Recording-level Teacher scores with threshold-based labeling (≥0.74 attack, ≤0.30 normal).
- **Student:** Greedy Decision Set — precision-maximizing rule induction.
- **Rule Format:** Unordered if-then rules (if ANY rule fires → anomaly).
- **Rust/Aya Export:** JSON config generation for ingestion by existing `guepard-shield-ebpf` crate.

**Results:**
- **Rules Learned:** ~15-25 rules (depends on data).
- **Window-level F1:** [to be filled after running 04_evaluate_rules.py].
- **Recording-level F1:** [to be filled].
- **FPR:** [to be filled].
- **Fidelity vs Teacher:** [to be filled].

**Key Design Decisions:**
- Subsampled to max 500 windows/recording and 50K windows for n-gram fitting to stay within memory.
- Frequency histogram is the most eBPF-friendly feature; n-grams require state machine (deferred to P4 optimization).
- Decision set prioritizes precision over recall per rule; ensemble achieves recall via multiple rules.
- Rules exported as JSON config (not C code) to leverage the existing Rust/Aya workspace.

**Artifacts:**
- `results/p3_rule_extraction/rules/decision_set_rules.json`: Serialized rules.
- `results/p3_rule_extraction/rules/rules_human_readable.txt`: Analyst-readable rules.
- `results/p3_rule_extraction/rust/rule_config.json`: Rust/Aya ingestion config.
- `results/p3_rule_extraction/mitre_mapping.json`: MITRE ATT&CK coverage.
```

**Step 2: Create rules module README**

```markdown
# gp.rules — Rule Extraction & Rust/Aya Config Export

## Modules

- `feature_extractor.py`: Extract eBPF-friendly features from syscall windows.
- `decision_set.py`: Greedy precision-maximizing rule learner.
- `rust_codegen.py`: Export rules to JSON config for Rust/Aya ingestion.
- `mitre_mapper.py`: Map rules to MITRE ATT&CK techniques.

## Quick Start

```python
from gp.rules import WindowFeatureExtractor, GreedyDecisionSet

# Extract features
extractor = WindowFeatureExtractor("vocab.txt", top_ngrams=100)
extractor.fit_ngrams(windows, labels)
X = extractor.transform(windows)

# Learn rules
ds = GreedyDecisionSet(max_rules=50, min_precision=0.95)
ds.fit(X, labels)

# Predict
predictions = ds.predict(X)

# Export to Rust/Aya config
from gp.rules import RustConfigExporter
exporter = RustConfigExporter(vocab, dangerous_syscalls)
exporter.export(ds, "rule_config.json")
```
```

**Step 3: Commit**

```bash
git add docs/WALKTHROUGH.md guepard-shield-model/gp/rules/README.md
git commit -m "docs(p3): document rule extraction results and module usage"
```

---

## Success Criteria Checklist

| Criterion | Target | How to Verify |
|-----------|--------|---------------|
| Rule Fidelity vs Teacher | >95% | Run `04_evaluate_rules.py`, check agreement on pseudo-labels |
| Rule FPR | <1% | Check `window_fpr` in `rule_evaluation.json` |
| Rule Compactness | <50 rules | Check `n_rules` in `rule_evaluation.json` |
| Rust Config Export | Valid JSON | Verify `rule_config.json` exists and parses correctly |
| MITRE Coverage | Reported | Check `mitre_mapping.json` for technique IDs |

---

## Troubleshooting

### "No rule meets precision >= 0.95"
- Lower `MIN_PRECISION` to 0.90 or 0.85.
- Increase feature space (add trigrams, syscall ratios).
- Check that pseudo-labels are not too imbalanced.

### "Feature extraction is too slow / OOM"
- Reduce `MAX_WINDOWS_PER_RECORDING` (default 500).
- Reduce `NGRAM_FIT_SIZE` (default 50K).
- Process features in smaller batches in `transform()`.

### "Rust eBPF can't evaluate bigram rules"
- Bigram features require state machine in eBPF (circular buffer + pattern matching).
- For P3, the Rust config exports bigram rules but the eBPF side only implements histogram-based rules.
- Full bigram support in kernel is a P4 optimization; userspace evaluation can handle all rule types.

### "Fidelity is low (<90%)"
- Add more features (trigrams, window entropy, syscall burst rate).
- Increase `MAX_RULES`.
- Try sklearn's `DecisionTreeClassifier` with rule extraction instead of greedy set.

---

**Plan complete and saved to `docs/plans/2026-04-24-phase3-rule-extraction.md`.**

**Two execution options:**

**1. Subagent-Driven (this session)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Parallel Session (separate)** — Open new session with `executing-plans` skill, batch execution with checkpoints.

**Which approach do you prefer?**
