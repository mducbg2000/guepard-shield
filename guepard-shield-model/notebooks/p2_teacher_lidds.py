# ---
# jupyter:
#   jupytext:
#     formats: py:percent
# ---

# %% [markdown]
# # P2 — LID-DS Teacher Training & Temperature Sweep
#
# **Goal:** Train BiLSTM and Transformer teachers on LID-DS-2021 (5 in-dist
# scenarios), pick the winner, then sweep temperature for optimal distillation.
#
# **Hardware target:** 32 GB RAM, RTX 3060 6 GB VRAM.
#
# **Outputs → `results/p2/`:**
# - `best_teacher_lidds.ckpt` — winner checkpoint
# - `teacher_comparison.json` — BiLSTM vs Transformer metrics
# - `temperature_sweep.json` — T → Attack Fidelity mapping
# - `p2_checkpoint.json` — pass/fail for 3 checkpoint criteria

# %% [markdown]
# ## 1. Setup

# %%
import datetime
import json
import random
import shutil
import warnings
from pathlib import Path

import lightning as L
import matplotlib.pyplot as plt
import numpy as np
import torch
from guepard.config import TeacherConfig, WindowConfig
from guepard.data_loader.datamodule import TeacherDataModule
from guepard.data_loader.lidds_corpus import LiddsCorpus, read_sc_tokens
from guepard.data_loader.phase_segmenter import (
    phase_summary,
    read_sc_timestamps,
    segment_phases,
)
from guepard.data_loader.teacher_dataset import TeacherDataset
from guepard.data_loader.vocab import SyscallVocab
from guepard.data_loader.windowing import num_sliding_windows
from guepard.features.vectorizer import SyscallVectorizer
from guepard.models.teacher import SyscallLSTM, SyscallTransformer
from guepard.training.teacher_module import TeacherLightningModule
from lightning.pytorch.callbacks import (
    EarlyStopping,
    LearningRateMonitor,
    ModelCheckpoint,
)
from scipy.optimize import minimize_scalar
from sklearn.tree import DecisionTreeClassifier
from torch.utils.data import DataLoader

warnings.filterwarnings("ignore", message=".*LeafSpec.*deprecated.*")
torch.set_float32_matmul_precision("medium")

SEED = 42
L.seed_everything(SEED, workers=True)

print(f"PyTorch {torch.__version__}  |  CUDA: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    print(f"  GPU: {torch.cuda.get_device_name(0)}")
    print(f"  VRAM: {torch.cuda.get_device_properties(0).total_mem / 1e9:.1f} GB")

# %% [markdown]
# ## 2. Configuration

# %%
# --- Paths ---
DATA_DIR = Path("../data/processed/LID-DS-2021")
OUTPUT_DIR = Path("../results/p2")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# --- Scenarios (from experiments design §3) ---
IN_DIST_SCENARIOS = [
    "CVE-2014-0160",  # Heartbleed
    "CVE-2017-7529",  # Nginx OOB read
    "CWE-89-SQL-injection",  # SQL Injection
    "Bruteforce_CWE-307",  # Brute force auth
    "EPS_CWE-434",  # Unrestricted file upload
]

# --- Hyperparameters ---
WINDOW_SIZE = 64
STRIDE = 12
MAX_WINDOWS_PER_SEQ = 10  # cap windows per recording for class balance
BATCH_SIZE = 1024
MAX_EPOCHS = 50
PATIENCE = 10
NUM_WORKERS = 4  # 4 workers × ~2 GB peak each ≈ 8 GB RAM headroom
VECTORIZER_MAX_FEATURES = 1000
NGRAM_RANGE = (1, 2)

# Temperature sweep values (from research proposal §10)
T_SWEEP = [1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0]

# Mixed precision: bf16 on Ampere+, fp16 on older GPUs, 32 if no GPU
if torch.cuda.is_available():
    if torch.cuda.get_device_capability()[0] >= 8:
        PRECISION = "bf16-mixed"
    else:
        PRECISION = "16-mixed"
else:
    PRECISION = "32-true"

print(f"Precision: {PRECISION}")

# %% [markdown]
# ## 3. Load LID-DS Corpus & Create Supervised Splits

# %%
print("Indexing LID-DS-2021 (5 in-dist scenarios)...")
corpus = LiddsCorpus(DATA_DIR, scenarios=IN_DIST_SCENARIOS)

print(f"Total recordings: {len(corpus.metadata)}")
for scenario in IN_DIST_SCENARIOS:
    metas = [m for m in corpus.metadata if m.scenario == scenario]
    n_attack = sum(1 for m in metas if m.label == 1)
    print(f"  {scenario}: {len(metas)} recordings ({n_attack} attack)")

# %%
# Create supervised splits: need both normal and attack in train/val
# Strategy:
#   - training/ (normal)    → train_normal
#   - validation/ (normal)  → val_normal
#   - test/normal/          → test_normal
#   - test/normal_and_attack/ with exploit=True  → split 60/20/20 into train/val/test
#   - test/normal_and_attack/ with exploit=False → test_normal_extra

train_normal = corpus.get_split("training")
val_normal = corpus.get_split("validation")
test_normal = corpus.get_split("test_normal")
test_mixed = corpus.get_split("test_attack")

attack_recs = [m for m in test_mixed if m.label == 1]
normal_from_mixed = [m for m in test_mixed if m.label == 0]

rng = random.Random(SEED)
rng.shuffle(attack_recs)
n_attack = len(attack_recs)
train_attack = attack_recs[: int(0.6 * n_attack)]
val_attack = attack_recs[int(0.6 * n_attack) : int(0.8 * n_attack)]
test_attack = attack_recs[int(0.8 * n_attack) :]

# Assign custom split names for DataModule
train_metas = train_normal + train_attack
val_metas = val_normal + val_attack
test_metas = test_normal + normal_from_mixed + test_attack

for m in train_metas:
    m.seq_class = "p2_train"
for m in val_metas:
    m.seq_class = "p2_val"
for m in test_metas:
    m.seq_class = "p2_test"

corpus.metadata = train_metas + val_metas + test_metas

print("\nSupervised splits:")
for name, metas in [("Train", train_metas), ("Val", val_metas), ("Test", test_metas)]:
    n_norm = sum(1 for m in metas if m.label == 0)
    n_atk = sum(1 for m in metas if m.label == 1)
    print(f"  {name:5s}: {len(metas):5d} recordings  (normal={n_norm}, attack={n_atk})")

# %% [markdown]
# ## 4. Data Diagnostics

# %%
print("\n=== DATA DIAGNOSTICS ===")

window_config = WindowConfig(window_size=WINDOW_SIZE, stride=STRIDE)

for split_name, metas in [("Train", train_metas), ("Val", val_metas)]:
    win_counts = {0: 0, 1: 0}
    for m in metas:
        n_win = num_sliding_windows(m.seq_length, window_config)
        capped = min(n_win, MAX_WINDOWS_PER_SEQ) if MAX_WINDOWS_PER_SEQ else n_win
        win_counts[m.label] += capped
    ratio = win_counts[1] / max(win_counts[0], 1)
    print(
        f"{split_name} windows (capped={MAX_WINDOWS_PER_SEQ}): "
        f"normal={win_counts[0]:,}, attack={win_counts[1]:,}, ratio={ratio:.2f}"
    )

# Sequence length distribution
fig, axes = plt.subplots(1, 2, figsize=(12, 4))
for ax, metas, title in [(axes[0], train_metas, "Train"), (axes[1], val_metas, "Val")]:
    normal_lens = [m.seq_length for m in metas if m.label == 0]
    attack_lens = [m.seq_length for m in metas if m.label == 1]
    ax.boxplot(
        [normal_lens, attack_lens],
        tick_labels=["Normal", "Attack"],
        showfliers=False,
    )
    ax.set_title(f"{title}: Sequence Length by Class")
    ax.set_ylabel("# exit events")
plt.tight_layout()
plt.savefig(OUTPUT_DIR / "diag_seq_lengths.png", dpi=120)
plt.show()

# %% [markdown]
# ## 5. Build Vocab & Vectorizer

# %%
print("Building vocab (streaming, no full materialisation)...")
vocab = SyscallVocab()

# Stream tokens from train split only (avoid test leakage)
train_seqs = list(corpus.iter_sequences("p2_train"))
n_train = len(train_seqs)
vocab.build((tokens for _, _, tokens in train_seqs), total=n_train)
print(f"Vocab size: {len(vocab)}")
vocab.save(OUTPUT_DIR / "vocab.json")

print("Fitting n-gram vectorizer...")
vectorizer = SyscallVectorizer(
    max_features=VECTORIZER_MAX_FEATURES, ngram_range=NGRAM_RANGE
)
vectorizer.fit((tokens for _, _, tokens in train_seqs), total=n_train)
print(f"Vectorizer features: {len(vectorizer.get_feature_names())}")

# Free memory
del train_seqs

# %% [markdown]
# ## 6. Phase Segmentation (sample analysis)

# %%
# Run phase segmenter on a sample of recordings to validate the algorithm
# (full per-recording phase labels are computed on-demand in P3 C6)

print("Phase segmentation — sample of 20 recordings...")
phase_stats: dict[str, list[dict]] = {"normal": [], "attack": []}

sample_metas = random.Random(SEED).sample(
    [m for m in train_metas if m.seq_length > 100], min(20, len(train_metas))
)

for meta in sample_metas:
    timestamps = read_sc_timestamps(meta.file_path)
    if len(timestamps) < 10:
        continue
    labels = segment_phases(timestamps)
    summary = phase_summary(labels)
    key = "attack" if meta.label == 1 else "normal"
    phase_stats[key].append(summary)

for cls, stats in phase_stats.items():
    if not stats:
        continue
    print(f"\n  {cls.upper()} recordings (n={len(stats)}):")
    for phase in ["startup", "active", "idle", "shutdown"]:
        vals = [s.get(phase, 0) for s in stats]
        print(f"    {phase:10s}: mean={np.mean(vals):8.1f}  std={np.std(vals):8.1f}")

# %% [markdown]
# ## 7. Create DataModule

# %%
print("Creating DataModule...")
datamodule = TeacherDataModule(
    corpus=corpus,
    vocab=vocab,
    window_config=window_config,
    train_split="p2_train",
    val_split="p2_val",
    batch_size=BATCH_SIZE,
    max_windows_per_seq=MAX_WINDOWS_PER_SEQ,
    seed=SEED,
    token_reader=read_sc_tokens,
    num_workers=NUM_WORKERS,
)

print(
    f"Train windows: {len(datamodule.train_dataset):,}  |  "
    f"Val windows: {len(datamodule.val_dataset):,}"
)

# %% [markdown]
# ## 8. Architecture Comparison — BiLSTM vs Transformer
#
# Train both on the same data, compare val F1 → pick winner as Teacher.


# %%
class DatasetReshuffleCallback(L.Callback):
    """Rebuilds sequence-level shuffle order after each training epoch."""

    def __init__(self, dm: TeacherDataModule):
        self._dm = dm

    def on_train_epoch_end(self, trainer, pl_module):
        if self._dm.train_dataset is not None:
            self._dm.train_dataset.reshuffle()


class MetricsHistory(L.Callback):
    """Collects per-epoch metrics for plotting."""

    def __init__(self):
        self.history: dict[str, list[float]] = {
            "train_loss": [],
            "val_loss": [],
            "val_accuracy": [],
            "val_f1": [],
        }

    def on_train_epoch_end(self, trainer, pl_module):
        self.history["train_loss"].append(
            float(trainer.callback_metrics.get("train_loss_epoch", 0))
        )

    def on_validation_epoch_end(self, trainer, pl_module):
        self.history["val_loss"].append(
            float(trainer.callback_metrics.get("val_loss", 0))
        )
        self.history["val_accuracy"].append(
            float(trainer.callback_metrics.get("val_accuracy", 0))
        )
        self.history["val_f1"].append(float(trainer.callback_metrics.get("val_f1", 0)))


def train_teacher(
    model_cls,
    model_kwargs: dict,
    config: TeacherConfig,
    tag: str,
) -> tuple[TeacherLightningModule, MetricsHistory]:
    """Train a teacher model and return the module + history."""
    model = model_cls(**model_kwargs)
    module = TeacherLightningModule(model, config)
    history = MetricsHistory()
    model_checkpoint = ModelCheckpoint(
        dirpath=str(OUTPUT_DIR),
        filename=f"teacher_{tag}",
        monitor="val_f1",
        save_top_k=1,
        mode="max",
    )
    callbacks = [
        model_checkpoint,
        EarlyStopping(monitor="val_f1", patience=PATIENCE, mode="max"),
        DatasetReshuffleCallback(datamodule),
        LearningRateMonitor(logging_interval="epoch"),
        history,
    ]

    trainer = L.Trainer(
        max_epochs=MAX_EPOCHS,
        precision=PRECISION,
        gradient_clip_val=1.0,
        callbacks=callbacks,
        enable_progress_bar=True,
        log_every_n_steps=1,
        deterministic=True,
    )

    print(f"\n{'=' * 60}")
    print(f"Training {tag} (precision={PRECISION})...")
    print(f"{'=' * 60}")
    trainer.fit(module, datamodule)

    # Reload best checkpoint
    best_path = model_checkpoint.best_model_path
    if best_path:
        module = TeacherLightningModule.load_from_checkpoint(
            best_path, model=model_cls(**model_kwargs), config=config
        )
        print(f"  Loaded best checkpoint: {best_path}")

    return module, history


# %%
teacher_config = TeacherConfig(vocab_size=len(vocab), temperature=1.0)

# --- BiLSTM ---
bilstm_module, bilstm_history = train_teacher(
    model_cls=SyscallLSTM,
    model_kwargs={"config": teacher_config},
    config=teacher_config,
    tag="bilstm",
)

# --- Transformer ---
transformer_module, transformer_history = train_teacher(
    model_cls=SyscallTransformer,
    model_kwargs={"config": teacher_config, "window_size": WINDOW_SIZE},
    config=teacher_config,
    tag="transformer",
)

# %%
# Compare and pick winner
bilstm_f1 = (
    max(bilstm_history.history["val_f1"]) if bilstm_history.history["val_f1"] else 0
)
transformer_f1 = (
    max(transformer_history.history["val_f1"])
    if transformer_history.history["val_f1"]
    else 0
)

comparison = {
    "bilstm": {
        "best_val_f1": bilstm_f1,
        "best_val_accuracy": max(bilstm_history.history["val_accuracy"])
        if bilstm_history.history["val_accuracy"]
        else 0,
        "epochs_trained": len(bilstm_history.history["train_loss"]),
    },
    "transformer": {
        "best_val_f1": transformer_f1,
        "best_val_accuracy": max(transformer_history.history["val_accuracy"])
        if transformer_history.history["val_accuracy"]
        else 0,
        "epochs_trained": len(transformer_history.history["train_loss"]),
    },
}

winner_name = "transformer" if transformer_f1 > bilstm_f1 else "bilstm"
winner_module = transformer_module if winner_name == "transformer" else bilstm_module
comparison["winner"] = winner_name

print(f"\n{'=' * 60}")
print(f"WINNER: {winner_name} (val F1 = {comparison[winner_name]['best_val_f1']:.4f})")
print(f"{'=' * 60}")

with open(OUTPUT_DIR / "teacher_comparison.json", "w") as f:
    json.dump(comparison, f, indent=2)

# Plot training curves
fig, axes = plt.subplots(1, 2, figsize=(12, 4))
for hist, name in [(bilstm_history, "BiLSTM"), (transformer_history, "Transformer")]:
    axes[0].plot(hist.history["val_loss"], label=name)
    axes[1].plot(hist.history["val_f1"], label=name)
axes[0].set_title("Validation Loss")
axes[0].set_xlabel("Epoch")
axes[0].legend()
axes[1].set_title("Validation F1")
axes[1].set_xlabel("Epoch")
axes[1].legend()
plt.tight_layout()
plt.savefig(OUTPUT_DIR / "architecture_comparison.png", dpi=120)
plt.show()

# Save winner checkpoint with a canonical name

winner_ckpt_src = OUTPUT_DIR / f"teacher_{winner_name}.ckpt"
winner_ckpt_dst = OUTPUT_DIR / "best_teacher_lidds.ckpt"
if winner_ckpt_src.exists():
    shutil.copy2(winner_ckpt_src, winner_ckpt_dst)
    print(f"Saved: {winner_ckpt_dst}")

# %% [markdown]
# ## 9. Temperature Sweep
#
# 1. Extract raw logits from the winner Teacher on val set (once).
# 2. Platt scaling → $T_{\text{calib}}$ (minimize NLL).
# 3. For each $T$: compute soft labels → train DT → measure Attack Fidelity.
# 4. Pick $T^*$ at peak Attack Fidelity.

# %%
print("\nExtracting logits and features from winner teacher on val set...")

# --- Extract logits ---
winner_model = winner_module.model
device = next(winner_model.parameters()).device

val_teacher_ds = TeacherDataset(
    corpus=corpus,
    vocab=vocab,
    window_config=window_config,
    split_name="p2_val",
    shuffle=False,
    max_windows_per_seq=MAX_WINDOWS_PER_SEQ,
    token_reader=read_sc_tokens,
)
val_loader = DataLoader(val_teacher_ds, batch_size=BATCH_SIZE, shuffle=False)

all_logits, all_labels = [], []
winner_model.eval()
with torch.no_grad():
    for token_ids, labels in val_loader:
        logits = winner_model(token_ids.to(device))
        all_logits.append(logits.cpu())
        all_labels.append(labels)

val_logits = torch.cat(all_logits, dim=0)  # (N, 2)
val_labels = torch.cat(all_labels, dim=0)  # (N,)

print(f"  Val windows: {val_logits.shape[0]}")
print(
    f"  Label balance: normal={int((val_labels == 0).sum())}, "
    f"attack={int((val_labels == 1).sum())}"
)

# --- Extract TF-IDF features for DT (same val windows) ---
print("  Extracting TF-IDF features...")
all_features, all_hard_labels = [], []
for i in range(len(val_teacher_ds)):
    # Reconstruct tokens from the same window the teacher saw
    seq_idx, win_idx = val_teacher_ds.flat_index[i]
    seq_meta = val_teacher_ds.sequences[seq_idx]
    from guepard.data_loader.windowing import extract_window_tokens, get_window_meta

    wmeta = get_window_meta(
        seq_meta.seq_id,
        seq_meta.label,
        seq_meta.seq_length,
        window_config,
        seq_meta.file_path,
        win_idx,
    )
    raw_tokens = read_sc_tokens(str(wmeta.file_path))
    window_tokens = extract_window_tokens(raw_tokens, wmeta)
    feats = vectorizer.transform(window_tokens)
    all_features.append(feats)
    all_hard_labels.append(wmeta.label)

X_val = np.vstack(all_features)
y_val = np.array(all_hard_labels)
print(f"  Feature matrix: {X_val.shape}")

# %%
# --- Platt scaling: find T_calib that minimises NLL ---
logits_np = val_logits.numpy()
labels_np = val_labels.numpy().astype(int)


def nll_at_temperature(T: float) -> float:
    probs = torch.softmax(val_logits / T, dim=-1).numpy()
    log_probs = np.log(probs[np.arange(len(labels_np)), labels_np] + 1e-10)
    return -log_probs.mean()


result = minimize_scalar(nll_at_temperature, bounds=(0.1, 10.0), method="bounded")
T_calib = float(result.x)
print(f"\nPlatt scaling: T_calib = {T_calib:.3f} (NLL = {result.fun:.4f})")

# %%
# --- Temperature sweep: train DT at each T, measure Attack Fidelity ---
print("\nTemperature sweep...")
sweep_results: list[dict] = []

for T in T_SWEEP:
    # Soft labels at this temperature
    soft_probs = torch.softmax(val_logits / T, dim=-1).numpy()

    # Teacher hard predictions (for fidelity measurement)
    teacher_preds = soft_probs.argmax(axis=1)

    # Train DT on soft labels (attack probability column)
    dt = DecisionTreeClassifier(max_depth=5, random_state=SEED)
    soft_attack_prob = soft_probs[:, 1]
    dt_labels = (soft_attack_prob > 0.5).astype(int)
    dt.fit(X_val, dt_labels)

    dt_preds = dt.predict(X_val)

    # Overall fidelity (to teacher)
    overall_fidelity = float(np.mean(dt_preds == teacher_preds))

    # Attack-class fidelity
    attack_mask = teacher_preds == 1
    if attack_mask.sum() > 0:
        attack_fidelity = float(
            np.mean(dt_preds[attack_mask] == teacher_preds[attack_mask])
        )
    else:
        attack_fidelity = 0.0

    # Entropy analysis
    attack_probs = soft_probs[y_val == 1]
    normal_probs = soft_probs[y_val == 0]

    def entropy(p):
        return -np.sum(p * np.log(p + 1e-10), axis=-1).mean() if len(p) > 0 else 0.0

    attack_entropy = entropy(attack_probs)
    normal_entropy = entropy(normal_probs)

    sweep_results.append(
        {
            "T": T,
            "overall_fidelity": overall_fidelity,
            "attack_fidelity": attack_fidelity,
            "attack_entropy": float(attack_entropy),
            "normal_entropy": float(normal_entropy),
            "n_leaves": dt.get_n_leaves(),
        }
    )

    print(
        f"  T={T:4.1f}  |  Attack Fid={attack_fidelity:.4f}  "
        f"Overall Fid={overall_fidelity:.4f}  "
        f"H(atk)={attack_entropy:.4f}  H(norm)={normal_entropy:.4f}"
    )

# Pick T* at peak Attack Fidelity
best_sweep = max(sweep_results, key=lambda r: r["attack_fidelity"])
T_star = best_sweep["T"]
print(f"\nT* = {T_star} (Attack Fidelity = {best_sweep['attack_fidelity']:.4f})")

sweep_output = {
    "T_calib": T_calib,
    "T_star": T_star,
    "sweep": sweep_results,
}
with open(OUTPUT_DIR / "temperature_sweep.json", "w") as f:
    json.dump(sweep_output, f, indent=2)

# Plot
fig, ax1 = plt.subplots(figsize=(8, 5))
Ts = [r["T"] for r in sweep_results]
ax1.plot(
    Ts, [r["attack_fidelity"] for r in sweep_results], "b-o", label="Attack Fidelity"
)
ax1.plot(
    Ts, [r["overall_fidelity"] for r in sweep_results], "g--s", label="Overall Fidelity"
)
ax1.axvline(T_star, color="r", linestyle=":", alpha=0.7, label=f"T*={T_star}")
ax1.axvline(
    T_calib, color="orange", linestyle=":", alpha=0.7, label=f"T_calib={T_calib:.2f}"
)
ax1.set_xlabel("Temperature T")
ax1.set_ylabel("Fidelity")
ax1.legend(loc="lower right")
ax1.set_title("Temperature Sweep: DT Fidelity vs T")

ax2 = ax1.twinx()
ax2.plot(
    Ts,
    [r["attack_entropy"] for r in sweep_results],
    "r--^",
    alpha=0.5,
    label="H(attack)",
)
ax2.plot(
    Ts,
    [r["normal_entropy"] for r in sweep_results],
    "m--v",
    alpha=0.5,
    label="H(normal)",
)
ax2.set_ylabel("Entropy")
ax2.legend(loc="upper left")

plt.tight_layout()
plt.savefig(OUTPUT_DIR / "temperature_sweep.png", dpi=120)
plt.show()

# %% [markdown]
# ## 10. P2 Checkpoint Validation
#
# Must pass **all three** before proceeding to P3:
#
# 1. Soft label entropy(attack class) > entropy(normal class)
# 2. T_calib > 1.0 (Teacher is overconfident → scaling helps)
# 3. DT Attack Fidelity increases when T goes from 1.0 → 3.0

# %%
# Criterion 1: entropy check at T*
best_result = next(r for r in sweep_results if r["T"] == T_star)
criterion_1 = best_result["attack_entropy"] > best_result["normal_entropy"]

# Criterion 2: T_calib > 1.0
criterion_2 = T_calib > 1.0

# Criterion 3: Attack Fidelity increases from T=1.0 to T=3.0
fid_at_1 = next(r for r in sweep_results if r["T"] == 1.0)["attack_fidelity"]
fid_at_3 = next(r for r in sweep_results if r["T"] == 3.0)["attack_fidelity"]
criterion_3 = fid_at_3 > fid_at_1

checkpoint = {
    "timestamp": datetime.datetime.now().isoformat(),
    "winner": winner_name,
    "winner_val_f1": comparison[winner_name]["best_val_f1"],
    "T_calib": T_calib,
    "T_star": T_star,
    "criteria": {
        "1_entropy_attack_gt_normal": {
            "pass": criterion_1,
            "attack_entropy": best_result["attack_entropy"],
            "normal_entropy": best_result["normal_entropy"],
        },
        "2_T_calib_gt_1": {
            "pass": criterion_2,
            "T_calib": T_calib,
        },
        "3_fidelity_increases_T1_to_T3": {
            "pass": criterion_3,
            "fidelity_at_T1": fid_at_1,
            "fidelity_at_T3": fid_at_3,
        },
    },
    "all_pass": criterion_1 and criterion_2 and criterion_3,
}

with open(OUTPUT_DIR / "p2_checkpoint.json", "w") as f:
    json.dump(checkpoint, f, indent=2)

print("\n" + "=" * 60)
print("P2 CHECKPOINT")
print("=" * 60)
print(
    f"  Winner:        {winner_name} (val F1 = {comparison[winner_name]['best_val_f1']:.4f})"
)
print(f"  T_calib:       {T_calib:.3f}")
print(f"  T*:            {T_star}")
print()
print(
    f"  [{'PASS' if criterion_1 else 'FAIL'}] Criterion 1: H(attack)={best_result['attack_entropy']:.4f} > H(normal)={best_result['normal_entropy']:.4f}"
)
print(
    f"  [{'PASS' if criterion_2 else 'FAIL'}] Criterion 2: T_calib={T_calib:.3f} > 1.0"
)
print(
    f"  [{'PASS' if criterion_3 else 'FAIL'}] Criterion 3: Fidelity@T=3.0 ({fid_at_3:.4f}) > Fidelity@T=1.0 ({fid_at_1:.4f})"
)
print()
if checkpoint["all_pass"]:
    print("  ✓ ALL CRITERIA PASSED — proceed to P3")
else:
    print("  ✗ SOME CRITERIA FAILED — investigate before proceeding")
print("=" * 60)
