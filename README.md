# Guepard Shield: A novel data breach detection mechanism using kernel-level information

**Guepard Shield** is a research framework for Host-based Intrusion Detection (HIDS) that bridges the gap between deep learning accuracy and kernel-level performance.

## 🎯 Project Objective
The goal is to train a high-accuracy Transformer model on system call sequences (Teacher), then distill its complex decision-making logic into simple, human-readable rules (Student) that can be enforced in real-time using eBPF.

## 🏗 Unified Monorepo Structure

This project is organized as a unified workspace for both Python (ML) and Rust (eBPF).

- **`guepard-shield-model/`**: The core Python logic.
  - `gp/`: The main package (importable as `import gp`). Contains models and data loaders.
  - `pyproject.toml`: Minimalist project file to register the `gp` package.
- **`guepard-shield-ebpf/`**: Rust implementation of the kernel-side detection logic.
- **`guepard-shield/`**: Rust implementation of the userspace agent (using Aya).
- **`guepard-shield-common/`**: Shared Rust structures between user and kernel space.
- **`data/`**: Consolidated syscall datasets (LID-DS, DongTing).
- **`results/`**: Shared training artifacts, checkpoints, and evaluation metrics.
- **`notebooks/`**: Phase-specific experimental scripts (Jupytext format).
- **`docs/`**: Project documentation and thesis materials.

## 🛠 Setup & Development

The project uses **UV** for Python and **Cargo** for Rust. Everything is designed to be executed from the **Project Root**.

### 1. Python Environment (Unified)
The Python environment is managed at the root. The `gp` module is installed in editable mode automatically via `uv_build`.

```bash
# Sync environment and dependencies
uv sync
```

### 2. Running ML Pipeline
No `PYTHONPATH` or `cd` required. Just run from root:
```bash
# Train the model
uv run python notebooks/p2/train_transformer.py

# Evaluate on Test set
uv run python notebooks/p2/evaluate_transformer.py
```

### 3. Rust/eBPF Build
```bash
# Build both userspace agent and kernel program
cargo build --release
```

## 📜 Progress & Documentation
For implementation details, Phase 2 status, and technical decisions, see:
👉 **[docs/WALKTHROUGH.md](docs/WALKTHROUGH.md)**
