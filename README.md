# Guepard Shield: A novel data breach detection mechanism using kernel-level information

**Guepard Shield** is a research framework for Host-based Intrusion Detection (HIDS) that bridges the gap between deep learning accuracy and kernel-level performance.

## 🎯 Project Objective
The long-term research goal is to study how syscall-based anomaly detection can move from offline machine-learning experiments to lightweight kernel-side enforcement with eBPF. In this checkout, the implemented and reproducible part of the project is **Phase 1: EDA and data preprocessing**. The later Transformer / rule-distillation stages are currently documented as a **new target architecture**, not as runnable code in the repository.

## 🏗 Unified Monorepo Structure

This project is organized as a unified workspace for both Python (ML) and Rust (eBPF).

- **`guepard-shield-model/`**: The core Python logic.
  - `gp/`: The main package (importable as `import gp`). Contains dataset loaders, diagnostics, and shared project paths.
  - `pyproject.toml`: Minimalist project file to register the `gp` package.
- **`guepard-shield-ebpf/`**: Rust eBPF scaffold for future kernel-side experiments.
- **`guepard-shield/`**: Rust userspace scaffold (using Aya).
- **`guepard-shield-common/`**: Shared Rust structures between user and kernel space.
- **`data/`**: Consolidated syscall datasets (LID-DS, DongTing).
- **`results/`**: Generated EDA artifacts and summaries.
- **`notebooks/`**: Phase-specific research scripts. At the moment, only `notebooks/p1/` is part of the maintained workflow.
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
# Run EDA on LID-DS-2021
uv run python notebooks/p1/eda_lidds2021.py

# Run EDA on LID-DS-2019
uv run python notebooks/p1/eda_lidds2019.py

# Run EDA on DongTing
uv run python notebooks/p1/eda_dongtingds.py
```

### 3. Rust/eBPF Build
```bash
# Build both userspace agent and kernel program
cargo build --release
```

## 📜 Progress & Documentation
- **Phase 1 (EDA):** ✅ Completed.
- **Phase 2 (Teacher):** ⏳ Not implemented in the current codebase. The docs describe a new intended architecture only.
- **Phase 3 (Student):** ⏳ Not implemented in the current codebase. The docs describe a new intended architecture only.
- **Phase 4 (Deployment):** ⏳ Planned.

For technical details and current tasks, see:
👉 **[docs/WALKTHROUGH.md](docs/WALKTHROUGH.md)**
