# README.md

## Project Overview

**guepard-shield** is a master's research project: a container security system that detects intrusions via syscall monitoring using eBPF, then uses a Transformer (Teacher) to extract interpretable rules (Decision Tree, RuleFit, Anchors) deployable back to eBPF/Cedar policies.

**Stack:** Rust + Aya (eBPF), PyTorch Lightning (deep learning), Scikit-learn/SHAP (rule extraction).

## Build & Run (Rust)

Build requires `bpf-linker` in PATH (for cross-compiling the eBPF bytecode):

```bash
# Build userspace + eBPF (eBPF is cross-compiled via build.rs automatically)
cargo build

# Run (requires root; .cargo/config.toml sets runner = "sudo -E")
cargo run

# Release build
cargo build --release
```

The `guepard-shield` build script (`build.rs`) calls `aya_build::build_ebpf` to cross-compile `guepard-shield-ebpf` for the BPF target. The resulting bytecode is embedded in the userspace binary via `include_bytes_aligned!`.

## Python (ML / Data)

Python workspace live in `guepard-shield-model/`
Uses `uv` for package management. Python ≥ 3.14 required.

```bash
# Install dependencies
uv sync

# Run any script
uv run scripts/<script>.py

# Run a notebook (jupytext format)
uv run jupyter notebook

# Type-check
uv run ty check
```

Notebooks in `guepard-shield-model/notebooks` use **jupytext** format — cells are delimited by `# %%` comments, not `.ipynb` JSON.

## Architecture

### Rust Workspace

| Crate                   | Target           | Role                                                                                                            |
| ----------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------- |
| `guepard-shield`        | host (userspace) | Loads eBPF bytecode, attaches tracepoint `raw_syscalls/sys_enter`, drives tokio async runtime                   |
| `guepard-shield-ebpf`   | `bpf` (kernel)   | `#![no_std]` eBPF program; hooks `sys_enter` tracepoint, logs/processes syscall events                          |
| `guepard-shield-common` | both             | Shared data structures; compiled with `#![no_std]`, feature-gated: `user` feature enables `std`-dependent impls |

**Data flow:** kernel eBPF program captures syscalls → passes events to userspace via eBPF maps → userspace processes/forwards for ML inference or rule matching.

### Python ML Pipeline

Located in `guepard-shield-model/`:

- `data/raw/` — read-only raw datasets (LID-DS, DongTing, ADFA-LD, etc.)
- `data/processed/` — preprocessed data output
- `scripts/` — data transformation, analysis, verification scripts

## Key Design Decisions

- `guepard-shield-common` must remain `no_std` compatible; use the `user` feature flag to gate any `std` usage
- eBPF programs use dual license `MIT/GPL` (required for kernel helper access)
- The workspace `default-members` excludes `guepard-shield-ebpf` to avoid attempting to build the BPF target with normal `cargo build`; the build script handles cross-compilation automatically
- Polars (not Pandas) for dataframes; Lightning (not raw PyTorch training loops) for model training
