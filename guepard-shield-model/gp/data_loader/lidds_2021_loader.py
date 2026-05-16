"""LID-DS-2021 loader and windowing helpers for preprocessing workflows."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import numpy as np
from tqdm import tqdm

from gp.data_loader.recording import Recording, load_recording

# Directories that are not scenario folders
_NON_SCENARIO = {"_lidds_seq_lengths.json", "README.md"}

# All 15 known LID-DS-2021 scenarios
ALL_SCENARIOS = [
    "CVE-2012-2122",
    "CVE-2014-0160",
    "CVE-2017-7529",
    "CVE-2017-12635_6",
    "CVE-2018-3760",
    "CVE-2019-5418",
    "CVE-2020-9484",
    "CVE-2020-13942",
    "CVE-2020-23839",
    "CVE-2021-3156",
    "CVE-2021-22555",
    "CVE-2021-31320",
    "CVE-2021-31921",
    "CVE-2021-41773",
    "CVE-2021-43798",
]

PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"


class LiddS2021Loader:
    """Load LID-DS-2021 recordings from disk and build a vocabulary."""

    def __init__(
        self,
        data_dir: Path,
        scenarios: list[str] | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.scenarios = scenarios  # None = all present

    def _scenario_dirs(self) -> list[Path]:
        if self.scenarios is not None:
            return [self.data_dir / s for s in self.scenarios]
        return sorted(
            p
            for p in self.data_dir.iterdir()
            if p.is_dir() and p.name not in _NON_SCENARIO
        )

    _SPLIT_MAP: dict[str, list[tuple[str, bool]]] = {
        "train": [("training", False)],
        "val":   [("validation", False)],
        "test":  [
            ("test/normal", False),
            ("test/normal_and_attack", True),
        ],
    }

    def stream_split(self, split: str, max_syscalls: int | None = None):
        """Lazily yield one Recording at a time.

        Args:
            max_syscalls: Cap on exit-syscall events read per recording.
                Set to ``window_size + max_windows * stride`` to avoid reading
                more of each .sc file than the windowing step will use.
                None reads every line (slow for large recordings).
        """
        for sc_dir in self._scenario_dirs():
            if not sc_dir.exists():
                continue
            sc_name = sc_dir.name
            for rel, is_exploit in self._SPLIT_MAP[split]:
                sub = sc_dir / rel
                if not sub.exists():
                    continue
                for rec_dir in sorted(sub.iterdir()):
                    if not rec_dir.is_dir():
                        continue
                    sc_path = rec_dir / f"{rec_dir.name}.sc"
                    json_path = rec_dir / f"{rec_dir.name}.json"
                    if not sc_path.exists() or not json_path.exists():
                        continue
                    yield load_recording(
                        sc_path=sc_path,
                        json_path=json_path,
                        scenario=sc_name,
                        split=split,
                        name=rec_dir.name,
                        is_exploit=is_exploit,
                        max_syscalls=max_syscalls,
                    )

    def load_split(self, split: str, max_syscalls: int | None = None) -> list[Recording]:
        """Load all recordings for a split eagerly."""
        return list(tqdm(self.stream_split(split, max_syscalls=max_syscalls),
                         desc=f"load {split}", unit="rec"))

    def load_all(self) -> dict[str, list[Recording]]:
        """Load all splits eagerly. Only use when all data fits in RAM."""
        return {
            "train": self.load_split("train"),
            "val":   self.load_split("val"),
            "test":  self.load_split("test"),
        }

    def build_vocab(
        self,
        train_recordings: list[Recording],
        min_freq: int = 2,
    ) -> dict[str, int]:
        """Build {syscall_name -> int} vocab from training recordings."""
        return self.build_vocab_from_stream(iter(train_recordings), min_freq=min_freq)

    def build_vocab_from_stream(
        self,
        recording_stream,
        min_freq: int = 2,
    ) -> dict[str, int]:
        """Build vocab from a stream of recordings without holding all in RAM."""
        counts: Counter[str] = Counter()
        for rec in tqdm(recording_stream, desc="Building vocab", unit="rec"):
            for sc in rec.syscalls:
                counts[sc.syscall] += 1
            # Quan trọng: giải phóng bộ nhớ syscalls sau khi đếm xong
            rec.syscalls.clear()

        vocab: dict[str, int] = {PAD_TOKEN: 0, UNK_TOKEN: 1}
        # unknown artifact (id=2) nếu có trong data
        if "<unknown>" in counts:
            vocab["<unknown>"] = 2
            
        for name, freq in sorted(counts.items()):
            if name == "<unknown>": continue
            if freq >= min_freq:
                vocab[name] = len(vocab)
        return vocab

    @staticmethod
    def save_vocab(vocab: dict[str, int], path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(vocab, f, indent=2)

    @staticmethod
    def load_vocab(path: Path) -> dict[str, int]:
        with open(path) as f:
            return json.load(f)


class SyscallWindowDataset:
    """Sliding-window dataset over a list of Recordings.

    Args:
        recordings: List of Recording objects. Syscall lists are freed from
            memory after windowing to keep peak RAM low.
        vocab: Token vocabulary from LiddS2021Loader.build_vocab().
        window_size: Number of tokens per window.
        stride: Step between windows. Defaults to window_size//2.
        max_windows_per_recording: Cap on windows extracted per recording.
            Uniform subsampling is applied when the cap is hit. Use ~500 for
            training on 32 GB RAM; None for evaluation (all windows needed
            for correct per-recording aggregation).
    """

    def __init__(
        self,
        recordings: list[Recording],
        vocab: dict[str, int],
        window_size: int = 100,
        stride: int | None = None,
        max_windows_per_recording: int | None = None,
    ) -> None:
        self.recordings = recordings
        self.vocab = vocab
        self.window_size = window_size
        self.stride = stride if stride is not None else window_size // 2
        self.max_windows_per_recording = max_windows_per_recording

    def _encode(self, syscalls: list[str]) -> np.ndarray:
        unk = self.vocab[UNK_TOKEN]
        return np.array([self.vocab.get(sc, unk) for sc in syscalls], dtype=np.int32)

    def as_arrays(
        self,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Return (X [N,W], y [N], rec_ids [N]) as int32 arrays.

        Syscall lists on Recording objects are cleared after encoding to
        release RAM as each recording is processed.
        """
        W = self.window_size
        S = self.stride
        rng = np.random.default_rng(0)

        X_parts: list[np.ndarray] = []
        y_parts: list[np.ndarray] = []
        ids_parts: list[np.ndarray] = []

        for rec_id, rec in enumerate(self.recordings):
            tokens = self._encode([sc.syscall for sc in rec.syscalls])
            # Free the syscall list immediately — largest per-recording cost.
            rec.syscalls.clear()

            label = int(rec.is_exploit)
            n_tok = len(tokens)

            if n_tok == 0:
                continue

            # Build all start indices for this recording.
            starts = np.arange(0, max(1, n_tok - W + 1), S)

            # Subsample if capped.
            cap = self.max_windows_per_recording
            if cap is not None and len(starts) > cap:
                starts = rng.choice(starts, size=cap, replace=False)
                starts.sort()

            n_win = len(starts)
            rec_X = np.zeros((n_win, W), dtype=np.int32)
            for i, start in enumerate(starts):
                chunk = tokens[start : start + W]
                rec_X[i, : len(chunk)] = chunk  # trailing zeros = PAD

            X_parts.append(rec_X)
            y_parts.append(np.full(n_win, label, dtype=np.int32))
            ids_parts.append(np.full(n_win, rec_id, dtype=np.int32))

        if not X_parts:
            return (
                np.empty((0, W), dtype=np.int32),
                np.empty((0,), dtype=np.int32),
                np.empty((0,), dtype=np.int32),
            )

        return (
            np.concatenate(X_parts, axis=0),
            np.concatenate(y_parts, axis=0),
            np.concatenate(ids_parts, axis=0),
        )


def stream_and_window(
    recording_stream,
    vocab: dict[str, int],
    window_size: int = 100,
    stride: int | None = None,
    max_windows_per_recording: int | None = None,
) -> tuple[list[Recording], np.ndarray, np.ndarray, np.ndarray]:
    """Window recordings from a generator without loading all into RAM at once.

    Each recording is loaded, windowed, and its syscalls freed before the next
    one is read. Only window arrays and lightweight Recording metadata remain.

    Returns:
        (meta_list, X [N,W], y [N], rec_ids [N])
        meta_list: Recording objects with empty .syscalls — used for per-recording
            metrics aggregation (scenario, is_exploit, etc.).
    """
    rng = np.random.default_rng(0)
    W = window_size
    S = stride if stride is not None else window_size // 2
    unk = vocab[UNK_TOKEN]

    meta_list: list[Recording] = []
    X_parts: list[np.ndarray] = []
    y_parts: list[np.ndarray] = []
    ids_parts: list[np.ndarray] = []

    for rec_id, rec in tqdm(enumerate(recording_stream), desc="windowing", unit="rec"):
        tokens = np.array(
            [vocab.get(sc.syscall, unk) for sc in rec.syscalls], dtype=np.int32
        )
        rec.syscalls.clear()  # free immediately

        meta_list.append(rec)
        label = int(rec.is_exploit)
        n_tok = len(tokens)
        if n_tok == 0:
            continue

        starts = np.arange(0, max(1, n_tok - W + 1), S)
        cap = max_windows_per_recording
        if cap is not None and len(starts) > cap:
            starts = rng.choice(starts, size=cap, replace=False)
            starts.sort()

        n_win = len(starts)
        rec_X = np.zeros((n_win, W), dtype=np.int32)
        for i, start in enumerate(starts):
            chunk = tokens[start : start + W]
            rec_X[i, : len(chunk)] = chunk

        X_parts.append(rec_X)
        y_parts.append(np.full(n_win, label, dtype=np.int32))
        ids_parts.append(np.full(n_win, rec_id, dtype=np.int32))

    if not X_parts:
        W_ = window_size
        return (
            meta_list,
            np.empty((0, W_), dtype=np.int32),
            np.empty((0,), dtype=np.int32),
            np.empty((0,), dtype=np.int32),
        )

    return (
        meta_list,
        np.concatenate(X_parts, axis=0),
        np.concatenate(y_parts, axis=0),
        np.concatenate(ids_parts, axis=0),
    )
