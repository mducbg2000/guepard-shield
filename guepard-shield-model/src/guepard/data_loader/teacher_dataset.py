import random
from functools import lru_cache
from typing import Callable, List, Optional

import numpy as np
from torch.utils.data import Dataset

from ..config import WindowConfig
from .vocab import SyscallVocab
from .windowing import extract_window_tokens, get_window_meta, num_sliding_windows

# Type alias for the token reader function (file_path_str → token list).
TokenReader = Callable[[str], List[str]]


@lru_cache(maxsize=8)
def _read_tokens_from_file(file_path_str: str) -> List[str]:
    """DongTing token reader: pipe-delimited .log files.

    Module-level LRU cache shared across all dataset instances.
    maxsize=8: sequence-level shuffle guarantees all windows of a sequence are
    accessed consecutively, so only O(workers) files need to be hot at once.
    """
    with open(file_path_str, "r", encoding="utf-8") as f:
        content = f.read().strip()
    return content.split("|") if content else []


class TeacherDataset(Dataset):
    """
    torch Dataset for the Teacher model.

    Uses a flat index of (seq_idx, win_idx) tuples for uniform per-sequence sampling.
    max_windows_per_seq caps windows per sequence to reduce class imbalance.
    Call reshuffle() at the end of each training epoch to re-randomise sequence order.

    Parameters
    ----------
    token_reader : callable, optional
        ``f(file_path_str) -> List[str]`` — reads a corpus file and returns
        the token list.  Defaults to DongTing pipe-delimited reader.
        For LID-DS, pass ``lidds_corpus.read_sc_tokens``.
    """

    def __init__(
        self,
        corpus,
        vocab: Optional[SyscallVocab],
        window_config: WindowConfig,
        split_name: str,
        batch_size: int = 32,  # stored for reference (e.g. results JSON)
        shuffle: bool = True,
        max_windows_per_seq: Optional[int] = None,
        seed: int = 42,
        token_reader: Optional[TokenReader] = None,
    ):
        super().__init__()
        self.corpus = corpus
        self.vocab = vocab
        self.window_config = window_config
        self.batch_size = batch_size
        self.shuffle = shuffle
        self.max_windows_per_seq = max_windows_per_seq
        self._seed = seed
        self._token_reader: TokenReader = token_reader or _read_tokens_from_file

        # Cache constants to avoid repeated dict lookups in __getitem__
        if vocab is not None:
            self.pad_id = vocab.token2id.get(vocab.PAD_TOKEN, 0)
            self.unk_id = vocab.token2id.get(vocab.UNK_TOKEN, 0)
        else:
            self.pad_id = 0
            self.unk_id = 1
        self.window_size = window_config.window_size

        self.sequences = list(corpus.get_split(split_name))
        self.flat_index: list[tuple[int, int]] = []
        self._build_index(random.Random(seed))

    def _build_index(self, rng: random.Random) -> None:
        groups: list[list[tuple[int, int]]] = []
        for seq_idx, meta in enumerate(self.sequences):
            n = num_sliding_windows(meta.seq_length, self.window_config)
            if n == 0:
                continue
            win_indices = list(range(n))
            if self.max_windows_per_seq and n > self.max_windows_per_seq:
                win_indices = rng.sample(win_indices, self.max_windows_per_seq)
            groups.append([(seq_idx, w) for w in win_indices])

        # Sequence-level shuffle: all windows of a sequence stay consecutive so each
        # file is read once then reused — critical for long attack sequences.
        if self.shuffle:
            rng.shuffle(groups)

        self.flat_index = [pair for group in groups for pair in group]

    def reshuffle(self) -> None:
        """Rebuild flat_index with a new random order. Call at end of each training epoch."""
        if self.shuffle:
            self._build_index(random.Random())

    def __len__(self) -> int:
        return len(self.flat_index)

    def __getitem__(self, index: int) -> tuple[np.ndarray, np.ndarray]:
        seq_idx, win_idx = self.flat_index[index]
        seq_meta = self.sequences[seq_idx]

        meta = get_window_meta(
            seq_id=seq_meta.seq_id,
            label=seq_meta.label,
            seq_length=seq_meta.seq_length,
            config=self.window_config,
            file_path=seq_meta.file_path,
            window_idx=win_idx,
        )
        raw_tokens = self._token_reader(str(meta.file_path))
        window_tokens = extract_window_tokens(raw_tokens, meta)

        if self.vocab is None:
            raise RuntimeError(
                "Vocab cannot be None when calling TeacherDataset.__getitem__"
            )

        ids = [self.vocab.token2id.get(t, self.unk_id) for t in window_tokens]
        if len(ids) < self.window_size:
            ids.extend([self.pad_id] * (self.window_size - len(ids)))

        return np.array(ids, dtype=np.int32), np.array(meta.label, dtype=np.int32)
