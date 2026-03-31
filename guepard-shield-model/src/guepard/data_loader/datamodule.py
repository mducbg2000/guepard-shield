from typing import Optional

import lightning as L
from torch.utils.data import DataLoader

from ..config import WindowConfig
from .teacher_dataset import TeacherDataset, TokenReader
from .vocab import SyscallVocab


class TeacherDataModule(L.LightningDataModule):
    """LightningDataModule wrapping TeacherDataset for train and validation.

    Works with any corpus that exposes ``get_split(name) -> list[SequenceMeta]``
    (both :class:`DongTingCorpus` and :class:`LiddsCorpus`).

    Sequence-level shuffling is preserved: datasets rebuild their flat_index
    each epoch via the :class:`DatasetReshuffleCallback`.

    Parameters
    ----------
    token_reader : callable, optional
        Custom file reader passed to TeacherDataset.
        Default (None) uses DongTing pipe-delimited reader.
        For LID-DS pass ``lidds_corpus.read_sc_tokens``.
    num_workers : int
        DataLoader workers. 0 = main-process loading. Default 0 is safe for
        any system; increase (e.g. 4) on machines with sufficient RAM.
    """

    def __init__(
        self,
        corpus,
        vocab: SyscallVocab,
        window_config: WindowConfig,
        train_split: str,
        val_split: str,
        batch_size: int = 1024,
        max_windows_per_seq: Optional[int] = None,
        seed: int = 42,
        token_reader: Optional[TokenReader] = None,
        num_workers: int = 0,
    ):
        super().__init__()
        self.corpus = corpus
        self.vocab = vocab
        self.window_config = window_config
        self.train_split = train_split
        self.val_split = val_split
        self.batch_size = batch_size
        self.max_windows_per_seq = max_windows_per_seq
        self.seed = seed
        self.token_reader = token_reader
        self.num_workers = num_workers

        self.train_dataset: TeacherDataset = TeacherDataset(
            corpus=corpus,
            vocab=vocab,
            window_config=window_config,
            split_name=train_split,
            batch_size=batch_size,
            shuffle=True,
            max_windows_per_seq=max_windows_per_seq,
            seed=self.seed,
            token_reader=token_reader,
        )
        self.val_dataset: TeacherDataset = TeacherDataset(
            corpus=corpus,
            vocab=vocab,
            window_config=window_config,
            split_name=val_split,
            batch_size=batch_size,
            shuffle=False,
            max_windows_per_seq=max_windows_per_seq,
            seed=self.seed,
            token_reader=token_reader,
        )

    def train_dataloader(self):
        return DataLoader(
            self.train_dataset,
            batch_size=self.batch_size,
            shuffle=False,  # sequence-level shuffle handled by TeacherDataset.reshuffle()
            num_workers=self.num_workers,
            pin_memory=True,
            # persistent_workers must be False so each epoch forks fresh workers
            # that inherit the reshuffled flat_index from the main process.
            persistent_workers=False,
        )

    def val_dataloader(self):
        return DataLoader(
            self.val_dataset,
            batch_size=self.batch_size,
            shuffle=False,
            num_workers=self.num_workers,
            pin_memory=True,
        )
