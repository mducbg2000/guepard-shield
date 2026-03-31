import lightning as L
import torch
import torch.nn as nn
import torch.nn.functional as F
from torchmetrics import Accuracy, F1Score

from ..config import TeacherConfig


class TeacherLightningModule(L.LightningModule):
    """Lightning wrapper for SyscallLSTM / SyscallTransformer teacher models."""

    def __init__(self, model: nn.Module, config: TeacherConfig):
        super().__init__()
        self.model = model
        self.config = config

        self.train_acc = Accuracy(task="binary")
        self.val_acc = Accuracy(task="binary")
        self.val_f1 = F1Score(task="binary")

    def forward(self, x: torch.Tensor):
        return self.model(x)

    def _compute_loss(self, y: torch.Tensor, logits: torch.Tensor):
        if y.is_floating_point():
            # Soft labels: temperature-scaled categorical cross-entropy
            log_probs = F.log_softmax(logits / self.config.temperature, dim=-1)
            return -(y * log_probs).sum(dim=-1).mean()
        return F.cross_entropy(logits, y.long())

    def _shared_step(self, batch: tuple):
        x, y = batch
        logits = self(x)
        loss = self._compute_loss(y, logits)
        preds = logits.argmax(dim=-1)
        hard_y = y.argmax(dim=-1).long() if y.is_floating_point() else y.long()
        return loss, preds, hard_y

    def training_step(self, batch: tuple, batch_idx: int):
        loss, preds, hard_y = self._shared_step(batch)
        self.train_acc(preds, hard_y)
        self.log("train_loss", loss, on_step=True, on_epoch=True, prog_bar=True)
        self.log(
            "train_accuracy",
            self.train_acc,
            on_step=False,
            on_epoch=True,
            prog_bar=True,
        )
        return loss

    def validation_step(self, batch: tuple, batch_idx: int):
        loss, preds, hard_y = self._shared_step(batch)
        self.val_acc(preds, hard_y)
        self.val_f1(preds, hard_y)
        self.log("val_loss", loss, on_step=False, on_epoch=True, prog_bar=True)
        self.log(
            "val_accuracy",
            self.val_acc,
            on_step=False,
            on_epoch=True,
            prog_bar=True,
        )
        self.log("val_f1", self.val_f1, on_step=False, on_epoch=True, prog_bar=True)
        return loss

    def configure_optimizers(self):
        optimizer = torch.optim.AdamW(
            self.parameters(),
            lr=self.config.lr,
            weight_decay=self.config.weight_decay,
        )
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=(self.trainer.max_epochs or 1), eta_min=1e-6
        )
        return {"optimizer": optimizer, "lr_scheduler": scheduler}
