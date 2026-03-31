import torch
import torch.nn as nn

from ..config import TeacherConfig


class SyscallLSTM(nn.Module):
    """Bidirectional LSTM teacher model.

    Fewer parameters than Transformer, better inductive bias for sequential
    syscall data on small datasets.
    """

    def __init__(self, config: TeacherConfig):
        super().__init__()
        self.embedding = nn.Embedding(config.vocab_size, config.d_model, padding_idx=0)
        self.lstm = nn.LSTM(
            input_size=config.d_model,
            hidden_size=config.d_model // 2,
            bidirectional=True,
            batch_first=True,
        )
        self.dropout = nn.Dropout(config.dropout)
        self.classifier = nn.Linear(config.d_model, 2)

    def forward(self, token_ids: torch.Tensor) -> torch.Tensor:
        x = self.embedding(token_ids)
        # pack_padded_sequence requires CPU lengths — unavoidable .cpu() sync
        lengths = (token_ids != 0).sum(dim=1).clamp(min=1).cpu()
        packed = nn.utils.rnn.pack_padded_sequence(
            x, lengths, batch_first=True, enforce_sorted=False
        )
        _, (h, _) = self.lstm(packed)
        h = torch.cat([h[0], h[1]], dim=-1)  # (B, d_model)
        return self.classifier(self.dropout(h))


class TransformerBlock(nn.Module):
    """Standard Transformer encoder block with optional padding mask."""

    def __init__(self, d_model: int, n_heads: int, d_ff: int, dropout: float):
        super().__init__()
        self.attn = nn.MultiheadAttention(
            embed_dim=d_model, num_heads=n_heads, dropout=dropout, batch_first=True
        )
        self.ffn = nn.Sequential(
            nn.Linear(d_model, d_ff),
            nn.GELU(),
            nn.Linear(d_ff, d_model),
        )
        self.norm1 = nn.LayerNorm(d_model, eps=1e-6)
        self.norm2 = nn.LayerNorm(d_model, eps=1e-6)
        self.drop1 = nn.Dropout(dropout)
        self.drop2 = nn.Dropout(dropout)

    def forward(
        self,
        x: torch.Tensor,
        key_padding_mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        attn_out, _ = self.attn(x, x, x, key_padding_mask=key_padding_mask)
        x = self.norm1(x + self.drop1(attn_out))
        return self.norm2(x + self.drop2(self.ffn(x)))


class SyscallTransformer(nn.Module):
    """Teacher transformer model for syscall sequence classification.

    Handles padding via ``key_padding_mask`` in attention layers and
    masked mean pooling before the classifier head.
    """

    def __init__(self, config: TeacherConfig, window_size: int):
        super().__init__()
        self.embedding = nn.Embedding(config.vocab_size, config.d_model, padding_idx=0)
        self.pos_embedding = nn.Embedding(window_size + 1, config.d_model)
        self.blocks = nn.ModuleList(
            [
                TransformerBlock(
                    config.d_model, config.n_heads, config.d_ff, config.dropout
                )
                for _ in range(config.n_layers)
            ]
        )
        self.classifier = nn.Linear(config.d_model, 2)

    def forward(self, token_ids: torch.Tensor) -> torch.Tensor:
        positions = torch.arange(token_ids.shape[1], device=token_ids.device)
        x = self.embedding(token_ids) + self.pos_embedding(positions)

        padding_mask = token_ids == 0  # (B, S) — True where padded
        for block in self.blocks:
            x = block(x, key_padding_mask=padding_mask)

        # Masked mean pooling: ignore padding positions
        mask = (~padding_mask).unsqueeze(-1).float()  # (B, S, 1)
        x = (x * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)

        return self.classifier(x)
