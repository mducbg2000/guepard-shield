"""Phase segmenter for syscall recordings.

Assigns each syscall event a lifecycle phase label based on the local
syscall rate.  Thresholds are percentile-based (P25/P75 of the rate
distribution within a single recording) so they auto-adapt to workload
intensity without per-dataset tuning.

Algorithm (from research proposal §4.2)::

    1. Compute syscall rate per sliding window (default 100 ms).
    2. P25 / P75 of the per-window rate define *idle* and *active* thresholds.
    3. Startup = initial contiguous block where rate variance is still high
       (coefficient of variation > cv_threshold over a look-back of 5 windows).
    4. Shutdown = trailing block where rate monotonically decreases to ≤ P25.
    5. Remaining windows: rate > P75 → active, rate < P25 → idle,
       otherwise → active (default bucket).
"""

from pathlib import Path
from typing import List

import numpy as np

PHASE_STARTUP = "startup"
PHASE_ACTIVE = "active"
PHASE_IDLE = "idle"
PHASE_SHUTDOWN = "shutdown"

ALL_PHASES = [PHASE_STARTUP, PHASE_ACTIVE, PHASE_IDLE, PHASE_SHUTDOWN]


def read_sc_timestamps(file_path: str | Path) -> list[int]:
    """Extract nanosecond timestamps of exit events from a .sc file."""
    timestamps: list[int] = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 7 and parts[6] == "<":
                try:
                    timestamps.append(int(parts[0]))
                except ValueError:
                    continue
    return timestamps


def compute_syscall_rates(
    timestamps_ns: list[int] | np.ndarray,
    window_ms: float = 100.0,
) -> tuple[np.ndarray, np.ndarray]:
    """Compute per-window syscall rate.

    Returns
    -------
    window_starts : ndarray, shape (N,)
        Start timestamp (ns) of each rate window.
    rates : ndarray, shape (N,)
        Number of events in each window.
    """
    if len(timestamps_ns) == 0:
        return np.array([], dtype=np.int64), np.array([], dtype=np.float64)

    ts = np.asarray(timestamps_ns, dtype=np.int64)
    window_ns = int(window_ms * 1_000_000)

    t_min, t_max = ts[0], ts[-1]
    if t_max <= t_min:
        return np.array([t_min], dtype=np.int64), np.array(
            [float(len(ts))], dtype=np.float64
        )

    edges = np.arange(t_min, t_max + window_ns, window_ns, dtype=np.int64)
    counts, _ = np.histogram(ts, bins=edges)

    window_starts = edges[:-1]
    rates = counts.astype(np.float64)
    return window_starts, rates


def segment_phases(
    timestamps_ns: list[int] | np.ndarray,
    window_ms: float = 100.0,
    cv_threshold: float = 0.5,
    lookback: int = 5,
) -> list[str]:
    """Assign a phase label to each event in a recording.

    Parameters
    ----------
    timestamps_ns : list[int]
        Nanosecond timestamps of exit events (must be sorted ascending).
    window_ms : float
        Sliding window width in milliseconds for rate computation.
    cv_threshold : float
        Coefficient of variation threshold for startup detection.
        Startup ends when the CV over *lookback* consecutive windows
        drops below this value.
    lookback : int
        Number of consecutive windows used for the rolling CV check.

    Returns
    -------
    labels : list[str]
        One phase label per event, same length as *timestamps_ns*.
    """
    n_events = len(timestamps_ns)
    if n_events == 0:
        return []

    ts = np.asarray(timestamps_ns, dtype=np.int64)
    window_starts, rates = compute_syscall_rates(ts, window_ms)
    n_windows = len(rates)

    if n_windows <= 1:
        return [PHASE_ACTIVE] * n_events

    # --- Percentile thresholds ---
    p25 = np.percentile(rates, 25)
    p75 = np.percentile(rates, 75)

    # --- Per-window phase assignment ---
    window_phases = [PHASE_ACTIVE] * n_windows

    # 1. Startup: initial block with high rate variance
    startup_end = 0
    for i in range(lookback, n_windows):
        block = rates[i - lookback : i]
        mean = block.mean()
        if mean > 0 and (block.std() / mean) < cv_threshold:
            startup_end = i
            break
    else:
        startup_end = min(lookback, n_windows)

    for i in range(startup_end):
        window_phases[i] = PHASE_STARTUP

    # 2. Shutdown: trailing monotonically decreasing block ending at ≤ P25
    shutdown_start = n_windows
    if rates[-1] <= p25:
        shutdown_start = n_windows - 1
        for i in range(n_windows - 2, startup_end - 1, -1):
            if rates[i] >= rates[i + 1]:
                shutdown_start = i + 1
            else:
                break
        for i in range(shutdown_start, n_windows):
            window_phases[i] = PHASE_SHUTDOWN

    # 3. Active / Idle for remaining windows
    for i in range(startup_end, shutdown_start):
        if rates[i] < p25:
            window_phases[i] = PHASE_IDLE
        elif rates[i] >= p75:
            window_phases[i] = PHASE_ACTIVE
        else:
            window_phases[i] = PHASE_ACTIVE  # default bucket

    # --- Map window phases back to individual events ---
    window_ns = int(window_ms * 1_000_000)
    t_min = window_starts[0] if len(window_starts) > 0 else ts[0]

    labels: list[str] = []
    for t in ts:
        win_idx = int((t - t_min) / window_ns)
        win_idx = max(0, min(win_idx, n_windows - 1))
        labels.append(window_phases[win_idx])

    return labels


def phase_summary(labels: List[str]) -> dict[str, int]:
    """Count events per phase."""
    counts = {p: 0 for p in ALL_PHASES}
    for lbl in labels:
        counts[lbl] = counts.get(lbl, 0) + 1
    return counts
