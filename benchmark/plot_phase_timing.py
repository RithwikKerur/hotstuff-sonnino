#!/usr/bin/env python3
"""
Parse PHASE_TIMING log entries produced by the HotStuff consensus node and
plot per-round Phase 1 (voting/locking) and Phase 2 (commit) durations.

Because the leader rotates each round, each PHASE_TIMING entry is emitted
only by the vote-collecting leader for that round. Pass ALL node logs so
every round is covered.

python3 benchmark/plot_phase_timing.py benchmark/logs/node-*.log -o benchmark/plots/phase_timing
python3 plot_phase_timing.py logs/node-*.log -o plots/phase_timing


"""

import argparse
import re
import sys

import matplotlib
matplotlib.use("Agg")  # non-interactive backend — no display required
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np


# ── parsing ──────────────────────────────────────────────────────────────────

PATTERN = re.compile(
    r"PHASE_TIMING\s+round=(\d+)\s+phase1_ms=([\d.]+)\s+phase2_ms=([\d.]+)"
)


def parse_logs(paths: list[str]) -> tuple[list[int], list[float], list[float]]:
    """
    Merge PHASE_TIMING entries from all node logs.

    Each round's entry is emitted only by whichever node was the
    vote-collecting leader that round, so we need all logs to get full
    coverage. Duplicate entries for the same round (shouldn't happen, but
    just in case) are deduplicated by keeping the first occurrence.
    """
    seen: dict[int, tuple[float, float]] = {}
    for path in paths:
        with open(path) as f:
            for line in f:
                m = PATTERN.search(line)
                if m:
                    r = int(m.group(1))
                    if r not in seen:
                        seen[r] = (float(m.group(2)), float(m.group(3)))

    if not seen:
        return [], [], []

    rounds_sorted = sorted(seen)
    rounds = rounds_sorted
    phase1 = [seen[r][0] for r in rounds_sorted]
    phase2 = [seen[r][1] for r in rounds_sorted]
    return rounds, phase1, phase2


# ── plotting ─────────────────────────────────────────────────────────────────

def plot(log_files: list[str], output_prefix: str = "phase_timing") -> None:
    rounds, phase1, phase2 = parse_logs(log_files)

    if not rounds:
        print("No PHASE_TIMING data found in any log file.", file=sys.stderr)
        sys.exit(1)

    rounds = np.array(rounds)
    phase1 = np.array(phase1)
    phase2 = np.array(phase2)
    total  = phase1 + phase2

    print(f"Parsed {len(rounds)} rounds from {len(log_files)} log file(s).")

    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(14, 12))

    xlim = (max(0, rounds.min() - 1), rounds.max() + 1)

    def _style(ax, data, label, color, title):
        ax.bar(rounds, data, label=label, color=color, alpha=0.85)
        ax.axhline(data.mean(), color=color, linewidth=1.2, linestyle="--",
                   label=f"Mean: {data.mean():.1f} ms")
        ax.set_title(title, fontsize=11)
        ax.set_xlabel("Round", fontsize=10)
        ax.set_ylabel("Duration (ms)", fontsize=10)
        ax.legend(loc="upper right", fontsize=9)
        ax.grid(axis="y", linestyle="--", alpha=0.5)
        ax.xaxis.set_major_formatter(ticker.StrMethodFormatter("{x:,.0f}"))
        ax.yaxis.set_major_formatter(ticker.StrMethodFormatter("{x:,.1f}"))
        ax.set_xlim(xlim)
        # Zoom y-axis to the p1–p99 range so outliers don't swamp the scale.
        y_lo = max(0, np.percentile(data, 1) * 0.8)
        y_hi = np.percentile(data, 99) * 1.2
        ax.set_ylim(y_lo, y_hi)
        stats = (f"mean {data.mean():.1f} ms  |  "
                 f"median {np.median(data):.1f} ms  |  "
                 f"p95 {np.percentile(data, 95):.1f} ms  |  "
                 f"p99 {np.percentile(data, 99):.1f} ms")
        ax.text(0.01, 0.97, stats, transform=ax.transAxes,
                verticalalignment="top", fontsize=8,
                bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.7))

    _style(ax1, phase1, "Phase 1", "#4c72b0",
           "Phase 1 — Vote Collection (proposal → QC formed)")
    _style(ax2, phase2, "Phase 2", "#dd8452",
           "Phase 2 — Commit (QC formed → block committed)")
    _style(ax3, total,  "Total",   "#55a868",
           "Total Latency (proposal → committed)")

    fig.suptitle("HotStuff Phase Timing (merged across all nodes)", fontsize=13, y=1.01)
    fig.tight_layout(pad=2.0)

    out = f"{output_prefix}.png"
    fig.savefig(out, bbox_inches="tight", dpi=150)
    print(f"Saved {out}")

    plt.close(fig)


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "logs",
        nargs="+",
        metavar="LOG_FILE",
        help="All node log files (required to cover every round's leader).",
    )
    parser.add_argument(
        "-o", "--output",
        default="phase_timing",
        metavar="PREFIX",
        help="Output filename prefix (default: phase_timing). Saves <prefix>.png.",
    )
    args = parser.parse_args()
    plot(args.logs, args.output)


if __name__ == "__main__":
    main()
