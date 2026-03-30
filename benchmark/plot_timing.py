"""
Parse TIMING log entries from node logs and plot:
  1. CDF of proof delay    (availability_proof - block_received)
  2. CDF of commit delay   (block_committed    - block_received)
  3. Scatter: proof delay vs commit delay per batch root

Usage:
    python benchmark/plot_timing.py [logs_dir]

logs_dir defaults to benchmark/logs/
"""

import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median

import matplotlib.pyplot as plt
import numpy as np


# ── log parsing ──────────────────────────────────────────────────────────────

TIMESTAMP_RE = re.compile(r'\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)')
RECEIVED_RE  = re.compile(r'TIMING block_received root=(\S+) block=\S+ round=\d+')
PROOF_RE     = re.compile(r'TIMING availability_proof root=(\S+)')
COMMITTED_RE = re.compile(r'TIMING block_committed root=(\S+) block=\S+ round=\d+')


def parse_ts(ts_str: str) -> float:
    return datetime.fromisoformat(ts_str.replace('Z', '+00:00')).timestamp()


def parse_log(path: Path) -> tuple[dict, dict, dict]:
    received  = {}   # root -> earliest timestamp
    proof     = {}
    committed = {}

    with open(path) as f:
        for line in f:
            ts_match = TIMESTAMP_RE.match(line)
            if not ts_match:
                continue
            ts = parse_ts(ts_match.group(1))

            m = RECEIVED_RE.search(line)
            if m:
                root = m.group(1)
                if root not in received or ts < received[root]:
                    received[root] = ts
                continue

            m = PROOF_RE.search(line)
            if m:
                root = m.group(1)
                if root not in proof or ts < proof[root]:
                    proof[root] = ts
                continue

            m = COMMITTED_RE.search(line)
            if m:
                root = m.group(1)
                if root not in committed or ts < committed[root]:
                    committed[root] = ts

    return received, proof, committed


def merge_earliest(dicts: list[dict]) -> dict:
    merged = {}
    for d in dicts:
        for k, v in d.items():
            if k not in merged or v < merged[k]:
                merged[k] = v
    return merged


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    logs_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / 'logs'
    node_logs = sorted(logs_dir.glob('node-*.log'))

    if not node_logs:
        print(f'No node-*.log files found in {logs_dir}')
        sys.exit(1)

    all_received, all_proof, all_committed = [], [], []
    for p in node_logs:
        r, pr, c = parse_log(p)
        all_received.append(r)
        all_proof.append(pr)
        all_committed.append(c)

    received  = merge_earliest(all_received)
    proof     = merge_earliest(all_proof)
    committed = merge_earliest(all_committed)

    # Compute delays for roots that have all three events.
    proof_delays  = []
    commit_delays = []
    common_roots  = set(received) & set(proof) & set(committed)

    for root in common_roots:
        t0 = received[root]
        proof_delays.append((proof[root]     - t0) * 1000)   # ms
        commit_delays.append((committed[root] - t0) * 1000)  # ms

    if not proof_delays:
        print('No complete TIMING entries found. Make sure the binary was rebuilt '
              'and the benchmark was run after adding the log statements.')
        sys.exit(1)

    proof_delays  = np.array(sorted(proof_delays))
    commit_delays = np.array(sorted(commit_delays))

    print(f'Batches with complete timing: {len(proof_delays)}')
    print(f'Proof delay   — mean: {mean(proof_delays):.1f} ms  median: {median(proof_delays):.1f} ms')
    print(f'Commit delay  — mean: {mean(commit_delays):.1f} ms  median: {median(commit_delays):.1f} ms')

    # ── plots ─────────────────────────────────────────────────────────────────
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    def cdf(ax, data, label, color):
        y = np.arange(1, len(data) + 1) / len(data)
        ax.plot(data, y, color=color, linewidth=1.5, label=label)
        ax.axvline(np.median(data), color=color, linestyle='--', linewidth=1,
                   label=f'median {np.median(data):.0f} ms')

    # Plot 1: proof delay CDF
    cdf(axes[0], proof_delays, 'Proof delay', 'steelblue')
    axes[0].set_xlabel('Delay (ms)')
    axes[0].set_ylabel('CDF')
    axes[0].set_title('Time: block received → FullAvailabilityProof')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    # Plot 2: commit delay CDF
    cdf(axes[1], commit_delays, 'Commit delay', 'darkorange')
    axes[1].set_xlabel('Delay (ms)')
    axes[1].set_ylabel('CDF')
    axes[1].set_title('Time: block received → committed')
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    # Plot 3: scatter proof vs commit delay
    axes[2].scatter(proof_delays, commit_delays, alpha=0.4, s=10, color='purple')
    lim = max(proof_delays.max(), commit_delays.max()) * 1.05
    axes[2].plot([0, lim], [0, lim], 'k--', linewidth=0.8, label='y = x')
    axes[2].set_xlabel('Proof delay (ms)')
    axes[2].set_ylabel('Commit delay (ms)')
    axes[2].set_title('Proof delay vs commit delay per batch')
    axes[2].legend()
    axes[2].grid(True, alpha=0.3)

    plt.tight_layout()
    out = logs_dir / 'timing.png'
    plt.savefig(out, dpi=150)
    print(f'Plot saved to {out}')
    plt.show()


if __name__ == '__main__':
    main()
