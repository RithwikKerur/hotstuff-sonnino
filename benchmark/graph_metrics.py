#!/usr/bin/env python3
"""
Parse METRIC log lines from node logs and produce two graphs:
  1. BatchCert latency distribution  (ms from batch sealed → quorum reached)
  2. FAP latency distribution        (ms from batch sealed → all N nodes voted)
  3. Block commit latency            (ms from batch proposed → batch committed)

Usage:
    python3 graph_metrics.py [logs_dir]   (default: ./logs)
"""

import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ── optional matplotlib ────────────────────────────────────────────────────────
try:
    import matplotlib.pyplot as plt
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("matplotlib not found – printing stats only (pip install matplotlib to enable graphs)")

# ── regex patterns ─────────────────────────────────────────────────────────────
TS_PAT      = re.compile(r'\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)Z')
CERT_PAT    = re.compile(r'METRIC cert_latency_ms=(\d+) root=(\S+)')
FAP_PAT     = re.compile(r'METRIC fap_latency_ms=(\d+) root=(\S+)')
PROPOSED_PAT= re.compile(r'METRIC batch_proposed round=(\d+) root=(\S+)')
COMMITTED_PAT=re.compile(r'METRIC batch_committed round=(\d+) root=(\S+)')


def parse_ts(line):
    m = TS_PAT.search(line)
    if not m:
        return None
    return datetime.fromisoformat(m.group(1))


def parse_logs(logs_dir: Path):
    cert_latencies = []   # ms
    fap_latencies  = []   # ms

    # root → (proposed_ts, proposed_round)
    proposed = {}
    commit_latencies = []  # ms
    commit_rounds    = []  # delta rounds (always pipeline depth, sanity check)

    for log_file in sorted(logs_dir.glob("node-*.log")):
        with open(log_file) as f:
            for line in f:
                ts = parse_ts(line)

                m = CERT_PAT.search(line)
                if m:
                    cert_latencies.append(int(m.group(1)))
                    continue

                m = FAP_PAT.search(line)
                if m:
                    fap_latencies.append(int(m.group(1)))
                    continue

                m = PROPOSED_PAT.search(line)
                if m and ts:
                    root  = m.group(2)
                    round_ = int(m.group(1))
                    # first occurrence wins (a root appears on the proposing node only)
                    proposed.setdefault(root, (ts, round_))
                    continue

                m = COMMITTED_PAT.search(line)
                if m and ts:
                    root   = m.group(2)
                    c_round = int(m.group(1))
                    if root in proposed:
                        p_ts, p_round = proposed[root]
                        delta_ms = (ts - p_ts).total_seconds() * 1000
                        if delta_ms >= 0:
                            commit_latencies.append(delta_ms)
                            commit_rounds.append(c_round - p_round)

    return cert_latencies, fap_latencies, commit_latencies, commit_rounds


def print_stats(label, data):
    if not data:
        print(f"  {label}: no data")
        return
    data_s = sorted(data)
    n = len(data_s)
    print(f"  {label}: n={n}  min={data_s[0]:.1f}  "
          f"p50={data_s[n//2]:.1f}  "
          f"p95={data_s[int(n*0.95)]:.1f}  "
          f"p99={data_s[min(int(n*0.99), n-1)]:.1f}  "
          f"max={data_s[-1]:.1f}")


def plot(cert_ms, fap_ms, commit_ms, commit_rounds):
    fig, axes = plt.subplots(1, 3, figsize=(15, 4))
    fig.suptitle("HotStuff mempool latency metrics", fontsize=13)

    # ── 1. BatchCert latency ──────────────────────────────────────────────────
    ax = axes[0]
    if cert_ms:
        ax.hist(cert_ms, bins=40, color='steelblue', edgecolor='white')
        ax.axvline(sorted(cert_ms)[len(cert_ms)//2], color='red',
                   linestyle='--', label=f'p50={sorted(cert_ms)[len(cert_ms)//2]:.0f}ms')
        ax.legend()
    ax.set_title("BatchCert latency\n(sealed → quorum)")
    ax.set_xlabel("ms")
    ax.set_ylabel("count")

    # ── 2. FAP latency ────────────────────────────────────────────────────────
    ax = axes[1]
    if fap_ms:
        ax.hist(fap_ms, bins=40, color='darkorange', edgecolor='white')
        ax.axvline(sorted(fap_ms)[len(fap_ms)//2], color='red',
                   linestyle='--', label=f'p50={sorted(fap_ms)[len(fap_ms)//2]:.0f}ms')
        ax.legend()
    ax.set_title("FAP latency\n(sealed → all-N votes)")
    ax.set_xlabel("ms")
    ax.set_ylabel("count")

    # ── 3. Block commit latency ───────────────────────────────────────────────
    ax = axes[2]
    if commit_ms:
        ax.hist(commit_ms, bins=40, color='seagreen', edgecolor='white')
        ax.axvline(sorted(commit_ms)[len(commit_ms)//2], color='red',
                   linestyle='--', label=f'p50={sorted(commit_ms)[len(commit_ms)//2]:.0f}ms')
        ax.legend()
    ax.set_title("Block commit latency\n(proposed → committed)")
    ax.set_xlabel("ms")
    ax.set_ylabel("count")

    plt.tight_layout()
    out = Path("metrics.png")
    plt.savefig(out, dpi=150)
    print(f"\nSaved graph → {out}")
    plt.show()


def main():
    logs_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("logs")
    if not logs_dir.is_dir():
        print(f"Logs directory not found: {logs_dir}")
        sys.exit(1)

    print(f"Parsing {logs_dir} ...")
    cert_ms, fap_ms, commit_ms, commit_rounds = parse_logs(logs_dir)

    print("\n── Summary ──────────────────────────────────────────────────")
    print_stats("BatchCert latency (ms)", cert_ms)
    print_stats("FAP latency       (ms)", fap_ms)
    print_stats("Commit latency    (ms)", commit_ms)
    if commit_rounds:
        from collections import Counter
        rc = Counter(commit_rounds)
        print(f"  Commit round deltas: {dict(sorted(rc.items()))}")

    if HAS_MPL:
        plot(cert_ms, fap_ms, commit_ms, commit_rounds)


if __name__ == "__main__":
    main()
