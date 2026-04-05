import os
from datetime import datetime
from glob import glob
from os.path import join
from re import findall
from statistics import mean, stdev

import matplotlib.pyplot as plt

from benchmark.utils import PathMaker


class GraphMetrics:
    """
    Parses TIMING log entries emitted by nodes to compute per-phase latencies:

      BatchCert latency  — from batch_created (batch sealed by the author) to
                           availability_proof (quorum of votes assembled into a
                           BatchCertificate for that batch root).

      Block Commit latency — from block_received (block passes all checks and
                             enters the pipeline) to block_committed (block is
                             finalised and delivered to the application layer).
    """

    def __init__(self, nodes):
        assert isinstance(nodes, list)
        assert all(isinstance(x, str) for x in nodes)

        # cert_latency_ms values pre-computed by the node (aggregator receipt → quorum).
        cert_latencies: list = []       # int (ms)

        # Dicts mapping root -> earliest timestamp seen across all node logs.
        batch_proposed: dict = {}       # root -> float (posix seconds)
        batch_committed: dict = {}      # root -> float

        for log in nodes:
            # METRIC cert_latency_ms=<ms> root=<digest>
            for ms, _ in findall(
                r'METRIC cert_latency_ms=(\d+) root=(\S+)', log
            ):
                cert_latencies.append(int(ms))

            # TIMING batch_proposed round=<n> root=<digest>
            for t, root in findall(
                r'\[(.*Z).*TIMING batch_proposed round=\d+ root=(\S+)', log
            ):
                ts = self._to_posix(t)
                if root not in batch_proposed or batch_proposed[root] > ts:
                    batch_proposed[root] = ts

            # TIMING batch_committed round=<n> root=<digest>
            for t, root in findall(
                r'\[(.*Z).*TIMING batch_committed round=\d+ root=(\S+)', log
            ):
                ts = self._to_posix(t)
                if root not in batch_committed or batch_committed[root] > ts:
                    batch_committed[root] = ts

        self.cert_latencies = cert_latencies
        self.batch_proposed = batch_proposed
        self.batch_committed = batch_committed

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _to_posix(self, string):
        x = datetime.fromisoformat(string.replace('Z', '+00:00'))
        return datetime.timestamp(x)


    # ------------------------------------------------------------------
    # Metric computations
    # ------------------------------------------------------------------

    def _batch_cert_series(self):
        """
        Return (index, latency_ms) pairs in arrival order.
        Latency is pre-computed by the node (aggregator receipt → quorum).
        """
        latencies = self.cert_latencies
        return list(range(len(latencies))), list(latencies)

    def _block_commit_series(self):
        """
        Return (t_s, latency_ms) pairs sorted by commit time, where t_s is
        seconds elapsed since the first batch_committed event.
        """
        pairs = [
            (self.batch_committed[root],
             (self.batch_committed[root] - self.batch_proposed[root]) * 1_000)
            for root in self.batch_committed
            if root in self.batch_proposed
        ]
        pairs.sort(key=lambda x: x[0])
        if not pairs:
            return [], []
        t0 = pairs[0][0]
        return [t - t0 for t, _ in pairs], [lat for _, lat in pairs]

    def batch_cert_latency_ms(self):
        """Returns (mean_ms, stdev_ms, sample_count)."""
        _, latencies = self._batch_cert_series()
        if not latencies:
            return None, None, 0
        mean_ms = mean(latencies)
        std_ms = stdev(latencies) if len(latencies) > 1 else 0.0
        return mean_ms, std_ms, len(latencies)

    def block_commit_latency_ms(self):
        """Returns (mean_ms, stdev_ms, sample_count)."""
        _, latencies = self._block_commit_series()
        if not latencies:
            return None, None, 0
        mean_ms = mean(latencies)
        std_ms = stdev(latencies) if len(latencies) > 1 else 0.0
        return mean_ms, std_ms, len(latencies)

    # ------------------------------------------------------------------
    # Plotting
    # ------------------------------------------------------------------

    def plot(self, bins=100):
        """
        Produce a single figure with two histogram subplots saved to the
        plots directory:

          plots/latency_metrics.{pdf,png}

        Each subplot shows the latency distribution as a histogram with a
        dashed red line marking the median (p50).
        """
        if not os.path.exists(PathMaker.plots_path()):
            os.makedirs(PathMaker.plots_path())

        _, bc_latencies = self._batch_cert_series()
        _, bl_latencies = self._block_commit_series()

        if not bc_latencies and not bl_latencies:
            print('[graph_metrics] No data found, skipping plot.')
            return

        fig, axes = plt.subplots(1, 2, figsize=(10, 4))
        fig.suptitle('HotStuff mempool latency metrics', fontweight='bold')

        self._plot_histogram(
            ax=axes[0],
            latencies=bc_latencies,
            title='BatchCert latency\n(sealed \u2192 quorum)',
            bins=bins,
        )
        self._plot_histogram(
            ax=axes[1],
            latencies=bl_latencies,
            title='Block commit latency\n(proposed \u2192 committed)',
            bins=bins,
        )

        fig.tight_layout()
        for ext in ['pdf', 'png']:
            fig.savefig(PathMaker.plot_file('latency_metrics', ext), bbox_inches='tight')
        plt.close(fig)

    def _plot_histogram(self, ax, latencies, title, bins):
        if not latencies:
            ax.set_title(title)
            ax.text(0.5, 0.5, 'No data', transform=ax.transAxes,
                    ha='center', va='center')
            return

        sorted_lat = sorted(latencies)
        p99 = sorted_lat[int(len(sorted_lat) * 0.99)]

        ax.hist(latencies, bins=bins, color='tab:green', edgecolor='none')
        ax.axvline(p99, color='red', linestyle='dashed', linewidth=1.5,
                   label=f'p99={p99:.0f}ms')

        ax.set_title(title)
        ax.set_xlabel('ms')
        ax.set_ylabel('count')
        ax.set_xlim(left=0, right=p99 * 1.05)
        ax.set_ylim(bottom=0)
        ax.legend()

    # ------------------------------------------------------------------
    # Text summary
    # ------------------------------------------------------------------

    def result(self):
        bc_mean, bc_std, bc_n = self.batch_cert_latency_ms()
        bl_mean, bl_std, bl_n = self.block_commit_latency_ms()

        def _fmt(mean_ms, std_ms, n):
            if mean_ms is None:
                return 'N/A (no samples)'
            return f'{round(mean_ms):,} ms  (+/- {round(std_ms):,} ms,  n={n:,})'

        return (
            '\n'
            '-----------------------------------------\n'
            ' GRAPH METRICS (latency breakdown):\n'
            '-----------------------------------------\n'
            f' BatchCert latency:    {_fmt(bc_mean, bc_std, bc_n)}\n'
            f' Block Commit latency: {_fmt(bl_mean, bl_std, bl_n)}\n'
            '-----------------------------------------\n'
        )

    def print(self):
        print(self.result())

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def process(cls, directory=None):
        """
        Load all node-*.log files from *directory* (defaults to the standard
        logs path) and return a ready-to-use GraphMetrics instance.
        """
        if directory is None:
            directory = PathMaker.logs_path()
        nodes = []
        for filename in sorted(glob(join(directory, 'node-*.log'))):
            with open(filename, 'r') as f:
                nodes.append(f.read())
        return cls(nodes)


if __name__ == '__main__':
    m = GraphMetrics.process()
    m.print()
    m.plot()
