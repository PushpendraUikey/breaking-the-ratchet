#!/usr/bin/env python3
"""plot.py — plot Bob's CPU/memory from capture.sh CSVs.

Two modes:

  # single run: CPU & memory vs time (one capture)
  python3 plot.py stats_flood_1000000.csv [out.png]

  # sweep: peak CPU & peak memory vs counter gap, across many captures
  python3 plot.py --sweep [out.png] [dir]

Sweep reads every `stats_<label>_<N>.csv` in `dir` (default: this script's
folder), takes each run's peak CPU and peak memory, and plots them against the
trailing number `N` (the counter gap for --gap runs, or K*N for --flood runs)
on a log x-axis. One line per `<label>` prefix (e.g. single, flood).

CSV columns: t,cpu_pct,mem   (mem like "12.3MiB / 1.9GiB")
"""
import os
import re
import sys
import glob
import matplotlib.pyplot as plt


def parse_mem(s):
    # take the "used" side of "12.3MiB / 1.9GiB" and normalise to MiB
    used = s.split("/")[0].strip()
    num = float("".join(c for c in used if (c.isdigit() or c == ".")))
    if "GiB" in used:
        num *= 1024
    return num


def read_csv(path):
    """Return (cpu_list, mem_list_MiB) from a capture CSV."""
    cpu, mem = [], []
    with open(path) as f:
        next(f)  # header
        for line in f:
            line = line.strip()
            if not line:
                continue
            cols = line.split(",", 2)
            cpu.append(float(cols[1].rstrip("%")))
            mem.append(parse_mem(cols[2]))
    return cpu, mem


# ---------------------------------------------------------------------------
# Single-run mode: CPU and memory vs time.
# ---------------------------------------------------------------------------
def plot_single(path, out):
    cpu, mem = read_csv(path)
    t = list(range(len(cpu)))  # sample index; capture samples ~1-2s apart

    fig, ax1 = plt.subplots()
    ax1.plot(t, cpu, color="tab:red", label="CPU %")
    ax1.set_xlabel("sample")
    ax1.set_ylabel("CPU %", color="tab:red")

    ax2 = ax1.twinx()
    ax2.plot(t, mem, color="tab:blue", label="Mem (MiB)")
    ax2.set_ylabel("Mem (MiB)", color="tab:blue")

    fig.tight_layout()
    fig.savefig(out, dpi=120)
    print(f"wrote {out}")


# ---------------------------------------------------------------------------
# Sweep mode: peak CPU / peak memory vs counter gap (one point per capture).
# ---------------------------------------------------------------------------
def collect_sweep(directory):
    """Return {label: [(gap, peak_cpu, peak_mem_MiB), ...]} sorted by gap."""
    pat = re.compile(r"stats_([A-Za-z]+)_(\d+)\.csv$")
    series = {}
    for path in glob.glob(os.path.join(directory, "stats_*.csv")):
        m = pat.search(os.path.basename(path))
        if not m:
            continue
        label, gap = m.group(1), int(m.group(2))
        cpu, mem = read_csv(path)
        if not cpu:
            continue
        series.setdefault(label, []).append((gap, max(cpu), max(mem)))
    for label in series:
        series[label].sort(key=lambda r: r[0])
    return series


def plot_sweep(out, directory):
    series = collect_sweep(directory)
    if not series:
        sys.exit(f"no stats_<label>_<N>.csv files found in {directory}")

    fig, ax1 = plt.subplots()
    ax2 = ax1.twinx()
    for label, rows in sorted(series.items()):
        gaps = [r[0] for r in rows]
        cpus = [r[1] for r in rows]
        mems = [r[2] for r in rows]
        ax2.plot(gaps, mems, "o-", color="tab:blue",
                 label=f"{label} peak mem")
        ax1.plot(gaps, cpus, "s--", color="tab:red",
                 label=f"{label} peak CPU")
        for g, mm in zip(gaps, mems):
            ax2.annotate(f"{mm/1024:.2f}GiB" if mm >= 1024 else f"{mm:.0f}MiB",
                         (g, mm), textcoords="offset points", xytext=(0, 6),
                         ha="center", fontsize=7, color="tab:blue")

    ax1.set_xscale("log")
    ax1.set_xlabel("counter gap forced  (K*N; log scale)")
    ax1.set_ylabel("peak CPU %", color="tab:red")
    ax2.set_ylabel("peak memory (MiB)", color="tab:blue")
    ax1.set_title("Attack 0: Bob resource use vs forced counter gap")
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    print(f"wrote {out}  ({sum(len(v) for v in series.values())} points)")


def main():
    args = sys.argv[1:]
    here = os.path.dirname(os.path.abspath(__file__))

    if args and args[0] == "--sweep":
        out = args[1] if len(args) > 1 else os.path.join(here, "sweep.png")
        directory = args[2] if len(args) > 2 else here
        plot_sweep(out, directory)
        return

    if not args:
        sys.exit("usage: plot.py stats.csv [out.png]  |  plot.py --sweep [out.png] [dir]")
    path = args[0]
    out = args[1] if len(args) > 1 else "stats.png"
    plot_single(path, out)


if __name__ == "__main__":
    main()
