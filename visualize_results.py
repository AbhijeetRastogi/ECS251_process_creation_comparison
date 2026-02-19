#!/usr/bin/env python3
"""
visualize_results.py — Benchmark results visualizer
=====================================================

Reads the results.csv produced by benchmark.c and generates a set of
graphs that make the data easy to understand at a glance.

USAGE:
    python3 visualize_results.py results.csv
    python3 visualize_results.py results_20260209_215349/results.csv

OUTPUT:
    A new folder named graphs_YYYYMMDD_HHMMSS/ containing one PNG per graph
    plus a summary.txt that describes what each graph shows.

REQUIREMENTS:
    pip install matplotlib pandas numpy seaborn
"""

import sys
import os
import argparse
import datetime
import textwrap

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns


# =============================================================================
# Global style
# =============================================================================

# Colour palette — one consistent colour per method across all graphs so
# the reader can quickly identify fork/vfork/posix_spawn without reading labels
METHOD_COLORS = {
    "fork":         "#E74C3C",   # red   — powerful but heavy
    "vfork":        "#3498DB",   # blue  — fast but risky
    "posix_spawn":  "#2ECC71",   # green — safe and clean
}

# Page size display names
PAGE_LABELS = {
    "4KB": "4 KB (regular pages)",
    "2MB": "2 MB (huge pages)",
}

def apply_global_style():
    """Set matplotlib/seaborn defaults used across all graphs."""
    sns.set_theme(style="whitegrid", font_scale=1.05)
    plt.rcParams.update({
        "figure.dpi":        150,
        "savefig.dpi":       150,
        "savefig.bbox":      "tight",
        "font.family":       "DejaVu Sans",
        "axes.spines.top":   False,
        "axes.spines.right": False,
    })


# =============================================================================
# Data loading and validation
# =============================================================================

REQUIRED_COLUMNS = {
    "Memory_GB", "Page_Size", "Method",
    "Mean_ms", "StdDev_ms", "P99_ms", "Min_ms", "Max_ms",
}

EBPF_COLUMNS = {
    "PF_User", "PF_Kernel", "PF_Total",
    "TLB_Total", "TLB_RemoteShootdown", "TLB_LocalShootdown",
    "TLB_LocalMM", "TLB_RemoteIPI", "TLB_TaskSwitch",
}

def load_csv(path: str) -> tuple[pd.DataFrame, bool]:
    """
    Load the benchmark CSV and return (dataframe, has_ebpf).

    has_ebpf is True when the eBPF metric columns are present and non-zero.
    The benchmark writes zeros for those columns when eBPF was unavailable,
    so we check for actual non-zero values rather than just column presence.
    """
    if not os.path.isfile(path):
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)

    df = pd.read_csv(path, skipinitialspace=True)

    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        print(f"[ERROR] CSV is missing expected columns: {missing}")
        print(f"        Found columns: {list(df.columns)}")
        sys.exit(1)

    # Detect whether eBPF data is meaningful
    has_ebpf = (
        EBPF_COLUMNS.issubset(set(df.columns)) and
        df["TLB_Total"].sum() > 0
    )

    print(f"[INFO] Loaded {len(df)} rows from {path}")
    print(f"[INFO] eBPF metrics available: {has_ebpf}")
    print(f"[INFO] Methods  : {sorted(df['Method'].unique())}")
    print(f"[INFO] Memory   : {sorted(df['Memory_GB'].unique())} GB")
    print(f"[INFO] Page sizes: {sorted(df['Page_Size'].unique())}")

    return df, has_ebpf


# =============================================================================
# Helper — build a consistent legend
# =============================================================================

def method_legend(ax, methods):
    """Add a colour-coded method legend to an axes."""
    patches = [
        mpatches.Patch(color=METHOD_COLORS[m], label=m)
        for m in methods if m in METHOD_COLORS
    ]
    ax.legend(handles=patches, title="Method", framealpha=0.7)


# =============================================================================
# Graph 1 — Mean latency by method (grouped bar, one panel per memory size)
#
# PURPOSE:
#   The headline comparison. Shows fork's heavy cost vs vfork/posix_spawn
#   and how huge pages (2MB) reduce fork's latency compared to 4KB pages.
#   Grouped bars let you compare both the method effect and the page-size
#   effect side by side.
# =============================================================================

def graph_mean_latency(df: pd.DataFrame, out_dir: str):
    memory_sizes = sorted(df["Memory_GB"].unique())
    n_panels = len(memory_sizes)

    fig, axes = plt.subplots(1, n_panels, figsize=(7 * n_panels, 6),
                             sharey=False)
    if n_panels == 1:
        axes = [axes]

    fig.suptitle("Mean Process Creation Latency\nby Method and Page Size",
                 fontsize=14, fontweight="bold", y=1.02)

    for ax, mem_gb in zip(axes, memory_sizes):
        sub = df[df["Memory_GB"] == mem_gb]
        page_sizes = sorted(sub["Page_Size"].unique())
        methods    = sorted(sub["Method"].unique())

        n_groups = len(page_sizes)
        n_bars   = len(methods)
        bar_w    = 0.7 / n_bars
        x        = np.arange(n_groups)

        for i, method in enumerate(methods):
            mdf    = sub[sub["Method"] == method]
            values = [
                mdf[mdf["Page_Size"] == ps]["Mean_ms"].values[0]
                if len(mdf[mdf["Page_Size"] == ps]) > 0 else 0
                for ps in page_sizes
            ]
            errors = [
                mdf[mdf["Page_Size"] == ps]["StdDev_ms"].values[0]
                if len(mdf[mdf["Page_Size"] == ps]) > 0 else 0
                for ps in page_sizes
            ]
            offset = (i - n_bars / 2 + 0.5) * bar_w
            bars = ax.bar(x + offset, values, bar_w,
                          label=method,
                          color=METHOD_COLORS.get(method, "#888888"),
                          yerr=errors, capsize=4, alpha=0.9,
                          error_kw={"elinewidth": 1.2})

            # Value labels on bars
            for bar, val in zip(bars, values):
                if val > 0:
                    ax.text(bar.get_x() + bar.get_width() / 2,
                            bar.get_height() + max(errors) * 0.1,
                            f"{val:.2f}", ha="center", va="bottom",
                            fontsize=8)

        ax.set_title(f"{mem_gb} GB Parent Memory", fontsize=12)
        ax.set_xlabel("Page Size")
        ax.set_ylabel("Mean Latency (ms)")
        ax.set_xticks(x)
        ax.set_xticklabels([PAGE_LABELS.get(ps, ps) for ps in page_sizes])
        method_legend(ax, methods)

        # Annotation explaining error bars
        ax.annotate("Error bars = ±1 std dev",
                    xy=(0.98, 0.02), xycoords="axes fraction",
                    ha="right", fontsize=8, color="grey")

    plt.tight_layout()
    path = os.path.join(out_dir, "01_mean_latency.png")
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")
    return path


# =============================================================================
# Graph 2 — Latency distribution box plots
#
# PURPOSE:
#   Mean alone hides outliers. Box plots show the full spread —
#   median, quartiles, and outlier dots. This reveals whether a method
#   is consistently fast or has occasional slow spikes (high P99).
#   One panel per memory size; x-axis groups by page size within each method.
# =============================================================================

def graph_latency_boxplot(df: pd.DataFrame, out_dir: str):
    """
    Approximate box plots from the summary stats we have
    (we don't store raw iteration data in the CSV, only summary stats).
    We reconstruct a representative distribution using mean, stddev, min, max.
    """
    memory_sizes = sorted(df["Memory_GB"].unique())
    n_panels     = len(memory_sizes)

    fig, axes = plt.subplots(1, n_panels, figsize=(7 * n_panels, 6),
                             sharey=False)
    if n_panels == 1:
        axes = [axes]

    fig.suptitle("Latency Distribution (Min / Mean ± StdDev / P99 / Max)\n"
                 "by Method and Page Size",
                 fontsize=14, fontweight="bold", y=1.02)

    for ax, mem_gb in zip(axes, memory_sizes):
        sub     = df[df["Memory_GB"] == mem_gb]
        methods = sorted(sub["Method"].unique())
        pages   = sorted(sub["Page_Size"].unique())

        # Build a label and stats list for each (method, page) combination
        labels, means, stds, mins_, maxs_, p99s = [], [], [], [], [], []
        colors = []

        for method in methods:
            for ps in pages:
                row = sub[(sub["Method"] == method) & (sub["Page_Size"] == ps)]
                if row.empty:
                    continue
                labels.append(f"{method}\n{ps}")
                means.append(row["Mean_ms"].values[0])
                stds.append(row["StdDev_ms"].values[0])
                mins_.append(row["Min_ms"].values[0])
                maxs_.append(row["Max_ms"].values[0])
                p99s.append(row["P99_ms"].values[0])
                colors.append(METHOD_COLORS.get(method, "#888888"))

        x = np.arange(len(labels))

        # Draw range bar (min to max) as a thin line
        for i, (mn, mx, col) in enumerate(zip(mins_, maxs_, colors)):
            ax.plot([i, i], [mn, mx], color=col, linewidth=1.5,
                    alpha=0.4, zorder=1)

        # Draw mean ± stddev box
        for i, (m, s, col) in enumerate(zip(means, stds, colors)):
            ax.bar(i, 2 * s, bottom=m - s, width=0.4,
                   color=col, alpha=0.6, zorder=2)

        # Draw mean line
        ax.scatter(x, means, color=colors, zorder=4, s=60,
                   edgecolors="white", linewidths=0.8, label="Mean")

        # Draw P99 marker
        ax.scatter(x, p99s, color=colors, zorder=3, s=40,
                   marker="^", alpha=0.8, label="P99")

        ax.set_title(f"{mem_gb} GB Parent Memory", fontsize=12)
        ax.set_xlabel("Method / Page Size")
        ax.set_ylabel("Latency (ms)")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=9)
        method_legend(ax, methods)

        # Legend for markers
        mean_marker  = plt.Line2D([0], [0], marker="o", color="grey",
                                  linestyle="None", markersize=7, label="Mean")
        p99_marker   = plt.Line2D([0], [0], marker="^", color="grey",
                                  linestyle="None", markersize=7, label="P99")
        range_line   = plt.Line2D([0], [0], color="grey", linewidth=1.5,
                                  alpha=0.5, label="Min–Max range")
        ax.legend(handles=[mean_marker, p99_marker, range_line],
                  fontsize=8, loc="upper left")

    plt.tight_layout()
    path = os.path.join(out_dir, "02_latency_distribution.png")
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")
    return path


# =============================================================================
# Graph 3 — Huge page speedup ratio
#
# PURPOSE:
#   Directly answers "how much faster does huge pages make each method?"
#   A ratio of 1.0 means no change; 3.0 means huge pages made it 3× faster.
#   This should dramatically highlight fork's improvement while showing
#   vfork/posix_spawn barely change (they don't copy memory anyway).
# =============================================================================

def graph_hugepage_speedup(df: pd.DataFrame, out_dir: str):
    memory_sizes = sorted(df["Memory_GB"].unique())
    methods      = sorted(df["Method"].unique())

    fig, ax = plt.subplots(figsize=(9, 5))
    fig.suptitle("Huge Page Speedup Ratio vs Regular Pages\n"
                 "(ratio > 1 means huge pages are faster; higher = bigger gain)",
                 fontsize=13, fontweight="bold")

    bar_w   = 0.7 / len(methods)
    x       = np.arange(len(memory_sizes))
    has_data = False

    for i, method in enumerate(methods):
        ratios = []
        for mem_gb in memory_sizes:
            row_4kb = df[(df["Method"] == method) &
                         (df["Page_Size"] == "4KB") &
                         (df["Memory_GB"] == mem_gb)]
            row_2mb = df[(df["Method"] == method) &
                         (df["Page_Size"] == "2MB") &
                         (df["Memory_GB"] == mem_gb)]
            if row_4kb.empty or row_2mb.empty:
                ratios.append(0)
                continue
            v4 = row_4kb["Mean_ms"].values[0]
            v2 = row_2mb["Mean_ms"].values[0]
            ratios.append(v4 / v2 if v2 > 0 else 0)

        if any(r > 0 for r in ratios):
            has_data = True
            offset = (i - len(methods) / 2 + 0.5) * bar_w
            bars = ax.bar(x + offset, ratios, bar_w,
                          label=method,
                          color=METHOD_COLORS.get(method, "#888888"),
                          alpha=0.9)
            for bar, ratio in zip(bars, ratios):
                if ratio > 0:
                    ax.text(bar.get_x() + bar.get_width() / 2,
                            bar.get_height() + 0.02,
                            f"{ratio:.2f}×",
                            ha="center", va="bottom", fontsize=9)

    if has_data:
        ax.axhline(1.0, color="black", linewidth=1.0, linestyle="--",
                   label="No change (ratio = 1.0)")
        ax.set_xlabel("Parent Memory Size")
        ax.set_ylabel("Speedup Ratio  (4KB latency ÷ 2MB latency)")
        ax.set_xticks(x)
        ax.set_xticklabels([f"{m} GB" for m in memory_sizes])
        ax.legend(title="Method", framealpha=0.7)
        ax.annotate(
            "fork benefits most from huge pages because it copies more\n"
            "page table entries — huge pages means far fewer entries to copy.",
            xy=(0.98, 0.02), xycoords="axes fraction",
            ha="right", fontsize=8, color="grey",
            bbox=dict(boxstyle="round,pad=0.3", fc="white", alpha=0.6))
    else:
        ax.text(0.5, 0.5, "Insufficient data\n(need both 4KB and 2MB rows)",
                ha="center", va="center", transform=ax.transAxes, fontsize=12)

    plt.tight_layout()
    path = os.path.join(out_dir, "03_hugepage_speedup.png")
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")
    return path


# =============================================================================
# Graph 4 — Memory scaling (latency vs memory size, line chart)
#
# PURPOSE:
#   Shows how each method scales as the parent process gets larger.
#   fork should grow linearly — double the memory, roughly double the time.
#   vfork and posix_spawn should be flat — they don't copy memory so
#   parent size shouldn't matter. Any deviation is interesting.
# =============================================================================

def graph_memory_scaling(df: pd.DataFrame, out_dir: str):
    page_sizes = sorted(df["Page_Size"].unique())
    methods    = sorted(df["Method"].unique())

    fig, axes = plt.subplots(1, len(page_sizes),
                             figsize=(7 * len(page_sizes), 5),
                             sharey=False)
    if len(page_sizes) == 1:
        axes = [axes]

    fig.suptitle("Latency Scaling with Parent Memory Size\n"
                 "by Method and Page Type",
                 fontsize=14, fontweight="bold", y=1.02)

    for ax, ps in zip(axes, page_sizes):
        sub    = df[df["Page_Size"] == ps]
        x_vals = sorted(sub["Memory_GB"].unique())

        for method in methods:
            mdf    = sub[sub["Method"] == method].sort_values("Memory_GB")
            if mdf.empty:
                continue
            y = mdf["Mean_ms"].values
            e = mdf["StdDev_ms"].values
            x = mdf["Memory_GB"].values

            ax.plot(x, y, marker="o", linewidth=2,
                    color=METHOD_COLORS.get(method, "#888888"),
                    label=method)
            ax.fill_between(x, y - e, y + e,
                            color=METHOD_COLORS.get(method, "#888888"),
                            alpha=0.15)
            # P99 as dotted line
            ax.plot(x, mdf["P99_ms"].values,
                    linestyle=":", linewidth=1.2,
                    color=METHOD_COLORS.get(method, "#888888"),
                    alpha=0.7)

        ax.set_title(f"Page Size: {PAGE_LABELS.get(ps, ps)}", fontsize=12)
        ax.set_xlabel("Parent Memory Size (GB)")
        ax.set_ylabel("Latency (ms)")
        ax.set_xticks(x_vals)
        ax.set_xticklabels([f"{m} GB" for m in x_vals])
        method_legend(ax, methods)
        ax.annotate("Shaded band = ±1 std dev | Dotted line = P99",
                    xy=(0.98, 0.02), xycoords="axes fraction",
                    ha="right", fontsize=8, color="grey")

    plt.tight_layout()
    path = os.path.join(out_dir, "04_memory_scaling.png")
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")
    return path


# =============================================================================
# Graph 5 — Page fault comparison (eBPF)
#
# PURPOSE:
#   Shows the actual kernel work happening during each method.
#   fork will have many kernel page faults (copying page tables).
#   vfork and posix_spawn should have near zero.
#   Huge pages should reduce fork's count because there are far fewer
#   pages to process (512× fewer entries for the same memory footprint).
# =============================================================================

def graph_page_faults(df: pd.DataFrame, out_dir: str):
    memory_sizes = sorted(df["Memory_GB"].unique())
    methods      = sorted(df["Method"].unique())
    page_sizes   = sorted(df["Page_Size"].unique())

    fig, axes = plt.subplots(len(memory_sizes), len(page_sizes),
                             figsize=(7 * len(page_sizes), 5 * len(memory_sizes)),
                             squeeze=False)

    fig.suptitle("Average Kernel Page Faults Per Iteration\n"
                 "(eBPF measured — kernel faults = page table copy work inside fork)",
                 fontsize=13, fontweight="bold", y=1.01)

    for row_i, mem_gb in enumerate(memory_sizes):
        for col_i, ps in enumerate(page_sizes):
            ax  = axes[row_i][col_i]
            sub = df[(df["Memory_GB"] == mem_gb) & (df["Page_Size"] == ps)]

            if sub.empty:
                ax.text(0.5, 0.5, "No data", ha="center", va="center",
                        transform=ax.transAxes)
                continue

            method_names  = sub["Method"].values
            kernel_faults = sub["PF_Kernel"].values
            user_faults   = sub["PF_User"].values
            colors        = [METHOD_COLORS.get(m, "#888") for m in method_names]

            x = np.arange(len(method_names))
            ax.bar(x, kernel_faults, color=colors, alpha=0.9,
                   label="Kernel faults")
            ax.bar(x, user_faults, bottom=kernel_faults,
                   color=colors, alpha=0.4, hatch="//",
                   label="User faults (CoW copies)")

            for xi, (kf, uf) in enumerate(zip(kernel_faults, user_faults)):
                total = kf + uf
                if total > 0:
                    ax.text(xi, total + total * 0.02, f"{total:.0f}",
                            ha="center", va="bottom", fontsize=9)

            ax.set_title(f"{mem_gb} GB | {PAGE_LABELS.get(ps, ps)}", fontsize=11)
            ax.set_ylabel("Avg page faults per iteration")
            ax.set_xticks(x)
            ax.set_xticklabels(method_names)

            # Only show legend on first panel
            if row_i == 0 and col_i == 0:
                solid  = mpatches.Patch(color="grey", alpha=0.9,
                                        label="Kernel page faults")
                hatch  = mpatches.Patch(color="grey", alpha=0.4,
                                        hatch="//", label="User page faults (CoW)")
                ax.legend(handles=[solid, hatch], fontsize=8)

    plt.tight_layout()
    path = os.path.join(out_dir, "05_page_faults.png")
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")
    return path


# =============================================================================
# Graph 6 — TLB shootdown breakdown (eBPF)
#
# PURPOSE:
#   TLB shootdowns are the hidden cost of fork on multi-core systems.
#   This stacked bar shows exactly what kind of TLB flushing each method
#   causes. Remote shootdowns (the expensive cross-CPU ones) should be
#   high for fork and near-zero for vfork/posix_spawn.
#   Huge pages should dramatically reduce the remote shootdown count.
# =============================================================================

def graph_tlb_breakdown(df: pd.DataFrame, out_dir: str):
    memory_sizes = sorted(df["Memory_GB"].unique())
    page_sizes   = sorted(df["Page_Size"].unique())

    components = [
        ("TLB_RemoteShootdown", "#E74C3C", "Remote Shootdown (cross-CPU, expensive)"),
        ("TLB_LocalShootdown",  "#E67E22", "Local Shootdown"),
        ("TLB_LocalMM",         "#F1C40F", "Local MM Flush"),
        ("TLB_RemoteIPI",       "#9B59B6", "Remote IPI Sent"),
        ("TLB_TaskSwitch",      "#BDC3C7", "Task Switch (background noise)"),
    ]

    n_rows = len(memory_sizes)
    n_cols = len(page_sizes)

    # Use constrained_layout=True instead of tight_layout() to avoid the
    # blank-space rendering bug that occurs with squeeze=False grids.
    fig, axes = plt.subplots(n_rows, n_cols,
                             figsize=(7 * n_cols, 5 * n_rows),
                             constrained_layout=True,
                             squeeze=False)

    fig.suptitle("TLB Flush Breakdown Per Iteration\n"
                 "(eBPF measured — Remote Shootdown is the key fork overhead metric)",
                 fontsize=13, fontweight="bold")

    for row_i, mem_gb in enumerate(memory_sizes):
        for col_i, ps in enumerate(page_sizes):
            ax  = axes[row_i][col_i]
            sub = df[(df["Memory_GB"] == mem_gb) & (df["Page_Size"] == ps)]

            if sub.empty:
                ax.text(0.5, 0.5, "No data", ha="center", va="center",
                        transform=ax.transAxes)
                continue

            methods = sub["Method"].values
            x       = np.arange(len(methods))
            bottom  = np.zeros(len(methods))

            for col_name, color, label in components:
                if col_name not in sub.columns:
                    continue
                values = sub[col_name].values.astype(float)
                ax.bar(x, values, bottom=bottom, color=color,
                       alpha=0.85, label=label)
                bottom += values

            totals = sub["TLB_Total"].values if "TLB_Total" in sub.columns \
                     else bottom
            for xi, total in enumerate(totals):
                if total > 0:
                    ax.text(xi, total + total * 0.02, f"{total:.0f}",
                            ha="center", va="bottom", fontsize=9)

            ax.set_title(f"{mem_gb} GB | {PAGE_LABELS.get(ps, ps)}", fontsize=11)
            ax.set_ylabel("Avg TLB flush events per iteration")
            ax.set_xticks(x)
            ax.set_xticklabels(methods)

            if row_i == 0 and col_i == 0:
                ax.legend(fontsize=8, loc="upper right")

    path = os.path.join(out_dir, "06_tlb_breakdown.png")
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")
    return path


# =============================================================================
# Graph 7 — Correlation heatmap: latency vs eBPF metrics
#
# PURPOSE:
#   A correlation matrix showing which kernel events most strongly
#   predict latency. If TLB_RemoteShootdown correlates 0.98 with Mean_ms
#   that tells you remote shootdowns are almost entirely responsible for
#   fork's latency cost, not some other factor.
# =============================================================================

def graph_correlation_heatmap(df: pd.DataFrame, out_dir: str):
    numeric_cols = [
        "Mean_ms", "P99_ms",
        "PF_Kernel", "PF_User",
        "TLB_Total", "TLB_RemoteShootdown",
        "TLB_LocalShootdown", "TLB_LocalMM",
        "TLB_RemoteIPI", "TLB_TaskSwitch",
    ]

    available = [c for c in numeric_cols if c in df.columns]
    if len(available) < 4:
        print("  [SKIP] Not enough numeric columns for correlation heatmap.")
        return None

    corr = df[available].corr()

    # Rename columns to shorter display names for readability
    rename = {
        "Mean_ms":             "Mean latency",
        "P99_ms":              "P99 latency",
        "PF_Kernel":           "Kernel PF",
        "PF_User":             "User PF",
        "TLB_Total":           "TLB total",
        "TLB_RemoteShootdown": "Remote shootdown",
        "TLB_LocalShootdown":  "Local shootdown",
        "TLB_LocalMM":         "Local MM flush",
        "TLB_RemoteIPI":       "Remote IPI",
        "TLB_TaskSwitch":      "Task switch flush",
    }
    corr = corr.rename(columns=rename, index=rename)

    fig, ax = plt.subplots(figsize=(10, 8))
    fig.suptitle("Correlation Between Latency and Kernel Events\n"
                 "(1.0 = perfect correlation, 0 = no relationship, −1 = inverse)",
                 fontsize=13, fontweight="bold")

    mask = np.triu(np.ones_like(corr, dtype=bool), k=1)  # upper triangle
    sns.heatmap(corr, ax=ax, annot=True, fmt=".2f",
                cmap="RdYlGn", vmin=-1, vmax=1,
                linewidths=0.5, linecolor="white",
                mask=mask,
                annot_kws={"size": 9})

    ax.set_xticklabels(ax.get_xticklabels(), rotation=35, ha="right", fontsize=9)
    ax.set_yticklabels(ax.get_yticklabels(), rotation=0, fontsize=9)

    ax.annotate(
        "Strong correlations with 'Mean latency' show which kernel events\n"
        "most directly drive process creation cost.",
        xy=(0.01, -0.18), xycoords="axes fraction",
        ha="left", fontsize=8, color="grey")

    plt.tight_layout()
    path = os.path.join(out_dir, "07_correlation_heatmap.png")
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")
    return path


# =============================================================================
# Graph 8 — Summary comparison table (rendered as image)
#
# PURPOSE:
#   A clean table image showing every configuration's key numbers side by
#   side. Useful for reports or slides — one image captures the full picture.
# =============================================================================

def graph_summary_table(df: pd.DataFrame, out_dir: str, has_ebpf: bool):
    display_cols = ["Memory_GB", "Page_Size", "Method",
                    "Mean_ms", "StdDev_ms", "P99_ms"]
    if has_ebpf:
        display_cols += ["PF_Total", "TLB_Total", "TLB_RemoteShootdown"]

    available = [c for c in display_cols if c in df.columns]
    sub = df[available].copy().sort_values(
        ["Memory_GB", "Page_Size", "Method"]).reset_index(drop=True)

    # Round numerics
    for col in sub.select_dtypes(include="number").columns:
        sub[col] = sub[col].round(3)

    col_labels = {
        "Memory_GB":           "Memory\n(GB)",
        "Page_Size":           "Page\nSize",
        "Method":              "Method",
        "Mean_ms":             "Mean\n(ms)",
        "StdDev_ms":           "Std Dev\n(ms)",
        "P99_ms":              "P99\n(ms)",
        "PF_Total":            "Page\nFaults",
        "TLB_Total":           "TLB\nFlushes",
        "TLB_RemoteShootdown": "Remote\nShootdown",
    }

    headers = [col_labels.get(c, c) for c in available]

    fig_h = max(4, 0.4 * len(sub) + 2)
    fig, ax = plt.subplots(figsize=(max(10, 1.5 * len(available)), fig_h))
    ax.axis("off")
    fig.suptitle("Full Results Summary Table", fontsize=13,
                 fontweight="bold", y=0.98)

    tbl = ax.table(
        cellText=sub.values,
        colLabels=headers,
        cellLoc="center",
        loc="center",
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9)
    tbl.scale(1, 1.6)

    # Colour header row
    for j in range(len(headers)):
        tbl[0, j].set_facecolor("#2C3E50")
        tbl[0, j].set_text_props(color="white", fontweight="bold")

    # Zebra stripes and method colouring
    for i in range(1, len(sub) + 1):
        method = sub.iloc[i - 1]["Method"]
        base   = METHOD_COLORS.get(method, "#CCCCCC") + "33"  # 20% opacity hex
        for j in range(len(available)):
            tbl[i, j].set_facecolor(base)

    plt.tight_layout()
    path = os.path.join(out_dir, "08_summary_table.png")
    plt.savefig(path)
    plt.close()
    print(f"  Saved: {path}")
    return path


# =============================================================================
# Summary text file
# =============================================================================

def write_summary(df: pd.DataFrame, has_ebpf: bool,
                  out_dir: str, csv_path: str, saved_graphs: list):

    lines = []
    lines.append("BENCHMARK VISUALIZATION SUMMARY")
    lines.append("=" * 60)
    lines.append(f"Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Source CSV: {os.path.abspath(csv_path)}")
    lines.append(f"Output dir: {os.path.abspath(out_dir)}")
    lines.append(f"eBPF data : {'Yes' if has_ebpf else 'No (timing only)'}")
    lines.append("")
    lines.append("GRAPHS GENERATED")
    lines.append("-" * 40)

    descriptions = {
        "01_mean_latency.png":       "Mean latency grouped bar chart. "
                                     "Headline comparison of all three methods.",
        "02_latency_distribution.png": "Distribution plot showing mean, std dev, "
                                       "P99, min, and max for each configuration.",
        "03_hugepage_speedup.png":   "Speedup ratio chart showing how much faster "
                                     "2MB huge pages are vs 4KB regular pages.",
        "04_memory_scaling.png":     "Line chart showing how latency grows as parent "
                                     "memory doubles. fork scales linearly; "
                                     "vfork/posix_spawn stay flat.",
        "05_page_faults.png":        "(eBPF) Kernel and user page faults per "
                                     "iteration. Quantifies the CoW copy work "
                                     "triggered by fork.",
        "06_tlb_breakdown.png":      "(eBPF) TLB flush events broken down by type. "
                                     "Remote shootdowns are the key multi-core cost "
                                     "of fork.",
        "07_correlation_heatmap.png": "(eBPF) Correlation matrix between latency "
                                      "and kernel events. Shows which events most "
                                      "strongly predict latency.",
        "08_summary_table.png":      "Full results in table form. All configurations "
                                     "side by side — useful for reports or slides.",
    }

    for g in saved_graphs:
        name = os.path.basename(g)
        desc = descriptions.get(name, "")
        lines.append(f"  {name}")
        if desc:
            wrapped = textwrap.fill(desc, width=56, initial_indent="    ",
                                    subsequent_indent="    ")
            lines.append(wrapped)
        lines.append("")

    lines.append("KEY FINDINGS (from data)")
    lines.append("-" * 40)

    # Auto-generate a few key findings from the data
    try:
        fork_4kb_1gb = df[(df["Method"] == "fork") &
                          (df["Page_Size"] == "4KB") &
                          (df["Memory_GB"] == df["Memory_GB"].min())]
        vfork_4kb_1gb = df[(df["Method"] == "vfork") &
                           (df["Page_Size"] == "4KB") &
                           (df["Memory_GB"] == df["Memory_GB"].min())]
        if not fork_4kb_1gb.empty and not vfork_4kb_1gb.empty:
            ratio = (fork_4kb_1gb["Mean_ms"].values[0] /
                     vfork_4kb_1gb["Mean_ms"].values[0])
            lines.append(f"  - fork() is {ratio:.0f}× slower than vfork() "
                         f"at {df['Memory_GB'].min()} GB with 4KB pages.")

        fork_4kb = df[(df["Method"] == "fork") & (df["Page_Size"] == "4KB")]
        fork_2mb = df[(df["Method"] == "fork") & (df["Page_Size"] == "2MB")]
        if not fork_4kb.empty and not fork_2mb.empty:
            speedup = (fork_4kb["Mean_ms"].mean() / fork_2mb["Mean_ms"].mean())
            lines.append(f"  - Huge pages reduce fork() latency by "
                         f"{speedup:.1f}× on average.")

        if has_ebpf:
            fork_tlb = df[(df["Method"] == "fork") &
                          (df["Page_Size"] == "4KB")]["TLB_RemoteShootdown"].mean()
            vfork_tlb = df[(df["Method"] == "vfork") &
                           (df["Page_Size"] == "4KB")]["TLB_RemoteShootdown"].mean()
            if vfork_tlb > 0:
                lines.append(f"  - fork() causes {fork_tlb:.0f}× more remote TLB "
                             f"shootdowns than vfork() on 4KB pages.")
    except Exception:
        pass

    lines.append("")
    lines.append("HOW TO READ THE GRAPHS")
    lines.append("-" * 40)
    lines.append("  Red   = fork()")
    lines.append("  Blue  = vfork()")
    lines.append("  Green = posix_spawn()")
    lines.append("")
    lines.append("  Error bars / shaded bands = ±1 standard deviation")
    lines.append("  P99 = worst time experienced by 1% of iterations")
    lines.append("")

    summary_path = os.path.join(out_dir, "summary.txt")
    with open(summary_path, "w") as f:
        f.write("\n".join(lines))
    print(f"  Saved: {summary_path}")
    return summary_path


# =============================================================================
# Entry point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate graphs from benchmark.c CSV output.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python3 visualize_results.py results.csv
          python3 visualize_results.py results_20260209_215349/results.csv
        """)
    )
    parser.add_argument("csv_file", help="Path to the benchmark results CSV file")
    args = parser.parse_args()

    # ---- Load data ----
    df, has_ebpf = load_csv(args.csv_file)

    # ---- Create output directory ----
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir   = f"graphs_{timestamp}"
    os.makedirs(out_dir, exist_ok=True)
    print(f"\n[INFO] Saving graphs to: {out_dir}/\n")

    apply_global_style()

    # ---- Generate all graphs ----
    saved = []

    print("[1/8] Mean latency bar chart...")
    p = graph_mean_latency(df, out_dir)
    if p: saved.append(p)

    print("[2/8] Latency distribution plot...")
    p = graph_latency_boxplot(df, out_dir)
    if p: saved.append(p)

    print("[3/8] Huge page speedup ratio...")
    p = graph_hugepage_speedup(df, out_dir)
    if p: saved.append(p)

    print("[4/8] Memory scaling line chart...")
    p = graph_memory_scaling(df, out_dir)
    if p: saved.append(p)

    if has_ebpf:
        print("[5/8] Page fault comparison (eBPF)...")
        p = graph_page_faults(df, out_dir)
        if p: saved.append(p)

        print("[6/8] TLB breakdown (eBPF)...")
        p = graph_tlb_breakdown(df, out_dir)
        if p: saved.append(p)

        print("[7/8] Correlation heatmap (eBPF)...")
        p = graph_correlation_heatmap(df, out_dir)
        if p: saved.append(p)
    else:
        print("[5-7/8] Skipping eBPF graphs (no eBPF data in CSV).")

    print("[8/8] Summary table...")
    p = graph_summary_table(df, out_dir, has_ebpf)
    if p: saved.append(p)

    # ---- Write summary ----
    print("\n[INFO] Writing summary.txt...")
    write_summary(df, has_ebpf, out_dir, args.csv_file, saved)

    print(f"\n{'='*50}")
    print(f"Done. {len(saved)} graphs saved to: {out_dir}/")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()