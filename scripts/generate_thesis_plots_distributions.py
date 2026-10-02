from __future__ import annotations

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INPUT_CSV = (
    PROJECT_ROOT
    / "results"
    / "reference"
    / "benchmark.csv"
)
OUTPUT_DIR = PROJECT_ROOT / "results" / "local" / "figures"

CONFIGURATION_ORDER = (
    "C0_baseline",
    "C1_secure_passport_v1",
    "C2_extended_secure_passport",
    "C3_extended_plus_per_hop_security",
)

DISPLAY_LABELS = {
    "C0_baseline": "C0",
    "C1_secure_passport_v1": "C1",
    "C2_extended_secure_passport": "C2",
    "C3_extended_plus_per_hop_security": "C3",
}


def load_benign_measurements() -> dict[str, list[dict[str, str]]]:
    if not INPUT_CSV.exists():
        raise FileNotFoundError(f"Benchmark CSV not found: {INPUT_CSV}")

    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)

    with INPUT_CSV.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["scenario"] == "benign":
                grouped[row["configuration"]].append(row)

    missing = [
        configuration
        for configuration in CONFIGURATION_ORDER
        if not grouped[configuration]
    ]
    if missing:
        raise ValueError(
            "Missing benign benchmark observations for: "
            + ", ".join(missing)
        )

    counts = {
        configuration: len(grouped[configuration])
        for configuration in CONFIGURATION_ORDER
    }
    if len(set(counts.values())) != 1:
        raise ValueError(f"Unequal benign sample counts: {counts}")

    return grouped


def add_raw_points(
    ax: plt.Axes,
    datasets: list[list[float]],
    *,
    seed: int,
) -> None:
    rng = random.Random(seed)

    for position, values in enumerate(datasets, start=1):
        jittered_x = [
            position + rng.uniform(-0.10, 0.10)
            for _ in values
        ]
        ax.scatter(
            jittered_x,
            values,
            s=10,
            alpha=0.28,
            linewidths=0,
            zorder=2,
        )


def save_figure(fig: plt.Figure, stem: str) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(
        OUTPUT_DIR / f"{stem}.png",
        dpi=300,
        bbox_inches="tight",
    )
    fig.savefig(
        OUTPUT_DIR / f"{stem}.pdf",
        bbox_inches="tight",
    )
    plt.close(fig)


def create_latency_distribution(
    grouped: dict[str, list[dict[str, str]]],
) -> None:
    datasets = [
        [
            float(row["local_security_pipeline_latency_ms"])
            for row in grouped[configuration]
        ]
        for configuration in CONFIGURATION_ORDER
    ]
    labels = [
        DISPLAY_LABELS[configuration]
        for configuration in CONFIGURATION_ORDER
    ]

    fig, ax = plt.subplots(figsize=(8.4, 5.2))
    ax.boxplot(
        datasets,
        tick_labels=labels,
        showfliers=False,
        whis=1.5,
        widths=0.55,
        medianprops={"linewidth": 1.6},
    )
    add_raw_points(ax, datasets, seed=20260802)

    ax.set_xlabel("Configuration")
    ax.set_ylabel("Local security-processing latency (ms)")
    ax.set_yscale("log")
    ax.grid(axis="y", linewidth=0.5, alpha=0.35)

    save_figure(fig, "LatencyResults")


def create_payload_distribution(
    grouped: dict[str, list[dict[str, str]]],
) -> None:
    datasets = [
        [
            float(row["serialized_benchmark_payload_size_bytes"])
            for row in grouped[configuration]
        ]
        for configuration in CONFIGURATION_ORDER
    ]
    labels = [
        DISPLAY_LABELS[configuration]
        for configuration in CONFIGURATION_ORDER
    ]

    fig, ax = plt.subplots(figsize=(8.0, 5.0))
    ax.boxplot(
        datasets,
        tick_labels=labels,
        showfliers=False,
        whis=1.5,
        widths=0.55,
        medianprops={"linewidth": 1.6},
    )
    add_raw_points(ax, datasets, seed=20260803)

    ax.set_xlabel("Configuration")
    ax.set_ylabel("Serialized local benchmark payload size (bytes)")
    ax.set_ylim(bottom=0)
    ax.grid(axis="y", linewidth=0.5, alpha=0.35)

    save_figure(fig, "PayloadSizeResults")


def main() -> None:
    global INPUT_CSV, OUTPUT_DIR
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=INPUT_CSV)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    args = parser.parse_args()
    INPUT_CSV, OUTPUT_DIR = args.input, args.output_dir
    grouped = load_benign_measurements()
    create_latency_distribution(grouped)
    create_payload_distribution(grouped)

    sample_count = len(grouped[CONFIGURATION_ORDER[0]])
    print(
        f"Distribution figures created in {OUTPUT_DIR} "
        f"from {sample_count} benign observations per configuration."
    )


if __name__ == "__main__":
    main()
