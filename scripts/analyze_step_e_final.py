from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = (
    PROJECT_ROOT
    / "results"
    / "reference"
    / "benchmark.csv"
)
DEFAULT_OUTPUT_DIR = (
    PROJECT_ROOT
    / "results"
    / "local"
    / "analysis"
)

BENIGN_ORDER = (
    "C0_baseline",
    "C1_secure_passport_v1",
    "C2_extended_secure_passport",
    "C3_extended_plus_per_hop_security",
)


def percentile(
    values: list[float],
    q: float,
) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]

    position = (
        len(ordered) - 1
    ) * q
    lower = math.floor(position)
    upper = math.ceil(position)

    if lower == upper:
        return ordered[lower]

    weight = position - lower

    return (
        ordered[lower] * (1 - weight)
        + ordered[upper] * weight
    )


def summarize(
    values: list[float],
) -> dict[str, float]:
    return {
        "mean": statistics.fmean(values),
        "median": statistics.median(
            values
        ),
        "stdev": (
            statistics.stdev(values)
            if len(values) > 1
            else 0.0
        ),
        "iqr": (
            percentile(values, 0.75)
            - percentile(values, 0.25)
        ),
        "p95": percentile(
            values,
            0.95,
        ),
        "min": min(values),
        "max": max(values),
    }


def pct_change(
    value: float,
    baseline: float,
) -> float:
    if baseline == 0:
        return 0.0
    return (
        (value - baseline)
        / baseline
        * 100.0
    )


def bool_value(value: str) -> bool:
    return (
        value.strip().lower()
        == "true"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
    )
    args = parser.parse_args()

    args.output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    with args.input.open(
        encoding="utf-8",
        newline="",
    ) as handle:
        rows = list(
            csv.DictReader(handle)
        )

    benign = [
        row
        for row in rows
        if row["scenario"] == "benign"
    ]

    grouped: dict[
        str,
        list[dict[str, str]],
    ] = defaultdict(list)

    for row in benign:
        grouped[
            row["configuration"]
        ].append(row)

    baseline_latency = statistics.median(
        [
            float(
                row[
                    "local_security_pipeline_latency_ms"
                ]
            )
            for row in grouped[
                "C0_baseline"
            ]
        ]
    )

    baseline_size = statistics.median(
        [
            float(
                row[
                    "serialized_benchmark_payload_size_bytes"
                ]
            )
            for row in grouped[
                "C0_baseline"
            ]
        ]
    )

    performance: list[
        dict[str, Any]
    ] = []

    for configuration in BENIGN_ORDER:
        group = grouped[
            configuration
        ]

        latency = summarize(
            [
                float(
                    row[
                        "local_security_pipeline_latency_ms"
                    ]
                )
                for row in group
            ]
        )

        signing = summarize(
            [
                float(
                    row[
                        "signing_time_ms"
                    ]
                )
                for row in group
            ]
        )

        verification = summarize(
            [
                float(
                    row[
                        "verification_time_ms"
                    ]
                )
                for row in group
            ]
        )

        size = summarize(
            [
                float(
                    row[
                        "serialized_benchmark_payload_size_bytes"
                    ]
                )
                for row in group
            ]
        )

        performance.append(
            {
                "configuration": configuration,
                "runs": len(group),
                "latency_mean_ms": latency[
                    "mean"
                ],
                "latency_median_ms": latency[
                    "median"
                ],
                "latency_stdev_ms": latency[
                    "stdev"
                ],
                "latency_iqr_ms": latency[
                    "iqr"
                ],
                "latency_p95_ms": latency[
                    "p95"
                ],
                "signing_mean_ms": signing[
                    "mean"
                ],
                "signing_median_ms": signing[
                    "median"
                ],
                "verification_mean_ms": (
                    verification["mean"]
                ),
                "verification_median_ms": (
                    verification["median"]
                ),
                "serialized_payload_mean_bytes": (
                    size["mean"]
                ),
                "serialized_payload_median_bytes": (
                    size["median"]
                ),
                "latency_overhead_percent_vs_c0": (
                    pct_change(
                        latency["median"],
                        baseline_latency,
                    )
                ),
                "serialized_payload_size_increase_percent_vs_c0": (
                    pct_change(
                        size["median"],
                        baseline_size,
                    )
                ),
            }
        )

    attacks = [
        row
        for row in rows
        if row["scenario"] != "benign"
    ]

    attack_groups: dict[
        str,
        list[dict[str, str]],
    ] = defaultdict(list)

    for row in attacks:
        attack_groups[
            row["scenario"]
        ].append(row)

    attack_summary: list[
        dict[str, Any]
    ] = []

    for scenario in sorted(
        attack_groups
    ):
        group = attack_groups[
            scenario
        ]
        rejected = [
            row
            for row in group
            if not bool_value(
                row["accepted"]
            )
        ]

        reasons = Counter(
            row["rejection_reason"]
            for row in rejected
        )
        layers = Counter(
            row["detection_layer"]
            for row in rejected
        )

        attack_summary.append(
            {
                "scenario": scenario,
                "runs": len(group),
                "rejected": len(
                    rejected
                ),
                "accepted": (
                    len(group)
                    - len(rejected)
                ),
                "attack_detection_rate_percent": (
                    len(rejected)
                    / len(group)
                    * 100.0
                ),
                "dominant_rejection_reason": (
                    reasons.most_common(
                        1
                    )[0][0]
                    if reasons
                    else ""
                ),
                "dominant_detection_layer": (
                    layers.most_common(
                        1
                    )[0][0]
                    if layers
                    else ""
                ),
            }
        )

    false_rejections = sum(
        not bool_value(
            row["accepted"]
        )
        for row in benign
    )

    detected_attacks = sum(
        not bool_value(
            row["accepted"]
        )
        for row in attacks
    )

    quality = {
        "benign_runs": len(benign),
        "false_rejections": (
            false_rejections
        ),
        "false_rejection_rate_percent": (
            false_rejections
            / len(benign)
            * 100.0
        ),
        "attack_runs": len(attacks),
        "detected_attacks": (
            detected_attacks
        ),
        "overall_attack_detection_rate_percent": (
            detected_attacks
            / len(attacks)
            * 100.0
        ),
        "scope_widening_policy_gap": (
            "Not part of the 5-condition benchmark; "
            "documented separately by Step D."
        ),
    }

    def write_csv(
        path: Path,
        values: list[dict[str, Any]],
    ) -> None:
        with path.open(
            "w",
            encoding="utf-8",
            newline="",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=list(
                    values[0].keys()
                ),
            )
            writer.writeheader()
            writer.writerows(values)

    write_csv(
        args.output_dir
        / "table_1_corrected_performance.csv",
        performance,
    )

    write_csv(
        args.output_dir
        / "table_2_corrected_attack_detection.csv",
        attack_summary,
    )

    (
        args.output_dir
        / "table_3_corrected_quality_metrics.json"
    ).write_text(
        json.dumps(
            quality,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    report = {
        "input_rows": len(rows),
        "benign_configurations": len(
            performance
        ),
        "attack_scenarios": len(
            attack_summary
        ),
        "latency_scope": (
            "local_security_pipeline_only"
        ),
        "size_scope": (
            "serialized_local_benchmark_payload_"
            "not_http_wire_bytes"
        ),
        "overall_attack_detection_rate_percent": (
            quality[
                "overall_attack_detection_rate_percent"
            ]
        ),
        "false_rejection_rate_percent": (
            quality[
                "false_rejection_rate_percent"
            ]
        ),
        "warning": (
            "Performance comparisons use benign "
            "conditions only. Replay scenarios "
            "involve multi-attempt logic and are "
            "not used for latency-overhead claims."
        ),
    }

    (
        args.output_dir
        / "step_e_analysis_report.json"
    ).write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    print(
        f"Input rows: {len(rows)}"
    )
    print(
        "Overall attack detection rate: "
        f"{quality['overall_attack_detection_rate_percent']:.2f}%"
    )
    print(
        "False rejection rate: "
        f"{quality['false_rejection_rate_percent']:.2f}%"
    )
    print(
        f"Output: {args.output_dir}"
    )


if __name__ == "__main__":
    main()
