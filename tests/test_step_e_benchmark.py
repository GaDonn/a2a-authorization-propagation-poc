from __future__ import annotations

from scripts.run_step_e_benchmark import (
    CONDITIONS,
    run_benchmark,
    validate_rows,
)


def test_step_e_has_nine_conditions() -> None:
    assert len(CONDITIONS) == 9


def test_step_e_has_four_benign_configurations() -> None:
    benign = [
        condition
        for condition in CONDITIONS
        if condition.scenario == "benign"
    ]

    assert len(benign) == 4


def test_step_e_has_five_attack_conditions() -> None:
    attacks = [
        condition
        for condition in CONDITIONS
        if condition.scenario != "benign"
    ]

    assert len(attacks) == 5


def test_single_run_matrix_is_valid() -> None:
    rows = run_benchmark(
        runs=1
    )

    result = validate_rows(
        rows,
        runs=1,
    )

    assert result["valid"] is True
    assert result["observed_rows"] == 9


def test_benign_conditions_are_accepted() -> None:
    rows = run_benchmark(
        runs=1
    )

    benign = [
        row
        for row in rows
        if row["scenario"] == "benign"
    ]

    assert all(
        row["accepted"]
        for row in benign
    )


def test_attack_conditions_are_rejected() -> None:
    rows = run_benchmark(
        runs=1
    )

    attacks = [
        row
        for row in rows
        if row["scenario"] != "benign"
    ]

    assert all(
        not row["accepted"]
        for row in attacks
    )
