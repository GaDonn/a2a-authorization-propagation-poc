from scripts.run_normal_workflow_matrix import (
    CONFIGURATIONS,
)


def test_normal_workflow_matrix_contains_four_configurations() -> None:
    assert len(CONFIGURATIONS) == 4


def test_configuration_names_are_stable() -> None:
    assert [
        configuration.name
        for configuration in CONFIGURATIONS
    ] == [
        "C0_baseline",
        "C1_standard_passport",
        "C2_extended",
        "C3_extended_signed",
    ]


def test_baseline_configuration() -> None:
    configuration = CONFIGURATIONS[0]

    assert configuration.mode == "baseline"
    assert configuration.request_authentication == "off"
    assert configuration.replay_protection == "off"


def test_standard_passport_configuration() -> None:
    configuration = CONFIGURATIONS[1]

    assert configuration.mode == "passport"
    assert configuration.request_authentication == "off"
    assert configuration.replay_protection == "off"


def test_extended_configuration() -> None:
    configuration = CONFIGURATIONS[2]

    assert configuration.mode == "extended"
    assert configuration.request_authentication == "off"
    assert configuration.replay_protection == "off"


def test_extended_signed_configuration() -> None:
    configuration = CONFIGURATIONS[3]

    assert configuration.mode == "extended"
    assert configuration.request_authentication == "on"
    assert configuration.replay_protection == "off"


def test_all_normal_configurations_disable_attacks() -> None:
    for configuration in CONFIGURATIONS:
        assert (
            configuration.environment()["ATTACK"]
            == "none"
        )
