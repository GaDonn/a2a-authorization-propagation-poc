import json


def pretty_print(title: str, data) -> None:
    print(f"\n--- {title} ---")

    if data is None:
        print("None")
        return

    if isinstance(data, (dict, list)):
        print(json.dumps(data, indent=2, sort_keys=True))
        return

    print(data)


def log_agent_header(agent_name: str, mode: str, attack: str) -> None:
    print(f"\n[{agent_name}]")
    print(f"MODE: {mode}")
    print(f"ATTACK: {attack}")