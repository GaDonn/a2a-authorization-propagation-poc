# Reproducing the artifact

Run commands from the repository root after the README setup. Use module invocation (`python -m scripts...`) so repository imports resolve reliably across operating systems.

## Historical reference versus new executions

`results/reference/benchmark.csv` is the original final CSV, preserved byte-for-byte. It has 900 rows: 100 for each of four benign configurations and five controlled attack conditions. The supplied reference performance and detection CSVs are also preserved byte-for-byte.

Supporting JSON reports are either copied or sanitized as documented in `results/reference/README.md`. Reference files are read-only by convention, not filesystem permissions. Default runner outputs are confined to ignored `results/local/`; analysis and plotting read the reference CSV by default.

| Task | Command | Output |
| --- | --- | --- |
| Unit and security tests | `uv run pytest -q` | Console test summary |
| Four benign network workflows | `uv run python -m scripts.run_normal_workflow_matrix` | `results/local/normal_workflows/` |
| 15 attacks plus controls | `uv run python -m scripts.run_step_d_adversarial_matrix` | `results/local/attacks/step_d_updated_matrix/` |
| Shared-HMAC intermediary limitation | `uv run python -m scripts.run_authorized_intermediary_case` | `results/local/attacks/authorized_intermediary_limitation/` |
| Network sender impersonation | `uv run python -m scripts.run_sender_impersonation_experiment` | `results/local/attacks/sender_impersonation/` |
| Request versus artifact replay | `uv run python -m scripts.run_replay_evidence` | `results/local/attacks/replay_evidence_final/` |
| New 900-row benchmark | `uv run python -m scripts.run_step_e_final_benchmark --runs 100` | `results/local/benchmark/` |
| Reference tables | `uv run python -m scripts.analyze_step_e_final` | `results/local/analysis/` |
| Reference distribution figures | `uv run python -m scripts.generate_thesis_plots_distributions` | `results/local/figures/` |

The final benchmark wrapper now defaults to 100 runs per condition, as used in the thesis. It does not require discarded pilot outputs. `--runs N` can be used for exploratory shorter or longer runs; a different repetition count is not the original experimental protocol. The wrapper records the runtime environment, code hashes before/after the run and row validation.

## Exact reproduction and comparison

The historical table generator should reproduce all numeric cells in `performance_summary.csv` and `attack_detection.csv` from `benchmark.csv`. Plot rendering can vary with Matplotlib or font versions; the figure source data and deterministic jitter seeds are retained. The original PNG/PDF plots are supplied alongside their generation script.

New benchmark runs use fresh secrets, keys, timestamps and UUID nonces, so signatures and measurements need not match the historical run. Nonce length or timings may affect payload-size and timing distributions. Compare accepted/rejected behavior, measurement scope and repetition counts before comparing performance.

The original Windows environment is recorded in `results/reference/environment.json`. `uv.lock` came from the supplied project and contains plotting dependencies newer than the original benchmark run; it is not a claim that those plotting versions generated the thesis figures.

## Troubleshooting

- If `.env` or key files already exist, skip generation commands and reuse them. The generators intentionally refuse overwrites.
- `A2A_HMAC_SECRET` must be exactly 64 hexadecimal characters. Environment variables override `.env`; unset an unintended inherited value before testing.
- In environments with global HTTP/SOCKS proxies, exempt loopback traffic from those proxies before running the local network demos.
- Network experiments need ports 12000–12002 available. They use subprocesses and loopback TCP; run them sequentially.
- The scripts validate newly generated time-limited evidence; factories refresh timestamps. Do not replay historical authorization artifacts as live requests.
- Do not install a newer A2A SDK to resolve a failure without separately assessing compatibility with the prerelease API used here.
