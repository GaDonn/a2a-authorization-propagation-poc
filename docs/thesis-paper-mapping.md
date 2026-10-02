# Thesis and paper result mapping

Thesis: *Trust and Identity Propagation in Agentic AI Systems*, submitted August 2026. Paper: *Authorization Propagation in Agent2Agent Systems: An Experimental Security Evaluation of Multi-Hop Delegation*, supplied draft (no publication status assumed).

| Reported material | Code / test | Historical evidence |
| --- | --- | --- |
| Thesis Table 5.1 and §5.1: benign workflow | `scripts/run_normal_workflow_matrix.py`; `tests/test_normal_workflow_matrix.py` checks runner configuration | `results/reference/normal_workflows.json` |
| Thesis Table 5.2 and §5.2; Paper Table IV and §VI.A: 15 functional attacks | `tests/test_step_d_adversarial_matrix.py`; `scripts/run_step_d_adversarial_matrix.py` | `results/reference/adversarial_matrix.json` |
| Thesis §5.2.3 and Appendix A.5; Paper §VI.B: authorized intermediary | `tests/test_authorized_intermediary_limitation.py`; `scripts/run_authorized_intermediary_case.py` | `results/reference/authorized_intermediary.json` |
| Thesis Table 5.3: benign processing latency | `scripts/run_step_e_benchmark.py`; `scripts/analyze_step_e_final.py` | `results/reference/benchmark.csv`; `performance_summary.csv` |
| Thesis Table 5.4: signing/verification and payload size; Paper Table V | Same benchmark and analysis scripts | Same benchmark and performance CSVs |
| Thesis Figures 5.1–5.2: latency and payload distributions | `scripts/generate_thesis_plots_distributions.py` | `results/reference/figures/`; benign rows in `benchmark.csv` |
| Thesis Table 5.5: repeated selected attacks; Paper §VI.C | `scripts/run_step_e_benchmark.py`; `tests/test_step_e_benchmark.py` | `results/reference/attack_detection.csv`; `benchmark.csv` |
| Thesis Appendix A.2: network sender impersonation | `scripts/run_sender_impersonation_experiment.py`; `tests/test_sender_impersonation.py` | `results/reference/sender_impersonation.json` |
| Thesis Appendix A.3: separate replay domains | `scripts/run_replay_evidence.py`; `tests/test_step_c_per_hop_request_security.py` | `results/reference/replay_domains.json` |
| Thesis C0–C3 design; Paper Table III and Table VI | Security modules in `common/`; [architecture](architecture.md) and [threat model](threat-model.md) | Mechanism coverage is distinct from the five repeated attack conditions |

The matrix runner executes more than 15 pytest tests because it includes benign and nonce-separation controls. Do not interpret the pytest pass count as the number of rejected attacks. The scope-widening and authorized-intermediary tests pass by confirming the accepted limitation cases.
