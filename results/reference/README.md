# Original final experimental evidence

These files come from the supplied thesis project. They are separate from new execution results.

| Public file | Original project path | Handling |
| --- | --- | --- |
| `benchmark.csv` | `benchmark_results/step_e_final/step_e_benchmark.csv` | Byte-identical |
| `benchmark_summary.json`, `benchmark_run.json` | Final benchmark summary and execution report in `step_e_final/` | Byte-identical |
| `performance_summary.csv`, `attack_detection.csv`, `quality_metrics.json`, `analysis_report.json` | Corrected final tables and report in `benchmark_results/step_e_analysis/` | Byte-identical |
| `environment.json` | `benchmark_results/step_e_final/environment.json` | Removed local interpreter/project paths; kept recorded versions and platform |
| `adversarial_matrix.json` | `attack_results/step_d_updated_matrix/step_d_adversarial_matrix_report.json` | Removed stdout/stderr log dump and normalized test-file path |
| `authorized_intermediary.json` | `attack_results/authorized_intermediary_limitation/authorized_intermediary_report.json` | Same log/path sanitization; retained observed outcome |
| `normal_workflows.json` | `normal_workflow_results/normal_workflow_report.json` | Removed top-level stdout/stderr if present; normalized machine-local paths |
| `sender_impersonation.json`, `replay_domains.json` | Corresponding final reports in `attack_results/` | Same diagnostic/path sanitization |
| `figures/LatencyResults.*`, `figures/PayloadSizeResults.*` | `figs/` | Original PNG and PDF bytes retained |

The CSV contains 900 observations, including request and authorization nonces for traceability, but no private-key material. The recorded normal-workflow report retains synthetic request output; no raw service logs or terminal screenshots are included.

The historical source manifest matched every retained core source module and the benchmark implementation in the supplied ZIP, and the original before/after manifests matched each other. The public core was subsequently changed only for local secret configuration/loading, related comments and line endings. See `docs/source-manifest.csv` for exact original/public hashes and `docs/provenance.md` for the changes.
