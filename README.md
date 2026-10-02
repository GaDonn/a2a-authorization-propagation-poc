# Authorization propagation in delegated A2A workflows

Research artifact for **Trust and Identity Propagation in Agentic AI Systems** (master's thesis, NTNU, August 2026) and the accompanying paper **Authorization Propagation in Agent2Agent Systems: An Experimental Security Evaluation of Multi-Hop Delegation**.

This proof of concept asks what a downstream agent can verify when the agent sending a request differs from the principal that originally authorized it. A synthetic healthcare reimbursement workflow separates current-caller context, inherited authorization evidence, and authentication of each direct request, without changing the A2A core protocol.

## Workflow and configurations

A reimbursement client contacts the Patient Agent, which prepares a synthetic claim and authorization details. The Hospital Agent validates and forwards them; the Insurance Agent checks the request and decides whether to reimburse the claim. Data are synthetic, FHIR-like objects rather than a complete FHIR deployment.

| Configuration | Mechanisms added | Main implementation |
| --- | --- | --- |
| C0 | Baseline A2A workflow | Agent executors and application processing |
| C1 | Secure Passport Extension v1 caller context, with Ed25519 state signatures | `common/a2a_secure_passport_v1.py` |
| C2 | Separate shared-HMAC authorization evidence: origin context, authorization hash, expected delegation path, expiry and optional artifact replay checks | `common/extended_secure_passport.py` |
| C3 | C2 plus a project-specific Ed25519 envelope for each direct request: sender, receiver, message, protected metadata, expiry and optional request replay checks | `common/request_authentication.py`, `common/fail_closed.py` |

Replay caches are enabled explicitly by the replay experiments. The benign network matrix runs with replay protection off in all four configurations. See [architecture](docs/architecture.md) for the configuration names used by each runner.

## Quick start

Install Python **3.10 or later** and `uv`, then run these commands from the repository root:

```bash
uv sync --frozen
uv run python -m scripts.generate_demo_secret
uv run python -m scripts.generate_agent_keys
uv run pytest -q
uv run python -m scripts.run_normal_workflow_matrix
```

The original benchmark was run on Windows 11 with Python 3.14.6 and `a2a-sdk==1.0.0a0`. The recorded environment is available in `results/reference/environment.json`. `uv.lock` preserves the supplied dependency resolutions and pins the SDK version used in the experiment.

The setup generates a local shared HMAC key and four Ed25519 key pairs, including `reimbursement-client`. Run each generation command once in a fresh checkout. Generated secrets are excluded by `.gitignore`. Existing key files and `.env` are never overwritten; reuse them for subsequent runs. `.env.example` documents the configuration rather than supplying a usable secret.

The network runner starts and stops all three agents automatically on loopback ports **12000–12002**. Run network experiments sequentially with those ports available. New reports, logs and measurements go to `results/local/`.

## Reproduce the evaluation

**Regenerate tables and plots from the original observations:**

```bash
uv run python -m scripts.analyze_step_e_final
uv run python -m scripts.generate_thesis_plots_distributions
```

These commands read `results/reference/benchmark.csv` and write to `results/local/analysis/` and `results/local/figures/`. The analysis uses only benign observations for performance comparisons. Reference figures and tables remain unchanged.

**Run the functional adversarial matrix and the separate limitation case:**

```bash
uv run python -m scripts.run_step_d_adversarial_matrix
uv run python -m scripts.run_authorized_intermediary_case
```

The matrix contains 15 attack scenarios plus control checks. Its pytest report passes when the expected behavior is observed, including acceptance of the known scope-widening gap. A passing authorized-intermediary test likewise confirms that the manipulated authorization is accepted; it does not claim that this attack is prevented.

**Collect a new benchmark with the original repetition count:**

```bash
uv run python -m scripts.run_step_e_final_benchmark --runs 100
uv run python -m scripts.analyze_step_e_final --input results/local/benchmark/step_e_benchmark.csv --output-dir results/local/new-analysis
uv run python -m scripts.generate_thesis_plots_distributions --input results/local/benchmark/step_e_benchmark.csv --output-dir results/local/new-figures
```

The benchmark measures a **local security-processing pipeline**, not end-to-end network latency. Payload sizes are **serialized local benchmark objects**, not HTTP wire bytes. Fresh timings vary with the machine and runtime; fresh keys and nonces also change signatures. The fixed dataset reproduces the reported tables; new runs check behavior on your environment.

For additional network impersonation and replay evidence, see [reproducibility](docs/reproducibility.md). The [thesis/paper mapping](docs/thesis-paper-mapping.md) links each reported result to its code and data.

## Recorded results and limits

| Evaluation | Recorded result |
| --- | --- |
| Functional matrix | 14 of 15 attack scenarios rejected; scope widening accepted |
| Authorized intermediary with the shared HMAC key | Modified authorization accepted despite valid downstream checks |
| Repeated benign conditions | 400/400 accepted: 100 observations per C0–C3 configuration |
| Five selected repeated attack conditions | 500/500 rejected: 100 observations per condition |
| Median local latency, C0 / C1 / C2 / C3 | 0.0195 / 1.0883 / 2.9986 / 5.1149 ms |
| Median serialized local payload, C0 / C1 / C2 / C3 | 513 / 996 / 2893 / 3870 bytes |

The 500/500 outcome covers five controlled, repeated attack conditions; it is not a general detection rate for arbitrary attacks. Structural delegation-path checks do not enforce semantic scope attenuation. Shared-HMAC holders can recompute authorization evidence. Per-hop signatures authenticate the current sender but cannot establish immutable original authority against a malicious authorized intermediary.

This is a research prototype. It uses local keys, a local trust store and process-local replay caches, without production key distribution, rotation or revocation, distributed replay state, or a complete OAuth authorization-server deployment. Read the [threat model](docs/threat-model.md) before interpreting the guarantees.

## Repository contents

| Path | Purpose |
| --- | --- |
| `patient_agent/`, `hospital_agent/`, `insurance_agent/` | Runnable A2A agents |
| `common/` | Security mechanisms, typed models, processing and synthetic templates |
| `scripts/` | Local setup, evaluation, analysis and plots |
| `tests/` | Tests of retained modules and final evaluation behavior |
| `results/reference/` | Original final observations and sanitized supporting reports |
| `results/local/` | Ignored outputs of new runs |
| `docs/` | Architecture, assumptions, reproduction, result mapping and provenance |

`common/secure_passport.py` retains canonicalization/replay utilities and compatibility helpers used by existing tests. The final C1/C2 split is implemented in the dedicated v1 and extended modules; the legacy combined-passport helpers are not the final C1 wire format.

## Citation and reuse

Use [CITATION.cff](CITATION.cff) for this software artifact. The thesis title and date come from the supplied thesis; publication identifiers and a repository URL have not been assigned. See [reuse status](docs/license-status.md) for license information and [publication steps](docs/publishing.md) for uploading this repository to a personal GitHub account. This package does not include the thesis or paper PDFs.
