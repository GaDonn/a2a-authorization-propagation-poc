# Source provenance and distribution changes

This is a fresh selection from the supplied `thesisA2A.zip`, with no Git history. The two supplied PDF documents are used to align documentation and results but are not redistributed in this package.

## Retained material

- Final Python modules in `common/` and the three agent packages, including synthetic JSON templates.
- All top-level tests except development-era `test_day18`–`test_day25` files. The useful canonicalization/compatibility test `test_secure_passport_day10.py` is retained as `test_secure_passport_utils.py`.
- The workflow client and final setup/evaluation/analysis/plot scripts, including network sender-impersonation and replay-domain evidence.
- Final Step E benchmark and corrected analysis, final adversarial reports and thesis distribution figures.

## Excluded material

Virtual environments, Git history, bytecode and pytest caches, all private/public key files, old public-key dumps, `*_before_day*.py` snapshots, daily design bundles, obsolete benchmark harnesses and pilot/day21–day24 data, temporary payloads, raw service logs, screenshots, nested evidence ZIPs and duplicate plot copies. `docs/file-selection.csv` records the decision for every original ZIP member.

## Changes made for distribution

| Change | Reason / impact |
| --- | --- |
| Project metadata renamed; explicit wheel packages and pytest configuration | Artifact identity and reliable imports; no business/security logic change |
| Evaluated SDK pinned to `1.0.0a0`; editable root metadata updated in `uv.lock` | Retains dependency resolutions while preventing an SDK upgrade |
| Local `.env` loaded in `common/config.py`; `DEMO_SECRET` supplied through validated `A2A_HMAC_SECRET` | No default shared key shipped; shared-HMAC trust model remains unchanged |
| New `scripts/generate_demo_secret.py` | Generates a fresh ignored local shared key without printing it |
| Subprocess stdout buffering disabled in network runners | Reliable log validation when child services are stopped; no request logic change |
| Runner output paths moved to `results/local/` | New runs do not overwrite historical results |
| Analysis/plots read `results/reference/benchmark.csv` by default | Tables and figures reproduce the supplied final observations |
| Plot input/output CLI options added | Allows comparison with new measurements |
| Final benchmark pilot-file dependency removed; default 100 repetitions | Fresh-checkout execution of the final protocol |
| Final wrapper environment capture uses installed package metadata | Portable and avoids recording absolute executable paths |
| Test file renamed; script package marker added | Removes obsolete day terminology at file level and supports module invocation |
| English documentation, citation metadata and original/public manifests added | Reviewability and traceability |
| New secret-configuration tests added | Checks missing/malformed secret failure and environment precedence |

Signature algorithms, authorization binding, delegation verification, request-envelope verification, replay semantics and application decisions have not been deliberately changed. The two accepted limitation cases are preserved. Some retained test identifiers still contain development-day labels because their fixture content is unchanged.

`docs/source-manifest.csv` records original and public hashes for retained Python/TOML/lock files. `results/reference` is not presented as output of the newly prepared version; it is historical evidence from the verified original source snapshot.

## Upstream origin

The project was developed under an `a2a-samples` checkout according to the supplied metadata and environment report. C1 references the upstream Secure Passport extension, while C2 and C3 use project-specific formats. No upstream license or copyright file was present in the uploaded root. Upstream references are retained for traceability. No project-wide reuse license is specified in this snapshot.
