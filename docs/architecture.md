# Architecture

The wire workflow is reimbursement-client → Patient Agent → Hospital Agent → Insurance Agent. The authorization delegation path starts with user → Patient Agent → Hospital Agent → Insurance Agent. The reimbursement client is the initiating request sender rather than an extra delegation entry.

| Participant | Responsibility | Entrypoint |
| --- | --- | --- |
| Client | Initiates the reimbursement request; signs it in C3 | `test_client.py` |
| Patient Agent | Builds consistent synthetic resources and structured authorization; creates caller context and C2 evidence | `patient_agent/agent_executor.py` |
| Hospital Agent | Verifies inbound material, validates the claim, enriches provenance and appends delegation evidence | `hospital_agent/agent_executor.py` |
| Insurance Agent | Verifies request and inherited evidence, validates application constraints and decides | `insurance_agent/agent_executor.py` |

## Distinct security objects

| Object | Verified information | Boundary |
| --- | --- | --- |
| Secure Passport v1 CallerContext | Caller identity, session/context state and an Ed25519 signature over state in this implementation | Current caller context |
| C2 companion artifact | Bound origin context, authorization-details hash, timestamps, authorization nonce, expected delegation path and shared HMAC integrity | Inherited evidence inside the shared-key trust domain |
| C3 request envelope | Sender, receiver, message ID, text and selected metadata digests, validity interval, request nonce and Ed25519 signature | Direct request from the immediate sender |
| FHIR-like Provenance resource | Application processing history represented by synthetic resources | Application data, distinct from authorization delegation |

`common/healthcare_factory.py` loads synthetic templates, sets fresh timestamps and validates cross-resource consistency. `common/hospital_processing.py` and `common/insurance_processing.py` implement application checks. `common/wire_client.py` handles the SDK wire representation. Canonicalization uses RFC 8785 with integral-float normalization for protobuf Struct values.

`common/fail_closed.py` checks inbound C3 requests before business processing. The two replay domains have separate process-local caches. Nonces are consumed after required checks succeed. Replay tests explicitly enable the relevant caches; optional replay protection is not enabled merely by choosing a C2/C3 mode.

## Configuration names

The supplied network runner and benchmark use different labels for the same incremental mechanism sets; labels are retained for traceability.

| ID | Network runner label | Benchmark label | MODE | REQUEST_AUTHENTICATION |
| --- | --- | --- | --- | --- |
| C0 | `C0_baseline` | `C0_baseline` | `baseline` | `off` |
| C1 | `C1_standard_passport` | `C1_secure_passport_v1` | `passport` | `off` |
| C2 | `C2_extended` | `C2_extended_secure_passport` | `extended` | `off` |
| C3 | `C3_extended_signed` | `C3_extended_plus_per_hop_security` | `extended` | `on` |

The baseline and intermediate modes exist for comparison. `REPLAY_PROTECTION=off` is the benign network runner's setting for every row. Controlled request/artifact replay checks are exercised separately.
