# Threat model and interpretation

The evaluated setting is a controlled local reimbursement workflow using synthetic resources. Trusted local public keys map fixed participant identities to Ed25519 keys. Agents share a key for HMAC protection of the C2 artifact. The experiment assumes local configuration and trusted-key files are provisioned consistently; it does not evaluate compromise of that provisioning system.

## Evaluated attacks

The functional matrix exercises impersonation; changes to message text, caller context and companion evidence; changes to authorization amount, beneficiary, coverage, treatment or action; unauthorized paths and destination substitution; scope widening; expired evidence; and replay in the request and authorization-artifact domains.

The tests isolate verification boundaries. Some authorization mutations are carried in freshly valid direct-request envelopes to exercise the C2 binding check, rather than merely failing the C3 signature first. A passing test means its intended outcome was observed.

## Trust boundaries and observed gaps

| Boundary | Assumption or result |
| --- | --- |
| Direct sender authentication | C3 verifies an envelope signed by a trusted immediate sender for the intended receiver and request |
| Original authorization | A shared-HMAC holder can rewrite and re-sign C2 evidence; the origin state signature does not make the authorization details immutable |
| Delegation | Expected path structure is checked; semantic attenuation of each delegated scope is not enforced |
| Replay | Separate in-memory caches detect selected repeats when enabled; state is local and lost on process restart |
| Application validation | Checks represented claims against represented authorization; forged but internally consistent authority can still pass |

The authorized-intermediary case grants the Hospital its legitimate Ed25519 key and the shared C2 HMAC key. It changes the maximum authorized amount from 120 to 9000 EUR, updates the bound hash, regenerates the artifact integrity and signs a fresh Hospital-to-Insurance request. Downstream verification and application validation accept it. This case is outside the 15-scenario matrix because it assumes a legitimate shared-key holder.

## Scope of evidence

Fourteen of the 15 functional attack scenarios are rejected; scope widening is accepted. The 900-row benchmark comprises 400 benign executions and 500 executions of five selected attacks. The 500/500 rejections demonstrate repeatability for those specific constructed conditions, not coverage of unseen attacks. These attack repetitions do not include the accepted scope-widening or authorized-intermediary cases.

Local processing times exclude HTTP transport, service startup and a full distributed deployment. Serialized payload sizes do not represent HTTP wire traffic. No production PKI, key rotation/revocation, distributed replay cache, full OAuth/RAR service or clinical FHIR conformance is claimed.
