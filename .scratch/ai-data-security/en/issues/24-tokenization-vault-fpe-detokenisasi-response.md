<!-- source-sha256: 0a59bf7669e83359 -->
# 24: Tokenization vault (FPE) + response detokenization

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 13
Spec: `../spec.md` §4.6 FR-DLP-3; §7.1

## Context
Allows the LLM to process data without seeing the original values.

## Scope
- FPE vault (FF1) with keys in KMS/HSM; configurable token TTL.
- `tokenize` action at the gateway; response detokenization only for entitled principals.
- Audit every detokenization.

## Acceptance criteria
- [x] Format-preserving round-trip tests for NIK (national ID number), bank account numbers, and PAN. *(`TestRoundTrip` (Postgres): plain and space-separated NIK, 10/13/15-digit bank account numbers, space-separated 16-digit PAN and 15-digit Amex, phone numbers `+62`/`08`, dotted NPWP (tax ID). Token has the same length and separators in the same positions; the same value always yields the same token; tokens differ across classes; the plain-digit form of a token also round-trips. `TestFF1Vector` pins the library to NIST SP 800-38G sample 1.)*
- [x] Principals without entitlement receive the tokenized value. *(`TestTokenize`: the provider only sees tokens; an app with `detokenize: true` receives the original value in the answer (via the vault, audited); an app without entitlement receives the token; vault down → value is redacted, never sent. `TestTokenizeStream`: a token split across deltas is returned intact.)*
- [x] Active-passive failover tested. *(`TestFailover`: two replicas share Postgres, only the advisory lock holder is ready and serves; when the active replica dies → the passive replica takes the lock, and tokens issued earlier can still be detokenized via a client that tries the next URL.)*

## Decisions
- **`token-vault` service** (`internal/tokvault`, `cmd/token-vault`): FF1 radix 10 (`capitalone/fpe` library, Apache-2.0, with NIST vectors), tweak = class name (one domain per class). Per-tenant FF1 keys are wrapped by a KEK (AES-256-GCM, `internal/seal`, shared with incident). The KEK pattern is the same as incident evidence: a file from Vault/HSM; the KMS unwrap call follows together with §10.1.
- **No plaintext stored.** The `tokvault.tokens` table only stores the token HMAC + `expires_at`. A token is only returned while registered (TTL per app, default 60 minutes, maximum 7 days); an expired token is still a token and is cleaned up periodically. Every detokenization is written to the audit log (app, principal HMAC, trace, class, token HMAC) before the value leaves: no audit record, no value.
- **Tokenizable classes:** NIK, KK (family card number), NPWP, phone number (prefix `08`/`628` preserved), bank account number, PAN. Only digits are encrypted; separators stay in place. Other classes are redacted.
- **Gateway:** the `tokenize` action uses the vault for numeric classes and overrides redact from weaker rules (FR-POL-4). Issued tokens are remembered per request. In the response, tokens (or their plain-digit form) are restored only for `detokenize: true` apps. Streaming never cuts a token in the middle. Vault unreachable → redaction (the stricter control).
- **Active-passive:** Postgres advisory lock; the `/ready` readiness is only for the active replica, so the Service only points to it; the client tries the next URL on a 503 or a connection failure.
- The vault API is bearer-authenticated (`VAULT_CLIENT_TOKEN_SHA256`). Values travel within the cluster without TLS until mTLS (ticket 40).

## Remaining
- Detokenization entitlement is currently per app, not yet per user/group (needs identity attributes at the gateway).
- A token that happens to pass structural validation (e.g. a NIK) could be recorded as a finding on the response direction.
