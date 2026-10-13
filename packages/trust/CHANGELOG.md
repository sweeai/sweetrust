# Changelog — `sweetrust`

All notable changes to this package. Format follows [Keep a Changelog](https://keepachangelog.com);
this package follows [Semantic Versioning](https://semver.org).

## [Unreleased]

### Security

- **Mandate authority is now possession of an issued scope, not a string** (DAN-1157, ADR 0001).
  Before this, an agent could invoke as its ancestors by naming their mandate id, or by reading
  `agent.parentScope.parentScope`. That second path needed no cast. The same agent could also
  permanently revoke the org root by naming its grantor. Scopes the module did not issue are now
  refused with `MandateScopeForged`. That covers copies, JSON round trips, and literals that copy
  every public field. `parentScope` is now a detached view with no authority.
- **The tier ladder holds at runtime**, not only at compile time. Agent → agent, org → agent and
  non-org grantors through `issueMandate` now throw the new `TierLadderViolation`.
- **The signed JSONL store is now the audit log itself.** `makeJsonlSignedAuditLive` re-verifies
  the whole file against the signer's key on every read, including a direct `isRevoked`. It
  refuses to append past a corrupt line. Before this, a corrupt line made it sign the next record
  as a second genesis mid-file.
- **The unsigned JSONL store fails closed.** One unparseable line used to blank the whole log,
  which flipped a direct `isRevoked` from `true` to `false`. It now throws `AuditLogCorrupt`. Only
  a missing file reads as an empty log; other I/O errors propagate.
- **Both verifiers return a verdict for every input, and two of them were failing open.**
  `verifySignedChain({})` and `verifyAuditChain({}, …)` returned `valid: true` for a plain object.
  Null records, records with no key and malformed anchors used to throw; they now fail with a
  reason. An empty chain passed `verifyAuditChain` vacuously and is now `empty-chain`.
- **An action no longer runs without its receipt when the caller's input is the problem.**
  Receipt arguments are rendered to a JSON snapshot BEFORE `execute()`. A `BigInt` is written as
  `1000000000n`. An argument that cannot be rendered is a violation, so `enforce` refuses before
  the action runs. The `raw` policy used to store the caller's object by reference, so editing it
  after the call rewrote the receipt and made `verifyChain()` report tampering.
- **Correction to the 0.3.0 entry below.** It says every decision lands in the receipt log,
  allowed *and* refused. Two decisions do not yet: a declassifier's refusal, and an action whose
  signer throws after `execute()`. `SECURITY.md` § *Honest limits* states both.
- **A signed record is exactly its six fields, and both verifiers now say so** (the 2026-10-13
  verify audit). A seventh key on the LAST record of a chain was authenticated by nothing: the
  signature covers four fields, the next link covers all six, and nothing came after the head.
  Both `verifySignedChain` and `verifyAuditChain` returned `valid: true` for it, and
  `makeJsonlSignedAuditLive` then signed the next record's link over the injected text, making
  it permanent. Any key outside `payload, signature, signerPublicKeyHex, signedAt, previousHash,
  domain` is now `malformed-record`, with the key named in `detail`, and the store refuses to
  read or append past it.
- **The pin gate refuses on its own.** `signerPublicKeyHex !== trustedSignerPublicKeyHex` was
  false when both were undefined, so a keyless record walked through; under the in-memory
  signer a keyless forged revoke was `valid: true`. A pin that is not a string is now
  `untrusted-signer` before anything else is read.
- **A signature is 128 lowercase hex characters, or it is not a signature.** Hex decoding was
  lenient, so uppercase, trailing garbage, a byte array and an odd-length string all decoded to
  the genuine bytes and verified on the head record. All three Ed25519 paths check the shape
  before decoding; the in-memory signer pins `inmem-` plus 64. An empty signature is still
  `missing-signature`.
- **Each record field is read once.** A getter or Proxy could answer the pin with the operator's
  key and the crypto with the attacker's, or swap a forged payload in after the signature check
  and have a seal over the forgery accepted; a getter that threw on a later read escaped as an
  exception. Both verifiers and all three signer `verify()`s now snapshot the six fields in one
  read and judge only that; a throwing getter is `malformed-record`.
- **`verifySignedChain` refuses options it does not know.** A caller still passing the retired
  `anchoredHead` got no anchor check and no signal, so a truncated chain verified. Any key other
  than `trustedSignerPublicKeyHex` and `anchor` is `malformed-record` naming it.
- **`makeInMemorySignerLive` refuses a marker that parses as a public key.** With the operator's
  real key hex as its marker, an `inmem-` signature anyone can compute verified under the
  operator's real pin.
- **Key material is validated where it is handed over.** `makeEd25519SignerLive` and
  `makeEd25519VerifierLive` accept Ed25519 keys only, the signer checks its private and public
  keys are a pair, and `publicKeyHexFromPem` and both factories refuse a PRIVATE key PEM in a
  public slot. Before this a mismatched pair signed a store no pin could verify.

### Added

- `AuditLogCorrupt { storePath, line, reason, detail? }`, a new `MandateError` variant thrown by
  every read of a corrupt store.
- `MandateFailure`, the `Error` subclass mandate refusals are thrown as, and `MandateFailure.is(e)`
  to narrow a caught value.
- `VerifyAuditChainResult.reason` gains `"empty-chain"` and `"malformed-record"`, plus an optional
  `detail`.
- `Receipt["decision"]` gains `"declassify-refused"`. It is **reserved, not yet produced**.
  Nothing emits it today, and it exists now because adding a member after publish would break
  every exhaustive switch.
- `RECEIPT_DOMAIN` and `signedPreimage` from `sweetrust/verify` and from the root. `ReceiptSigner`
  was public, but the domain tag a bring-your-own signer must fold into the preimage, and the
  preimage definition itself, could not be imported from either entry.

### Changed

- **Breaking:** the package is named `sweetrust`, with subpaths `sweetrust/mandate`, `sweetrust/gate`
  and `sweetrust/verify`. It was planned as `@swee/trust`, but the `@swee` npm scope belongs to
  another user. The 0.3.0 entry below still uses the old name.
- **Breaking:** `revokeMandate` takes `revokerScope` (the scope you hold) in place of `revoker`
  (a name). It succeeds when that scope is the target or one of its ancestors.
- **Breaking:** issued scopes and their capability lists are frozen.
- **Breaking:** `makeJsonlSignedAuditLive` returns `{ mandateAudit, signedAudit }`, not the
  signed surface alone. Pass `mandateAudit` wherever an audit log is taken.
- **Breaking:** mandate refusals are thrown as `MandateFailure`, a real `Error` with a stack, not
  as a plain object. The union's fields (`_tag` and the rest) are still own properties, so
  `e._tag` switches keep working and `JSON.stringify(e)` is unchanged. `message` is the `_tag`
  alone, because some variants carry attacker-supplied text. One thing does change:
  `structuredClone(e)` drops `_tag`, because cloning an `Error` keeps only its standard fields.
- **Breaking (types):** `makeSink`'s argument constraint is `Sourced<unknown>`, not
  `Sourced<any>`. Without declared generics, `execute` could read `amount.value.anything.deep`
  and compile. Declare `Args`, or type `execute`'s parameter.
- **Breaking (types):** an exhaustive switch over `Receipt["decision"]` must handle
  `"declassify-refused"`, and one over `VerifyAuditChainResult.reason` must handle the two new
  reasons.
- `verifySignedChain` reports a non-object record such as `[42]` as `malformed-record`. It used to
  report `missing-signature`.
- The npm package no longer ships sourcemaps.
- `canonicalJSON` follows `JSON.stringify` for boxed primitives and `toJSON`: a boxed
  `String`/`Number`/`Boolean` serializes as its primitive, `toJSON(key)` is called once with its
  key and its result is not asked again. A record signed over such a value used to fail to verify
  after an export. No persisted chain changes: a record that has been through JSON carries none
  of these, and on such values the bytes are identical to before.
- `parseJSONL` numbers an error line as the file numbers it, blank lines included, and accepts one
  leading byte-order mark. `exportJSONL` escapes U+2028, U+2029 and U+0085 as `\uXXXX`; the
  parsed values and both hashes are unchanged, and a line-splitting reader can no longer split a
  record.
- A record with a stray key in the MIDDLE of a chain reports `malformed-record` at its own index.
  It used to surface at the next record as `hash-chain-broken`.
- Both Ed25519 factories and `publicKeyHexFromPem` throw at construction on key material they
  used to accept silently (see Security). `makeInMemorySignerLive` throws on a marker that is a
  real key.

### Deprecated

- `issueMandate` and `issueRootMandate`. Use `issueOrgMandate`, then `issueProjectMandate` and
  `issueAgentMandate`. They will be removed in a future release.

## [0.3.0] — first public release

First release under the `@swee` scope. The package's development history predates this repository
and is not carried forward.

### Added

- **`@swee/trust/mandate`** — type-enforced multi-tier capability mandates on an Ed25519-signed
  hash chain. Authority is issued, delegated and revoked against an append-only audit log; the
  signed preimage binds the chain link, sequence, timestamp and a domain tag, so a record cannot be
  relinked, reordered, retimed or replayed as a different protocol's message without breaking a
  signature.
- **`@swee/trust/gate`** — `Sourced<T>` provenance tiers with sticky taint, three audited
  declassifiers as the only ways a value can rise, fail-closed sinks that declare their appetite,
  and tamper-evident receipts for every decision — allowed *and* refused.
- **`@swee/trust/verify`** — signed receipt chains re-checkable from public material alone, plus a
  Sui anchor convention that makes tail truncation detectable.
- **Zero runtime dependencies.** Node builtins only.

### Notes

- Read `SECURITY.md` § *Honest limits* before adopting. It names what this package does **not**
  protect — in particular that the TypeScript revocation and the on-chain revocation are two
  separate kill switches, and only the on-chain one stops money.
