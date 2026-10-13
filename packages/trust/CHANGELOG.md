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
- **Breaking:** `execute()` receives a snapshot of the declared arguments, not the object you
  passed. It has a null prototype and holds only the keys in `requires`, each read once when it
  was checked. An argument you did not declare is still written on the receipt and still a
  violation, but it no longer reaches `execute()` in any mode, `observe` and `warn` included. The
  judgment provider sees the same snapshot. Before this, a getter that answered one value when
  checked and another when used cleared `enforce` with a receipt for the first value.

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
