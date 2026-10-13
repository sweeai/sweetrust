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
- **The gate's sealed ancestry could be unsealed through `forEach`.** `Set.prototype.forEach`
  hands its callback the Set itself as the third argument, and the sealed view bound that to the
  raw inner Set. One line recovered a mutable Set, and `corroborate` then accepted two extractions
  of one email as independent. The callback now receives the sealed view. This was the one HIGH of
  the 2026-10-13 gate audit; the bullets that follow are from the same pass.
- **`humanConfirm` confirms on the literal `true` only.** Any truthy return used to confirm, so an
  `async` renderer (which returns a Promise) and a readline answer of `"no"` both minted `verified`
  before the human had answered.
- **`execute()` and the judgment provider see one checked snapshot, not your object.** A getter or
  Proxy that answered one value when checked and another when used cleared `enforce` with a receipt
  for the first value; a symbol-keyed, non-enumerable or inherited argument reached `execute()`
  unchecked and off the receipt; the judge's bag was a plain `{}`, so a declared `__proto__`
  vanished from its view. See *Changed*.
- **A mode outside the ladder is a `TypeError`, not `warn`.** `"ENFORCE"`, `"strict"`,
  `undefined` and `null` all executed an under-tier argument as if the sink were in `warn`.
  `makeSink` now throws at construction — see *Added*.
- **An async action that rejects now leaves an `errored` receipt**, behind its `executed` one.
  The catch was sync-only, so `async () => { throw }` was recorded as `executed` and the log never
  heard about the rejection. `SECURITY.md` § *Honest limits* states the ordering.
- **The declassifiers return a verdict for a BigInt.** `humanConfirm`, `corroborate` (its default
  `equals` and its disagreement reason) and `allowlisted` threw on a bigint value; `allowlisted`
  also blamed the candidate when the registry record was the side that would not serialize. A
  caller's `equals` that throws is now a refusal naming the error.
- **The judgment wall fails closed when it cannot score.** A provider that threw left no receipt;
  a `mismatch` with a `NaN`, `undefined` or string confidence executed; `floor: undefined` never
  blocked. A throwing provider, a non-object verdict and a non-finite confidence on a `mismatch`
  now block in `enforce` and flag in `observe`/`warn`, with the failure written on the receipt.
- **The `Sourced` constructor is private at runtime, not only in the types.** `new Sourced(…)`
  from JavaScript and `class Evil extends Sourced` minted branded values that cleared `enforce`.
  Both now throw `TypeError`; the class and its prototype are frozen, so `Sourced.is` and
  `describe` cannot be swapped.
- **`corroborate` never lowers a tier.** A verified claim checked against an agreeing untrusted
  reference came back `corroborated`, with the demotion recorded on its chain as an upgrade.
- Smaller closures from the same pass: `minTier` floors to `untrusted` for any tier string outside
  the lattice (it returned `verified`); `ReceiptLog.append` ignores a `seq`, `prevHash` or `hash`
  smuggled on the entry; committed receipts and the `UpgradeEvent`s on a chain are frozen;
  `describe()` tolerates a `null` confidence instead of throwing inside the sink before the
  receipt; `makeSink` reads every spec field as an own key, once, so a polluted
  `Object.prototype.redact` or `.judgment` reaches no sink; `humanConfirm` renders the provenance
  before the value and cuts the value at 256 characters; `fromAuthority` freezes an object value
  in place so an `allowlisted` hand-out cannot rewrite the registry.

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
- `makeSink` validates its spec at construction and throws `TypeError` naming the field: `mode`
  must be `observe` | `warn` | `enforce`, `log` must have `append()`, every `requires.<key>` must be
  a tier, `judgment.provider` must have `assess()`, and `judgment.floor` must be a finite number in
  `[0, 1]`. A misconfigured sink never exists.
- An `errored` receipt for an async action whose promise rejects, appended when it settles, with
  the rejection's message and the decision it follows.
- `humanConfirm`'s question states the value's full length when the value is cut.

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
- **Breaking:** a receipt renders a BigInt as `{"$bigint":"5"}` and a non-finite number as
  `{"$number":"NaN"}` (or `"Infinity"`, `"-Infinity"`). This supersedes the bullet above that says
  a BigInt is written as `1000000000n`: that form was byte-identical to the *string*
  `"1000000000n"`, and `null` was shared by `NaN` and a literal null. Hashed bytes change for those
  two value kinds only; every other value renders exactly as before, under `raw`, `hash` and
  `truncate` alike.
- **Breaking:** in `observe` mode every receipt is labelled `observed`, violations or not. A call
  with violations used to be labelled `warned`. `warn` is unchanged.
- **Breaking:** `Sourced.fromAuthority` freezes an object or array value in place, shallowly. If
  you keep editing a record after wrapping it, wrap a copy. Primitives, `null` and typed arrays are
  left alone; `fromChannel` and `fromLLM` do not freeze.
- **Breaking:** the receipts `append()` returns and `all()` hands out are deep-frozen. Editing one
  throws instead of silently drifting from what the chain hashed.
- `corroborate` returns a claim already at or above `corroborated` unchanged — same object,
  `ok: true`, no upgrade event — once the independence and agreement checks have passed. Its
  default `equals` requires the same `typeof` on both sides before comparing JSON, so a bigint
  never agrees with an object that merely renders like one.
- `minTier` returns `untrusted` for any combination containing a tier string outside the lattice,
  and `meetsTier` requires both sides to be in it.
- `humanConfirm`'s question reads `Confirm the value with provenance <…> — value: <…>?`, and a
  refusal for a non-`true` answer says that `render()` must return exactly `true`.

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
