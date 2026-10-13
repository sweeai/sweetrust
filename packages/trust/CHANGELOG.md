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
- **A getter on the `args` object can no longer split the scope that is checked from the scope
  that is acted on** (the 2026-10-13 mandate audit). Every exported mandate function used to
  re-read `args.mandate`, `args.grantorScope`, `args.mandateId`, `args.capabilities` and
  `args.rationale` at each site that wanted them. A caller holding only its own genuine leaf could
  define a getter that answered the possession check with the genuine object and every other read
  with forged data, and from a held leaf alone: invoke a capability it was never granted, recorded
  under another mandate's id; mint a genuine project-tier scope outside its own subtree; revoke the
  org root; and mint a child whose scope and grant both carried a capability outside its grantor's
  grant. Each function now reads each field exactly once, resolves each capability's `key` exactly
  once, and the checks, the mint and the record all use those values. If you pass plain objects,
  nothing changes for you.
- **A keyword split by one invisible or format character no longer slips past the pre-check.**
  `ig<U+200B>nore all previous instructions` returned null: the character broke the word boundary
  while staying under the four-in-a-window cluster rule. Invisible and format characters are now
  stripped before the MIP-1/MIP-3/MIP-4 matches; the cluster rule still reads the raw string.
  `CATALOG_VERSION` is `0.2.1`, so a record stamped `0.2.0` was not screened this way.
- **Capability identifiers are screened before they are persisted.** `defineCapability` refuses an
  injected key where it is authored, and every issuer screens the keys it is about to record, so a
  bare string through an `as any` is caught too. Both throw `MaliciousMandateMetadata` with the
  already-reserved `inputKind: "capability-identifier"`.
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
- `makeSink` validates its spec at construction and throws `TypeError` naming the field: `mode`
  must be `observe` | `warn` | `enforce`, `log` must have `append()`, every `requires.<key>` must be
  a tier, `judgment.provider` must have `assess()`, and `judgment.floor` must be a finite number in
  `[0, 1]`. A misconfigured sink never exists.
- An `errored` receipt for an async action whose promise rejects, appended when it settles, with
  the rejection's message and the decision it follows.
- `humanConfirm`'s question states the value's full length when the value is cut.
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
- **Breaking (format):** a `MandateId`'s random suffix is 16 hex characters (64 bits). It was 10
  (40 bits) while the types called ids "collision-free". An issuer also refuses an id the log
  already has an event for and draws again, so an id is never minted twice into one log. Ids stay
  sortable by their millisecond prefix; anything that parses the suffix width must accept 16.
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
- **Breaking: every receipt hash changes. A receipt log written by 0.3.0 does not verify under
  0.4.0.** The interior hash (`Receipt.hash`, and so every `prevHash` after it) is now computed
  over canonical JSON — keys sorted at every depth — through the same `canonicalJSON` the
  signature and the wrapper link already used. It was `JSON.stringify` of a hand-ordered object,
  which pinned the seven top-level keys and left the `args` tree underneath in insertion order, so
  an honest exported artifact run through `jq -S`, a sorted-map round trip or a pretty-printer
  reported `hash-mismatch` with every value intact; `SECURITY.md` carried that as an honest limit
  and now states the opposite. No public API changes, and a chain written and verified by one
  version is unaffected. Only a log that crosses the version line fails: `verifyChain()` and
  `verifySignedChain` recompute each hash, and the recomputation of a 0.3.0 receipt no longer
  matches the hash it carries. Anchor a 0.3.0 chain's head before upgrading if you need to prove
  it later, and start a new log under 0.4.0. `canonicalJSON` and `sha256Hex` moved to
  `src/canon.ts`, a leaf module every subpath imports; the exported functions are the same
  objects as before. `docs/adr/0002-receipt-interior-hash-is-canonical.md` records the decision.

### Removed

- **`issueMandate` and `issueRootMandate` are gone.** This supersedes the Deprecated entry below,
  from earlier in this same release: they never shipped deprecated, they ship removed. Both stamped
  `"organization"` on every scope they minted, so an organization's child claimed to be an
  organization, and `issueMandate` ignored the grantor's tier until a runtime check was bolted on.
  Migrate `issueRootMandate` → `issueOrgMandate` (same arguments) and `issueMandate` →
  `issueProjectMandate` (same arguments; the grantor must be an org scope) or `issueAgentMandate`
  (the grantor must be a project scope). One consequence for error handling: a
  `TierLadderViolation` with `requestedTier: "organization"` can no longer be raised, because only
  `issueMandate` produced it. The other three ladder refusals (agent → project, project → project,
  agent → agent, org → agent) are unchanged and now each pinned by name in the tests.
- **The `asserted` tier is gone.** `TIERS` is `["untrusted", "corroborated", "verified"]` and the
  `Tier` type names those three. The spec's fourth rung was documented and never produced: no
  factory and no declassifier emitted it, so a sink declaring `requires: { x: "asserted" }` could
  never be satisfied, and `SECURITY.md` already said to treat the ladder as three. **Breaking
  (types):** `"asserted"` no longer type-checks as a `Tier`; at runtime `makeSink` throws
  `TypeError` at construction for a `requires` entry of `"asserted"`, as it does for any string
  outside the lattice, and `minTier` floors a combination containing it to `untrusted`. Receipts
  are unaffected: no receipt ever carried the tier.

### Deprecated

- `issueMandate` and `issueRootMandate`. Use `issueOrgMandate`, then `issueProjectMandate` and
  `issueAgentMandate`. They will be removed in a future release. *(Superseded above: removed in this
  release.)*

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
