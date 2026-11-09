# Changelog — `sweetrust`

All notable changes to this package. Format follows [Keep a Changelog](https://keepachangelog.com);
this package follows [Semantic Versioning](https://semver.org).

## Versioning

`sweetrust` is 0.x: **a minor version may break.** Until 1.0 the following are explicitly unstable
and may change in a minor: the `Receipt["decision"]` union, `VerifyFailure` and
`VerifyAuditChainResult["reason"]`, the `MandateError` union, the receipt hash body (the bytes
`receiptBody` returns) and the signed preimage, the width of a `MandateId`'s random suffix, and the
`swee.*.v1` domain tags. Persisted JSONL is versioned by its `domain` tag. A chain written and
verified by one version is unaffected by an upgrade; a chain that crosses a version line is
re-verified by the newer code, which may refuse it — each such change is a *Breaking* bullet in the
release that makes it. A patch version changes none of these.

## [Unreleased]

### Breaking

- **`allowlisted` takes its key as a `Sourced<string>` and refuses one below `verified`.** The key
  picks the record a candidate is compared against, so a key the message supplied could pick the
  attacker's own record. Migrate by wrapping the key your host holds:
  `allowlisted(candidate, registry, Sourced.fromAuthority(po.vendorId, "purchase-orders"), name)`.
  A plain string is a `TypeError`. The key's tier and origin are now in the ascent's `evidence`
  (DAN-1444).
- **`allowlisted` refuses a registry row below `verified`, and a row or candidate the gate did not
  mint.** A row from parsed JSON, or built with `Sourced.fromChannel`, used to come back as a real
  `verified` value. Build registry rows with `Sourced.fromAuthority` (DAN-1448).

- **A confirmed value and a registry row are frozen at every depth.** `humanConfirm` deep-freezes the
  value it promotes, and `allowlisted` deep-freezes a row in place when a lookup finds it, so a value
  shown as good cannot be rewritten after the yes or through a nested field. A host that mutates a
  confirmed value or a nested registry row must copy it first. `humanConfirm` now refuses a value that
  is not plain JSON (a Map, a Set, bytes, a Date, an `undefined` field, `NaN`), because the question
  could not show it as it is.
  `corroborate` and `humanConfirm` refuse a claim, reference or candidate the gate did not mint, and
  no person is asked. `Sourced.fromLLM` throws a `TypeError` on an input the gate did not mint (DAN-1451).

### Security

- **`JudgmentVerdict.confidence` no longer claims to be calibrated.** It is whatever the provider
  reports, and `floor` is only a line drawn on that number, so re-examine a floor when the provider or
  its pinned model changes. `SECURITY.md` now also describes how a provider's text reaches the
  receipt, so scrub what a provider throws or returns (DAN-1446).

- **A doubted action needs its owner, however long the agent waits.** A hold expired after 15 minutes
  and a block after its window, and the next identical call was judged afresh, so a `match` ran with
  no approval and an agent could retry until the judge agreed. The judge is still asked, so the owner
  gets a fresh hold to approve, but a `match` on an action with a real doubt behind it is now held. A
  judge outage is not a doubt, and only the owner's approval of that doubt clears it (ADR 0010,
  DAN-1443). A log from 0.6.0 in which an unapproved run followed an expired doubt keeps that doubt,
  so the next repeat of that action is held until the owner approves it.

- **The provenance in a confirmation question is quoted.** A channel or authority name that held agent
  text could write a second line reading `Confirm VERIFIED (origin: authority:bank)` into the question
  a person answers. The origin is now escaped and cut to 64 characters, so it cannot pose as the value or
  as the gate's own upgrades, and invisible characters in the value show as escapes. `Sourced.describe`
  itself is unchanged (DAN-1458).
- **`allowlisted` refuses when its registry throws.** It used to throw. No value ascended either way
  (DAN-1458).
- **`mockJudgmentProvider` no longer writes the payee, amount or cap into its rationale**, since a fixed
  sentence holding them can be confirmed from its hash on a redacted receipt (DAN-1458).

### Added

- **A judge is told the payment the sink resolved.** On a sink that names `purposeArgs`,
  `JudgmentInput` now has a frozen `payment` (`payee`, `amount`, `asset`, `network`) built from the
  same values as the verdict's `paymentDigest`, so a provider can read the payment without repeating
  the sink's `purposeArgs` and can see a sink-level `judgment.asset`. `amount` is the decimal string the digest
  hashes, even for a bigint argument. The view has a fourth key only on such a sink. On every judged
  sink `input` no longer inherits from `Object`, so a provider that calls `input.hasOwnProperty` or
  stringifies `input` must use `Object.hasOwn` instead, or the call has no verdict (DAN-1445).
- **A sink can hold a payment to one spelling.** A block or hold names an action as written, so
  `0xABC` after a hold on `0xabc` was a new action and got a fresh judge. Set `judgment.spelling` to
  your rail's canonical form of a payee and an asset, and any other spelling is refused before a
  judge runs. A sink without it behaves as before, and no digest changes (DAN-1457). A function that
  throws or answers with something other than a string is reported as `could not be checked` (DAN-1458).
- **A judge can trace a payment to its arguments.** `JudgmentInput.payment` now has `payeeArg`,
  `amountArg` and `assetArg` (null when the sink fixes the asset), so `input.trust[input.payment.payeeArg]`
  is the payee's tier. No digest changes (DAN-1458).

## [0.6.0] — 2026-11-08

This release adds the intent layer: the owner's purpose is signed into the mandate,
a judge scores each action against it, and doubt never moves money. The kernel ships no judge.
`mockJudgmentProvider` is a stand-in for demos and tests, and a real model is a provider you bring.

**Upgrading from 0.5.x.** These call shapes change; each is a *Breaking* bullet below.

```ts
// 0.5.x: const r = pay(args)
const r = await pay(args) // every sink call now returns a Promise, judged or not
```

```ts
// 0.5.x: assess(name, args), answered synchronously. Now `name` is `action.sink`,
// `args.x.value` is `action.args.x`, and `args.x.tier` is `trust.x.tier`.
const provider: JudgmentProvider = {
  name: "my-judge",
  model: "my-judge@1",
  assess: async ({ purpose, action }, signal) => ({ assessment: "match", confidence: 0.9, rationale: "fits" }),
}
```

```ts
// A judged sink now needs the purpose its grant recorded.
const pay = makeSink({ /* … */ judgment: { provider, floor: 0.7, granted: trust.grantedPurpose(scope) } })
```

Three behaviors change as well. An `enforce` sink now refuses a `Sourced` value that is not plain
JSON. A judge's `unsure` in `enforce` no longer runs: the action is held. And a grant made on 0.5.x
carries no purpose, so a judged sink needs a new grant issued with `purpose`. Its id is new, so its
budget starts over.

Receipts from an unjudged sink hash exactly as they did in 0.5.x, so a 0.5.x log of them verifies
unchanged. Only a judged sink's receipts change shape (ADR 0009).

### Security

- **A payment amount has one spelling at a sink that names `purposeArgs`.** `"0100"` and `100n` were
  new actions, so they escaped a block on `"100"` and paid again. A string amount with leading zeros
  is refused in `enforce` before the judge runs, and `warn` and `observe` run it with the violation on
  the receipt. A bigint digests as its decimal string.
- **Every sink argument is read before any is rendered.** A getter on a later argument could edit an
  earlier one after its receipt entry was written, so the receipt said one thing and `execute()` ran
  another. Also fixed in 0.5.1.
- **A block and a hold share one default refusal string,** `stopped by judgment`. The receipt keeps
  the real decision, and `judgment.rationaleInRefusal` opts back in. The `held` field exists only on
  a hold, so keep it on the host side.

- **A judge is now told which values are untrusted.** `assess` receives a
  third key, `trust`, with each argument's tier and provenance. `action.args` still holds the raw
  values, which can include text an agent wrote.
- **`corroborate` promotes only what it compared (0.5.x has this bug).** A claim or reference
  that is not plain JSON is refused, so a `toJSON` or a getter can no longer compare as one value and
  promote as another, and what ascends is a deep-frozen copy. **Breaking:** a `Date`, `Map`, class
  instance or other non-JSON value no longer corroborates, even with a custom `equals`. An unjudged
  sink applies the same rule to every `Sourced` value: `enforce` refuses a non-plain value, and
  `observe` and `warn` run it with the violation on the receipt. **Breaking:** an `enforce` sink no
  longer accepts one. That includes an object with a property set to `undefined`, and `NaN`,
  `±Infinity` and `-0`, which the judged path already refused.
- **A cap now carries an asset.** `purpose.fields.asset` is optional, is narrowed by delegation
  and is checked against the payment. A sink with an asset argument and a `maxPerAction` with no
  asset refuses construction, so on that sink `1000` cannot cover every asset's decimals. A sink with
  a fixed `judgment.asset` needs no field, because the host settles the unit (`SECURITY.md`). A grant
  with no asset hashes as before.
- **A revoke reaches a judged sink built before it.** `grantedPurpose` also returns
  `isLive`, which the sink calls before judging and again immediately before `execute`. A grant no
  longer live, or one the check cannot confirm, is refused with a receipt, in every mode. A hand-built `granted` has no check and gets
  no revocation (`SECURITY.md`).
- **A verdict with a non-string, empty or whitespace-only rationale is a failed verdict.** It holds the action
  and does not stick. **Breaking** for a provider that returned an empty rationale with a `match`.
- **An invalid `redact` policy refuses construction.** A misspelled `"hash"`, or a policy for an
  argument `requires` does not declare, used to leave the value raw on a receipt that cannot be
  redacted later.
- **`sink(null)` records a refusal.** It used to reject with no receipt.
- **`mockJudgmentProvider` no longer coerces.** A payee in an array or an empty-string amount is
  a mismatch.
- **Two provider behaviours the sink cannot catch are now documented.** A throwing abort
  listener and a synchronously blocking provider are stated as limits in `SECURITY.md` and ADR 0007.
- **A judged action now has a lifecycle (ADR 0010).** In enforce, a
  block stands for a window (`blockWindowMs`, default one hour) and a hold stands until it is resolved
  or expires. A new call on either returns the existing answer without calling the judge, so a
  retry can no longer resample the judge into a `match`. Execution is claimed synchronously and
  keyed on the action plus a host-supplied idempotency key, so one approved action runs at most once
  and five concurrent identical calls run one. An `attempted` receipt is written before `execute`,
  so a failed log write can no longer make an approval reusable through a second sink. In warn and
  observe a flagged action no longer carries `authorizedBy`, and an undeclared argument no longer
  switches the judge off. `reconcile` reports one action executed twice as `duplicate-action`.
- **`requireAuthorization` (in `sweetrust-sui`) now consumes a one-shot `SpendAuthorization`** issued by the sink, so a
  verdict digest typed by a caller, or the same one three times, no longer passes. `purposeHash`
  on the verdict binds it to the purpose judged, checked by `verifyVerdictPurpose`.
- **The refusal string no longer carries the judge's assessment, confidence or rationale** by
  default, because the refusal goes to the agent. The receipt still holds them, redacted per
  `redact`. A host can opt back in with `judgment.rationaleInRefusal`.
- **A judge failure holds the call but does not stick.** The next identical call asks the judge
  again. Only a real assessment stands. A call with any violation carries no `authorizedBy` or token,
  even on a match.
- **A confident `mismatch` from an async judge no longer executes.** In 0.5.x the sink read a
  provider's Promise as if it were the verdict, so an async provider resolving `mismatch` still
  ran the action, recorded as `judgment-flagged`. TypeScript forbade that provider shape and
  JavaScript did not, so reaching it took a cast or plain JavaScript. The sink now awaits the
  provider on its one code path (ADR 0007). Regression: `test/gate/async-sink.test.ts`.
- **Doubt never moves money.** In `enforce`, a judge that throws, times out, returns a malformed
  verdict, answers `unsure`, or answers `match` below the floor leaves the action held and
  `execute` uncalled. A failed judge is recorded as `unsure` with confidence 0. A verdict that
  arrives after the deadline is discarded, and the abort signal has fired by then.
- **The judge sees a frozen view with three keys, `purpose`, `action` and `trust`.** Editing a nested
  argument during the judge's wait changes nothing that executes. A tier violation is refused
  before the judge is called, so a judge that always says `match` cannot lift a refusal.

- **A capability getter can no longer spend between the check and the record.** A `key` getter ran
  after `useCapability` had read the log, so it could call `useCapability` again and spend 150
  against a cap of 30 on a signed chain that verified. Every caller-supplied value is now a
  primitive before the first log read. A scope's `capabilities` elements are rebuilt per scope: they
  are no longer the objects you passed, and two scopes no longer share one. `capabilityKey` throws a
  `TypeError` on a non-string `key`. Also fixed in 0.5.1. Regression: `test/mandate/reentrancy.test.ts`.
- **`triggerSource` must be `"code"` or `"external"`, and `rationale` must be a string, or the call
  throws a `TypeError`.** An object with a `toJSON` used to reach the signed event, and every owner
  operation on that store then threw `AuditLogCorrupt`. `constitutionalPreCheck` throws a `TypeError`
  on anything that is not a string. Also fixed in 0.5.1.
- **`listAllSigned()` returns a copy.** A `.pop()` on the live array un-revoked a mandate, and the
  shorter chain verified. Also fixed in 0.5.1.
- **A revoke is always recorded.** A rationale that trips the injection screen no longer refuses the
  revoke. The record's `rationale` holds the matched pattern and a SHA-256 of the text instead, so
  the injection is not persisted. Issuing still refuses. Also fixed in 0.5.1.
- **The in-memory signer verifies only its own marker,** so a forgery naming the operator's key
  cannot pass the operator's pin through it. Also fixed in 0.5.1.
- **`grantedPurpose` refuses a revoked mandate or a revoked ancestor.** A judged sink built from a
  revoked grant used to execute. A sink built before the revoke is stopped by the action
  lifecycle's liveness check.
- **Lower items.** `grantor`, a limit's `unit` and `resumedBy` are screened before persistence, adding
  those three `inputKind` values. A child under a revoked grandparent is refused at issue.
  `SignedReceiptLog.signed()` hands out frozen records. JSONL store files are created mode 600, and an
  existing file keeps its mode. Those last three are also in 0.5.1. `SECURITY.md` now states the limits left as they are: amounts past
  2^53, a store that does not name itself, a torn append, no fsync, and `reconcile` trusting unsigned
  rows.

### Added

- **A hold can settle to its real cost (ADR 0011, amending ADR 0005).** Reusing a hold id after a
  settle voids that settle, so both invokes count at `amount`. `useCapability` takes an
  optional `holdId`, and `trust.settleCapability({ mandate, capability, holdId, actual })` records what
  the call really cost as a new `settle` event. The limit then counts `actual` in place of the invoke's
  `amount`, at the invoke's own time and still as one call. A settle only goes down and lands at most
  once, and it works on a revoked mandate. Anything the rule would not honor is refused and writes
  nothing, and a bad `settle` line already in a log is ignored, so its invoke counts at `amount`. An
  invoke with no `holdId` keeps its signed bytes. **Breaking** for a consumer that switches exhaustively
  on `MandateAuditEvent` (a new `settle` member) or `MandateError` (five new `MandateSettle*` tags).
- **`ReceiptLog.fromReceipts` and `SignedReceiptLog.fromSigned`** seed a new log from prior receipts,
  checking the chain and, for the signed log, every signature under the signer's key. A judged
  sink's blocks, holds and attempts last only as long as its log, so this is what lets them survive
  a real restart (ADR 0010).
- **A purpose on the grant.** `issueOrgMandate`, `issueProjectMandate` and `issueAgentMandate` take
  an optional `purpose: { statement, fields?: { payees?, maxPerAction?, actions? } }`. It is
  recorded on the grant event and covered by its signature. `trust.grantedPurpose(scope)` returns
  it with the grant's hash. A delegated mandate may only narrow its parent's fields: a child that
  widens one, or omits a field its parent set, is refused at issue.
- **`judgment-held`, a new `Receipt["decision"]`.** It is doubt in `enforce`: nothing ran and the
  action waits for its owner. The result carries `held: { verdictDigest, actionDigest, grantHash }`,
  the three digests an approval must name. `judgment-flagged` remains for `observe` and `warn`.
- **`sink.resume(args, approval)`, the one way a held action runs.** It takes an approval signed by
  the sink's `approvalKey`, usable once: two overlapping resumes run the action exactly once. An
  attempt that ends `errored` has used the approval, so an owner decides any retry. A refusal names
  one of `approval-unsigned`, `approval-mismatch`, `approval-expired` or `approval-replayed`. An
  altered argument is a different action, so it does not resume. Set `judgment.approvalKey`, or no hold can resume. The signature is
  Ed25519 over `canonicalJSON` of the approval's four other fields plus
  `domain: "sweetrust/approval@1"`.
- **Every judged receipt carries its verdict**: the assessment, confidence, provider, model, and
  digests of the rationale, the action, the payment and the grant. `verdictDigest(verdict)`
  recomputes its digest from the receipt alone. A resumed execution's receipt also carries the
  owner's `approval`.
- **`encodeAction`, `actionDigest`, `paymentDigest` and `verdictDigest`** from `sweetrust/gate`.
  They hash what they are given and normalize nothing, so give them the same canonical address and
  asset strings your adapter uses. A mismatch fails closed.
- **`judgment.purposeArgs`** (`{ payee, amount, asset? }`, with `judgment.network` and
  `judgment.asset`) names which arguments are the payment. The purpose's `fields` then refuse
  outside payees and amounts before the judge runs, and the verdict binds the payment's digest.
- **`execute(args, { authorizedBy })`.** A judged sink passes `{ verdictDigest, paymentDigest }` as
  an optional second argument, so a payment can name the verdict that approved it.
- **`useCapability({ verdictDigest })`** records that digest on the mandate's invoke event. An
  invoke without one signs exactly as before.
- **`reconcile({ gate, sui, chain })`** from `sweetrust/verify` compares a chain's real payments
  with your records and names each one the judge did not account for: `no-receipt`, `no-verdict`,
  `double-spend`, `payment-mismatch`, `duplicate-action` or `purpose-mismatch`. A failed chain transaction is a refusal, never an orphan. The
  `sui` rows are `sweetrust-sui` receipts.

### Changed

- ***Breaking:*** a judged enforce sink needs a log with `all()`, to read
  back its blocks, holds and attempts, and it writes an `attempted` receipt before each run, so a
  judged enforce run leaves two receipts. `Receipt["decision"]` gains `attempted`.
- **`execute`'s second argument is `{ authorizedBy, authorization }`, and it is present only on a
  confident match or an owner's approval.** A flagged run gets no second argument.
- **The sink's second argument is `{ idempotencyKey? }`, and `resume` takes the same third.** The
  key comes from the host and must never come from the agent.

- ***Breaking:*** every sink call returns a Promise. `execute` gains the optional second argument
  above, and a rejected async `execute` rejects the sink's promise.
- ***Breaking:*** `JudgmentProvider.assess` is async and takes `({ purpose, action, trust }, signal)`.
  `judgment.timeoutMs` sets its deadline (default 5,000 ms; at most 2^31-1).
- ***Breaking:*** a judged sink requires `judgment.granted`, and a grant with no purpose is a
  `TypeError` when the sink is built, never a surprise at runtime.
- ***Breaking:*** the receipt hash body gains two optional keys, `verdict` and `approval` (ADR
  0009). Omitting them keeps the 0.5.x bytes. A raw argument containing a `$bigint` key is now a
  tier-wall violation, because that key is the action encoding's own marker.
- A `Receipt["decision"]` consumer must handle `judgment-held` and `attempted`.
- `reconcile` reports a failed chain transaction as `payment-mismatch` when a `sweetrust-sui` spend receipt claimed it
  `executed`: the record contradicts the chain, so it is not read as a clean refusal.

### Notes

- **The check is off chain** (ADR 0008). Nothing on Sui refuses a spend no judge saw. `reconcile`
  finds it afterward, by comparing the chain with your records.
- **`reconcile` catches bypass and omission, not forgery by the log key's holder.** It also does
  not surface a verdict that executed at the gate with no payment leaving: that is not a payment.
- **`reconcile` is only as true as its chain list**, and `sweetrust-sui`'s `chainSpends` reads an
  unauthenticated indexer. `SECURITY.md` now says what that means.
- **The first end-to-end run used the stand-in judge.** It proves the records join, not that any
  model judges well.

## [0.5.1] — 2026-11-08

A security patch. No call shape, error union, receipt hash or signed preimage changes, and existing
logs verify as before. Code that compares capability objects needs one change, described under
*Changed*.

Upgrade if untrusted code can hand objects to this library in your process, or if a revoke
rationale can quote untrusted text.

### Security

- **A capability object cannot overrun a spending cap from inside the check.** An object with a
  `key` getter could run between the log read and the limit check, re-enter `useCapability`, and spend
  150 against a cap of 30 on a signed chain that still verified. In `useCapability`, every caller value is now
  read before the first log read.
- **A quoted injection no longer blocks a revoke.** A rationale that quoted an injection pattern made `revokeMandate`
  throw and left the mandate live. The record now carries the matched pattern and a hash in place
  of the text.
- **Reading the log cannot un-revoke a mandate.** `listAllSigned` returned the live array, so a
  `.pop()` undid a revoke and the chain still verified. It now returns a copy.
- **A poisoned field cannot brick the store.** A `triggerSource` carrying a `toJSON` made the signed
  bytes differ from the file bytes, and every later owner operation threw. A `triggerSource` or
  rationale that is not what its type says is now refused.
- **The in-memory test signer checks the key.** Its `verify` ignored the record's key, so a forged
  record could pass a real pin.
- **A sink reads every argument before rendering any.** A getter on a later argument could edit an
  earlier one after its receipt entry was written, so the receipt and `execute()` disagreed.
- **Smaller fixes.** A child can no longer be issued under a revoked ancestor; `signed()` records
  are frozen; a store file is created mode 600 (an existing file keeps its mode).

### Changed

- A scope's `capabilities` elements are now its own copies, so `scope.capabilities.includes(cap)`
  and `=== cap` are false where they were true. Compare `.key`. Extra fields on a capability object
  are dropped.
- In plain JavaScript, a `grantor` or `triggerSource` that is not what its type says now throws. That
  includes `triggerSource: null`.

### Documentation

- `SECURITY.md` now states that a cut log tail refunds spend, that nothing in this package detects
  a cut tail on a mandate log, and how a torn append fails.

## [0.5.0] — 2026-11-02

**Upgrading from 0.4.0.** These call shapes change; each is a *Breaking* bullet below.

```ts
// 0.4.0: useCapability(args, store), and likewise the three issuers and revokeMandate
const trust = createTrust({ store })   // once, where you build the store
trust.useCapability(args)              // the same args, no store
```

```ts
// 0.4.0: const r = humanConfirm(value, render)
const r = await humanConfirm(value, render) // render may now answer with a Promise<boolean>
```

A host that re-issued mandates at every boot should store the mandate ids and call
`trust.resume()` instead; a re-mint is a fresh id and a fresh budget.

### Security

- **The audit store is bound at construction, never passed per call** (ADR 0004). In 0.4.0 every
  mandate entry point took the store as a trailing argument, so a caller holding its own genuine,
  revoked scope could build a fresh in-memory store, record one forged `grant` line for its own
  id, pass that store in, and be allowed: every log check ran, against a log the caller wrote.
  Found by a stranger's review of the published package and reproduced against `dist/` on
  2026-10-31. Now `createTrust({ store })` binds the store once, and a scope is bound to the store
  that recorded its grant; a genuine scope presented to a client over a different store is refused
  with the new `MandateScopeForeign`. Regression: `test/mandate/audit-bound-client.test.ts`,
  watched red before the fix.

### Added

- **Capability limits** (ADR 0005). `issueOrgMandate`, `issueProjectMandate` and
  `issueAgentMandate` take an optional `limits`, keyed by capability key: `{ amount?, count?,
  windowMs?, unit? }`. `amount` caps the sum of what the uses spend, `count` caps how many uses
  there are, and `windowMs` makes either one rolling. "Under $30 a day, I just trust you" is
  `limits: { "amazon.buy": { amount: 30, unit: "USD", windowMs: 86_400_000 } }`.
- `useCapability` takes an optional `amount`. A capability capped by amount refuses a use that
  states none, and an amount that is not a finite, non-negative number is refused whether or not
  the capability is capped. A refused use records nothing.
- The cap is recorded in the grant event, and the spend is summed from the invoke events in the
  same audit log at every use. Nothing is counted in memory, so a restart refunds nothing, and the
  holder of a scope has nothing it can edit to reset its budget. Grant events gain `limits` and
  invoke events gain `amount`; both fields are optional, so a 0.4.0 log reads unchanged.
- A delegated mandate may only tighten its grantor's limits. A larger `amount` or `count`, a
  different `unit`, or no limit where the grantor has one is refused at issue. On windows, no
  `windowMs` means the life of the mandate, the tightest of all: a child of a lifetime cap must be
  lifetime too, and a child of a windowed cap may have no window or a window at least as long. A
  shorter window is looser, because spend falls out of it sooner, and is refused. `unit` is a
  label the kernel compares and never converts.
- The types `CapabilityLimit` and `CapabilityLimits` are exported from `sweetrust/mandate`, and a
  scope carries a read-only `limits` mirror (`{}` when none). Enforcement reads the grant event,
  never the mirror.
- What a cap does not do yet, so you can plan around it. A cap binds the scope it is written on:
  a parent's cap is not a shared budget across its children, so two agents capped at $20 under a
  project capped at $30 can spend $40 between them. Cap the agent-tier scope you hand each agent,
  to the share you mean it to have. `amount` is what the host declares; the kernel enforces the
  spend it is told, so the host, never the agent, makes that call with the true figure. Amounts
  are any finite, non-negative JavaScript number and are summed as floats, so for money use
  integers in minor units (cents).
- **`trust.resume({ resumedBy, mandateId, capabilities, tier? })`** (ADR 0006) picks an issued, unrevoked
  mandate back up from the store's log after a restart, as the same id with the same budget. You
  declare the capability set (order does not matter) and optionally the tier; the log confirms
  both. It runs the same revocation walk a use runs, so it refuses exactly where `useCapability`
  would (`MandateRevoked`, `AncestorMandateRevoked`, `DelegationChainBroken`, `MandateNotIssued`).
  It then re-checks every link of the rebuilt chain, child against parent, for capability subset
  and limit tightness, since a grant line appended to the log never passed the issuers' checks; a
  cyclic chain is refused as `DelegationChainBroken`. `resumedBy` (a `GrantorId`, required) names
  who resumed and is recorded on the `resume` event; it is the host's word, never verified.
  The scope it returns is bound to this client's store like any issued scope. Resuming twice gives
  two genuine objects over one recorded authority, and revoking the id revokes both. Only the id
  crosses the process boundary; no scope is persisted.
- A `resume` audit event (`MandateResumeEvent`) records every resume. It never counts toward a
  limit. A 0.4.0 reader that ignores unknown event types reads the log unchanged.
- `ResumedScope<Caps, Tier>` types what `resume` returns: with a declared tier, a resumed project
  can be handed to `issueAgentMandate` without a cast; with none, the scope is typed loosely and
  you narrow on `tier`.
- `grantorId(string)` builds a `GrantorId` from a non-empty string, so you no longer cast
  (`"ARTHUR" as GrantorId`). An empty or non-string argument is a `TypeError`.

### Changed

- **Breaking:** `issueOrgMandate`, `issueProjectMandate`, `issueAgentMandate`, `useCapability`
  and `revokeMandate` are no longer exported from `sweetrust/mandate` or the root. They are the
  verbs of the client returned by **`createTrust({ store })`**, with the same `args` and no store
  parameter. Migration: build your store as before, then
  `const trust = createTrust({ store })` and call `trust.useCapability(args)` where you called
  `useCapability(args, store)`. The client also exposes `audit` (`query`, `isRevoked`), a read-only
  view of the store. The binding is to the store **object**: two `makeJsonlAuditLive(path)` calls
  over one file are two stores, and the second refuses the first's scopes as `MandateScopeForeign`
  (fail-closed). Build one store per file and share it.
- The in-memory stores freeze every event they keep, and the kernel freezes every event it
  records, so an event handed back by `query` is a record and not a handle: editing a returned
  revoke can no longer un-revoke a mandate (found in the 2026-10-31 pre-review, before release).
- `MandateError` gains the variant `MandateScopeForeign { mandateId }` (0.x: the union may change
  in a minor, per § Versioning).
- `MandateError` gains four variants for capability limits: `MandateLimitExceeded` (with the
  `limit`, what was already `used` in the window, and the `requested` amount),
  `MandateAmountRequired`, `MandateAmountInvalid` (with what was `received`) and
  `LimitNotWithinGrantor` (naming the `field` that was looser). A `switch` over `_tag` that is
  exhaustive needs the new cases.
- `MandateError` gains `ResumeMismatch { mandateId, field, declared, recorded }`, raised by
  `resume` when the declared `capabilities` or `tier` is not what the log recorded; both lists are
  sorted. `MandateAuditEvent` gains the `resume` member, so a `switch` over `event.type` that is
  exhaustive needs a `resume` case.
- **Breaking:** `humanConfirm` is async. Its `render` may return `boolean | Promise<boolean>`, and
  it always returns `Promise<DeclassifyResult<T>>`, so you can ask a human who answers over a
  network: a phone, a voice call, a chat approval. Migration: add `await`; a synchronous renderer
  needs no other change. The question is still built at the call, before anything is awaited:
  provenance first, the value cut to 256 characters with its full length stated, and a bigint
  rendered rather than thrown. The value is **copied** at the call (`structuredClone`), and the
  copy is what ascends, so the value the human is asked about is the value that ascends even if
  the caller edits its own object while the human decides (a synchronous renderer left no time
  for that; a remote human leaves minutes). Two consequences: a value that cannot be cloned (a
  function, a symbol, a proxy) is refused, and a class instance is NOT refused: it ascends as a
  plain object of its own enumerable fields, its methods and `#private` fields dropped silently,
  so confirm a class whose meaning lives in private state as an explicit data object. Regression: `test/gate/human-confirm-async.test.ts`, watched red
  before the fix.
- An `async` renderer that resolves `true` now confirms. In 0.4.0 its Promise was refused unread,
  because only the literal `true` confirmed, which was safe and made a remote human impossible to
  ask. The settled answer must still be exactly `true`; `"yes"`, `1` and a resolved `"true"` are
  refusals. A call you forget to `await` hands you a Promise whose `.ok` is `undefined`, so it
  reads as a refusal rather than a confirmation. The return is a Promise even for a synchronous
  renderer for exactly that reason.

### Fixed

- `humanConfirm` returns a refusal when `render` throws or rejects, naming the error. In 0.4.0 a
  renderer that threw escaped as an exception, so a dropped call or a missing terminal surfaced
  as an outage instead of a "no". A renderer that never settles still never confirms: reject it
  from your own timeout to turn silence into a refusal.
- The README's mandate quickstart now does what it says. It was marked "run, expect true" and was
  only ever compiled. It now shows a use, a refused out-of-grant capability, a revocation and the
  refusal after it, and the README gate runs it against the built package and checks the three
  lines it prints. A README directive the gate does not recognize now fails the gate instead of
  passing unread.

## [0.4.0] — 2026-10-14

**0.4.0 is the first npm release of this package.** 0.3.0 and everything before it were never
published, so every *Breaking* bullet below is breaking relative to an unpublished tree: no
published consumer is affected.

### Security

- **Mandate authority is now possession of an issued scope, not a string** (ADR 0001).
  Before this, an agent could invoke as its ancestors by naming their mandate id, or by reading
  `agent.parentScope.parentScope`. That second path needed no cast. The same agent could also
  permanently revoke the org root by naming its grantor. Scopes the module did not issue are now
  refused with `MandateScopeForged`. That covers copies, JSON round trips, and literals that copy
  every public field. `parentScope` is now a detached view with no authority.
- **The tier ladder holds at runtime**, not only at compile time. Agent → project, project →
  project, agent → agent and org → agent now throw the new `TierLadderViolation`.
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
  Receipt arguments are rendered to a JSON snapshot BEFORE `execute()`. An argument that cannot be
  rendered is a violation, so `enforce` refuses before the action runs. The `raw` policy used to store the caller's object by reference, so editing it
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
- **Every object-taking export now reads each field of its argument once, and a test holds it
  there** (the 2026-10-13 rail audit). The mandate CRITICAL above was one function family doing
  the opposite; a harness now wraps every argument bag, nested bag, record, options bag and
  signer config in a Proxy that throws on the second read of any key, and requires the same
  verdict as on a plain object. It caught two more: `verifyAuditChain` read
  `opts.trustedSignerPublicKeyHex` inside its record loop, once per record, so a getter could pin
  a different key for each record and a chain signed by two keys verified (`verifySignedChain`
  already read it once); and `ReceiptLog.append` spread the entry twice, once into the bytes it
  hashed and once into the receipt it committed, so a getter on the entry could leave the log
  holding a receipt its own hash did not cover. Both read once now. The three declassifiers also
  read their `Sourced` arguments more than once and hand them to the ascent; a `Sourced` is frozen
  and cannot carry a getter, so nothing a caller could build reached that, and they now snapshot
  `value`, `tier` and `provenance` at the top so the rule holds for every export without an
  exception. `AGENTS.md` § Non-negotiables states the rule, and a new export that takes an object
  is added to `test/intake-poison.test.ts` in the same commit.
- **The sink no longer swallows a host's unhandled-rejection crash.** The `errored` receipt for an
  async action (above) was attached as a rejection handler on the host's own promise, and the host
  got that promise back unchanged. Attaching a handler marks a promise handled, so a host that
  forgot its own catch lost Node's crash: the action failed, the log said so, and the process
  carried on with nobody told. The sink now returns a wrapped promise that writes the receipt and
  re-raises the same error. A host that handles `result` sees exactly what it saw before; a host
  that ignores it crashes, as Node intends. See *Changed* for the one visible difference.

### Added

- `AuditLogCorrupt { storePath, line, reason, detail? }`, a new `MandateError` variant thrown by
  every read of a corrupt store.
- `TierLadderViolation { grantorMandateId, grantorTier, requestedTier }`, a new `MandateError`
  variant thrown by `issueProjectMandate` and `issueAgentMandate` when the grantor's tier cannot
  delegate the requested tier (see *Security*).
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
- **Breaking:** the host-produced `human-context` audit event names no vendor.
  `MandateHumanContextEvent` carries `externalRef: { system, id, url? }` (the new `ExternalRef`
  type) in place of `linearCommentUrl` and `linearIssueId`, and `TriggerSource` is
  `"external" | "code"` in place of `"linear" | "code"`. Nothing in this package produces the event
  or reads those fields; the shape is what a host records about a comment made in its own tool.
  No published consumer existed.
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
  `{"$number":"NaN"}` (or `"Infinity"`, `"-Infinity"`). Before 0.4.0 a BigInt was written as its
  digits plus `n`, byte-identical to the *string* `"1000000000n"`, and `null` was shared by `NaN`
  and a literal null. Hashed bytes change for those two value kinds only; every other value
  renders exactly as before, under `raw`, `hash` and `truncate` alike.
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
- **Breaking:** for an async or thenable `execute()`, `SinkResult.result` is a new `Promise` that
  settles exactly as yours does — resolving to the same value or rejecting with the same error —
  but it is **not the same object** your `execute()` returned, and a non-Promise thenable comes
  back as a real `Promise`. `await`, `.then` and `.catch` behave as before; an identity comparison
  against your own promise will not. This is what lets the sink re-raise instead of swallowing
  (see *Security*). A synchronous `execute()` is returned untouched.
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

- **`DirectConstructionRejected` is gone from `MandateError`.** Nothing ever threw it and nothing
  tested it, so a consumer's `case` for it handled a refusal that could not happen. **Breaking
  (types):** an exhaustive switch over `MandateError["_tag"]` that still names it fails to compile.
  The union has ten variants.
- **`issueMandate` and `issueRootMandate` are gone.** They were deprecated earlier in this same
  release and never shipped that way: they ship removed. Both stamped
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

## [0.3.0] — 2026-07-30 (internal, never published)

Formed by merging `@sweetrust/mandate`, `@sweetrust/gate` and `@sweetrust/verify` into one package,
then planned for the `@swee` scope. It never reached npm. The package's development history predates
this repository and is not carried forward.

### Added

- **`@swee/trust/mandate`** — type-enforced multi-tier capability mandates on an Ed25519-signed
  hash chain. Authority is issued, delegated and revoked against an append-only audit log; the
  signed preimage binds the chain link, sequence, timestamp and a domain tag, so a record cannot be
  relinked, reordered, retimed or replayed as a different protocol's message without breaking a
  signature.
- **`@swee/trust/gate`** — `Sourced<T>` provenance tiers with sticky taint, three audited
  declassifiers as the only ways a value can rise, fail-closed sinks that declare their appetite,
  and tamper-evident receipts for every decision — allowed *and* refused.
- **`@swee/trust/verify`** — signed receipt chains re-checkable from public material alone, plus an
  anchor-memo convention that makes tail truncation detectable.
- **Zero runtime dependencies.** Node builtins only.

### Notes

- Read `SECURITY.md` § *Honest limits* before adopting. It names what this package does **not**
  protect — in particular that `revokeMandate` writes only to this package's log and stops no
  money a chain already holds.

[0.6.0]: https://github.com/sweeai/sweetrust/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/sweeai/sweetrust/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/sweeai/sweetrust/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/sweeai/sweetrust/releases/tag/v0.4.0
