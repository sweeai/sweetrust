# Changelog — `sweetrust-sui`

All notable changes to this package. Format follows [Keep a Changelog](https://keepachangelog.com);
this package follows [Semantic Versioning](https://semver.org).

## Versioning

`sweetrust-sui` is 0.x: **a minor version may break.** Until 1.0 these may change in a minor: the
receipt shape (`schema: "sweetrust-sui/receipt@2"` names it, and a change bumps it), the
`RefusalCode`, `LimitVerdict` and `HeldBy` unions, and the `enforces` declaration (a limit moves
from `library` or `nobody` to `chain` when a Sui primitive with a public package can hold it). The
`why` sentences are written for people and may be reworded in any release: match on `code` and
`native`, never on `why`.

## [0.1.0] — Unreleased

The first release. Not yet on npm. It needs `sweetrust` 0.7.0, because 0.6.0 ignores `judgment.spelling`, and its first public receipt format
is receipt@2, so no consumer of receipt@1 exists. Out of 0.1, so you can plan around it: app-bound
allowances (`allowance::propose_for_app`, the slot a Sui agent product with a public package fills
later, which is where recipients and a per-payment cap can move on chain); reserve-then-commit
spends (Sui settles each spend, so `spend` is one step); and mainnet spends (the module is present
on mainnet; this package has spent only on testnet). Tested against `@mysten/sui` 2.35.0 only.

### Security

- **A spend's amount past u256 can no longer stall your process.** `spend` used to format and write out
  the amount before refusing it, and an agent's `1n << 1073741000n` never returned. Now an amount
  whose size is past u256, positive or negative, is refused at once as `invalid-amount` with one
  fixed sentence, and the receipt's `amount` and `amountText` are `null`. With an authorization
  presented it is `not-authorized` and is never digested, and a genuine token presented with it is
  not consumed, so it still pays the payment it approved. Amounts up to u256 read as before (DAN-1463).
- **A hand-built handle whose asset the Sui SDK cannot parse as a coin type is rejected at intake.**
  `spend`, `revoke` and `remaining` throw a `TypeError` naming `allowance.asset is not a coin type`
  before any chain read, instead of the SDK's raw `Invalid struct tag` from inside the send. Calls
  that used to answer with such a handle now throw, as any malformed handle does: `remaining` used to
  return a status, `revoke` a `not-submitted` or `errored` receipt, and `spend` an `invalid-amount`,
  `wrong-network` or `not-authorized` receipt. A handle from `open` is unaffected (DAN-1463).
- **A limit past u256 can no longer stall your process either.** A receipt writes each limit out, and
  a `lifetimeCap`, `rate.amount` or `perSpendMax` of `1n << 1073741000n` never finished formatting.
  On a hand-built handle, such a limit (positive or negative) now makes `spend`, `revoke` and
  `remaining` throw a `TypeError` naming the field and u256, before any chain read; `open` never
  returns such a handle. At `open`, a grant with one is still refused as a result, with the same
  code as before (`invalid-limit` for the cap and the rate, `limit-unheld` for `perSpendMax`), and
  the value reads as "an amount past u256 (not written out)" in the sentence and the limit lines.
  Limits up to u256 read exactly as before (DAN-1469).

- **`chainSpends` now finds a spend from what moved, not from the command list.** It lists a
  transaction when an input withdraws from this allowance (`FUNDS_WITHDRAWAL`, `source:
  SENDER_ALLOWANCE`), so a spend through your own Move module no longer reads clean, and the asset
  comes from that input. A transaction that merely passes the allowance as a shared object is no
  longer a spend, so a stranger cannot plant a false orphan for gas. `app_balance_spend` counts too.
- **A listed spend whose credit does not equal its debit is unreadable** (`amount` and `recipient`
  null), so a skim no longer reports the debit as the amount received. A spend of more than one
  withdrawal in a transaction is unreadable the same way.
- **A custom indexer that shows neither a spend nor the allowance's creation now throws**, so it
  cannot read as "no spends". `chainSpends` trusts its indexer; see `SECURITY.md`.

### Added

- **`suiPaymentSpelling`, Sui's canonical form of an address and a coin type.** Pass it as a judged
  sink's `judgment.spelling` so a respelled payee is refused before a judge runs. A sink's `asset`
  and a purpose's `payees` must then be in the long form it returns, and something that is not an
  address or a resolved coin type is refused too. A coin type over 1,024 characters or 16 sets of
  type arguments is refused before it is parsed, because the parser runs on agent input (DAN-1457). The same limits apply to `open` and to the
  asset on any handle passed to `spend`, `revoke` or `remaining`. `open` also refuses a type that grows past them once normalized, so it
  cannot issue a handle it could not then revoke, and a handle's ids are bounded the same way (DAN-1458).

- **`spend` refuses a recipient that is not in canonical form**, as `invalid-address`, and the refusal
  names the canonical spelling. It used to normalize silently, so a respelled payee could be paid
  from a sink that had not set `judgment.spelling` (DAN-1458).

- **Each spend is authorized by a one-shot token (ADR 0010, DAN-1406).** `spend` takes
  `authorization`, the `SpendAuthorization` a sink hands its `execute`, and every receipt@2 repeats
  its `authorizedBy`, `null` when there was none. With `suiAllowances({ requireAuthorization: true })`,
  the adapter recomputes the payment digest from what it would actually send and refuses, as
  `not-authorized`, a spend with no live token, a token for a different payment, a reused token,
  or a digest typed by a caller, which is not a token. That check runs first, so a refused payment
  signs nothing, and it binds only spends routed through this library. `authorizedBy` stays as an
  optional unchecked annotation without `requireAuthorization`. The recorded
  `test/conformance/intent-e2e.json` predates the new verdict shape and is marked stale, and
  `scripts/intent-e2e.ts` needs a testnet re-run to regenerate it.
- **`chainSpends({ allowanceId, network, graphqlUrl? })`** lists an allowance's real
  `balance_spend` transactions from the chain's indexer, owing nothing to any receipt of ours. An
  unreachable indexer, or one that does not know the allowance, throws, so silence never reads as
  "no spends". The indexer trails the chain by moments: wait for your spend to appear before
  passing the list to `reconcile`, or a fresh spend reads as missing.
- **One judged payment, proven end to end on testnet.** `scripts/intent-e2e.ts` issues a mandate
  with a purpose, runs a judged sink, spends, reads the chain and reconciles. Transaction
  `8yqHCsi6Ns9pKUE2sHr6iu4s5eLB4MndtVTWub2ZC6gV` is in `test/conformance/intent-e2e.json`: the
  invoke event, the gate receipt and receipt@2 carry the same verdict digest, with zero orphans.
  That run used `mockJudgmentProvider`, so it proves the records join, not a model's judgment.

- **`suiAllowances({ client, network, scale?, log?, gasBudget? })`**, SweeTrust's delegated-allowance
  interface (ADR 0003) on Sui's native allowance, `0x2::allowance`, plain path. Four verbs: `open`
  (the funder signs `allowance::new`), `spend` (the spender signs `allowance::balance_spend`),
  `revoke` (the funder's `AllowanceCap` deletes the allowance) and `remaining` (reads the allowance
  object and the chain's clock). No Move code of its own.
- **One `enforces` declaration**: lifetime cap, rate, start and expiry are held by the chain;
  the recipient list by the library, in-process, before sending; a per-spend maximum by nobody,
  so `open()` refuses an allowance that asks for one instead of dropping it.
- **Receipts that say why.** Every verb returns an `AllowanceReceipt` with the CAIP-2 network
  (`sui:testnet`, `sui:mainnet`), the transaction digest and an explorer link, and one line per
  limit, `{ limit, value, heldBy, verdict, why }`. A refusal carries a neutral `code`, who refused,
  the chain's abort quoted (`native: { module, abortName, abortCode, rawAbortCode }`) and a
  plain-English `why` with the numbers that decided it. Every library-held or refused limit names
  its on-chain successor (Sui Agent Payments, testnet-only with no public package as of
  2026-11-06).
- **A refused spend executes.** It is a failed transaction with a digest, so the refusal is on
  chain for anyone to read. The adapter builds transactions without the transport's
  simulate-first resolver, which would have thrown the refusal away before it reached the chain,
  and sets the gas budget itself (default 0.01 SUI; a refused spend costs the spender gas).
- Pre-flight checks of Sui's own rules at `open()` (`ENoLimit`, `ENoExpiration`,
  `EZeroLifetimeCap`, `EBadTimeWindow`, `EBadRateLimit`, `ENameTooLong`), refused with no
  transaction and the rule explained.
- `log`: every receipt is also appended to a SweeTrust `ReceiptLog` or `SignedReceiptLog`, at tier
  `untrusted`, so `verifySignedChain` re-checks it.
- `defineScale`, `SUI` and `baseUnitsOf`: how amounts read on receipts. A scale is a label and a
  divisor; it converts nothing on chain, and receipts keep the base-unit amount beside it.
- A testnet conformance suite (`pnpm test:testnet`, needs `SWEETRUST_SUI_TESTNET_KEYS`): one
  recorded Sui refusal per chain-held limit, each re-read from the chain by digest. The digests
  from 2026-11-07 (UTC) are in `test/conformance/testnet-digests.json`, and an offline test holds
  every `chain` label in `enforces` to a recorded refusal.
- **An `errored` verdict for a spend whose outcome is unknown.** If submitting throws (a timeout,
  a dropped connection), the adapter re-reads the transaction by its digest, which it computes
  before sending. It reports `executed` or the chain's refusal when the chain can say, and
  `errored`, carrying the digest, when it cannot. A thrown submit is never reported as a refusal,
  so a retry cannot pay twice or open a second allowance. Look the digest up before retrying.
- A limits object with a key outside the six (`recipient`, `maxPerSpend`, …) is refused at intake,
  so a misspelled limit is never silently dropped.
- Spend receipts print each chain-held limit from the allowance object on chain, not from the
  handle passed to `spend()`, and flag any difference between the two. `spender` is the address
  that actually signed.
- **The client is checked against `network` before the first transaction.** On `sui:mainnet` and
  `sui:testnet` the adapter compares the client's genesis checkpoint with the network's, once, and
  refuses with `wrong-network` (nothing sent) when they differ, so a receipt never names a network
  the transaction did not run on. Devnet and localnet are reset to new geneses, so they are not
  checked. A failed check refuses with `not-submitted` and is tried again on the next send.
  `remaining()` makes the same check, and refuses to answer (it throws) for a handle from another
  network, where the allowance would not be found and would look revoked.
- **A guard on the one SDK hook the adapter relies on.** A refusal reaches the chain only because
  the adapter keeps `@mysten/sui` from simulating first, through `resolveTransactionPlugin`. If a
  release of `@mysten/sui` ever builds without consulting it, the adapter sends nothing and
  refuses with `not-submitted`, naming the cause, instead of risking a refusal with no digest.
  The hook is unchanged through `@mysten/sui` 2.39.1 (its `resolve.mjs` is byte-identical to 2.35.0's).
- A rounded amount on a receipt is marked and carries its exact base units, e.g.
  `≈24.00 testUSD (2,400,049 base units)`, so the sums in a `why` stay true. Exact amounts read as
  before.
- Nothing that runs after a transaction is sent can throw away its receipt: a custom `explorer`
  function that throws costs the receipt its link; a `now` clock that throws or returns a fraction
  falls back to the system clock; a malformed `explorer`, `scale` or `now` is refused when the
  adapter is created; a rate window of any value can be written into a receipt; and an `open()`
  whose effects cannot be read is `errored`, with its digest, instead of throwing.
- A chain-held limit that the handle passed to `spend()` claims but the allowance on chain does not
  hold is shown as `unchecked` ("none on chain"), never as a zero limit Sui checked.

### Fixed

- **A read of nothing is never read as "revoked" or "nothing moved"** (audit 2026-11-08, R2, R4).
  A signed transaction whose outcome is unknown is `errored` with its digest, even when the
  allowance is gone, since the spend may have landed before whatever removed it. Only an explicit
  deleted or not-found `ObjectError`, three reads in a row, counts as absence, and a receipt or
  status words it as "not found". A `not-found` limit line is `unchecked`; `revoked` now appears
  only on an executed revoke's receipt. The `allowance-gone` code is renamed `allowance-not-found`
  and means no transaction was signed; a revoke that returns it did NOT run, so it never reads as done.
- **`remaining()` answers "could not be determined" instead of guessing.** `exists`, `active` and
  `spendableNow` are `null` when the read cannot say, and `at` is `null` when the chain's clock
  cannot be read (R9). It no longer borrows this machine's clock or throws on a failed read of the
  allowance. `rate.spentInWindow` and `rate.remainingInWindow` are `null` without a clock.
- **The receipt digest is the digest of the signed bytes** (R8). A node that answers with another
  digest has not answered about this transaction: the adapter asks for the signed digest instead,
  and reports `errored` when the chain cannot confirm it.
- **`""` and short addresses are refused, not padded** (R7). `""` used to pass and burn to the zero
  address, and `0x12` to pay a real address nobody named. `spend` refuses them with a receipt
  (`invalid-address`); `open` does the same for a spender or a recipient list.
- **A `Scale` binds to a coin type** (R9). `defineScale({ coinType })` names the asset; the adapter
  applies a scale only to that coin, shows any other asset in base units, and refuses an unbound
  scale when the adapter is constructed. The README's example binds `testUSD` to SUI.
