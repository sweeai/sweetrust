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

The first release. Not yet on npm. It needs `sweetrust` 0.6.0, and its first public receipt format
is receipt@2, so no consumer of receipt@1 exists. Out of 0.1, so you can plan around it: app-bound
allowances (`allowance::propose_for_app`, the slot a Sui agent product with a public package fills
later, which is where recipients and a per-payment cap can move on chain); reserve-then-commit
spends (Sui settles each spend, so `spend` is one step); and mainnet spends (the module is present
on mainnet; this package has spent only on testnet). Tested against `@mysten/sui` 2.35.0 only.

### Added

- **Each spend can name the verdict that approved it.** `spend` takes an optional
  `authorizedBy: { verdictDigest, paymentDigest }`, and every receipt@2 repeats it, `null` when
  none was given. With `suiAllowances({ requireAuthorization: true })`, the adapter recomputes the
  payment digest from what it would actually send and refuses, as `not-authorized`, a spend with no
  `authorizedBy` or a different digest. That check runs first, so a refused payment signs nothing.
  Like the recipient list, it binds only spends routed through this library.
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
