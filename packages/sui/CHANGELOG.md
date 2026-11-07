# Changelog — `sweetrust-sui`

All notable changes to this package. Format follows [Keep a Changelog](https://keepachangelog.com);
this package follows [Semantic Versioning](https://semver.org).

## Versioning

`sweetrust-sui` is 0.x: **a minor version may break.** Until 1.0 these may change in a minor: the
receipt shape (`schema: "sweetrust-sui/receipt@1"` names it, and a change bumps it), the
`RefusalCode`, `LimitVerdict` and `HeldBy` unions, and the `enforces` declaration (a limit moves
from `library` or `nobody` to `chain` when a Sui primitive with a public package can hold it). The
`why` sentences are written for people and may be reworded in any release: match on `code` and
`native`, never on `why`.

## [Unreleased]

The first release, 0.1.0. Not yet on npm. Out of 0.1, so you can plan around it: app-bound
allowances (`allowance::propose_for_app`, the slot a Sui agent product with a public package fills
later, which is where recipients and a per-payment cap can move on chain); reserve-then-commit
spends (Sui settles each spend, so `spend` is one step); and mainnet spends (the module is present
on mainnet; this package has spent only on testnet). Tested against `@mysten/sui` 2.35.0 only.

### Added

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

