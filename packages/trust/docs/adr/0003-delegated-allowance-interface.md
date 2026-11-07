---
title:       "ADR 0003: one delegated-allowance interface, a conformance suite, and one reference adapter (Sui)"
kind:        adr
status:      accepted
updated:     2026-11-06
owner:       sweetrust maintainers
implementation: in-progress
verified_by: "pnpm -C packages/sui test (test/receipts.test.ts: every verdict's receipt and WHY text against a mocked fullnode; test/conformance/fixture.test.ts: every `chain` label backed by a recorded refusal) + SWEETRUST_SUI_TESTNET_KEYS=… pnpm -C packages/sui test:testnet (four Sui refusals on testnet 2026-11-07 UTC, digests in packages/sui/test/conformance/testnet-digests.json)"
---

# ADR 0003: one delegated-allowance interface, a conformance suite, and one reference adapter (Sui)

**Status:** Accepted, 2026-11-06, on Danny's three rulings (below). The draft of 2026-10-14 asked six questions; each is answered at the end.
**Implementation:** in progress. `packages/sui` (`sweetrust-sui` 0.1.0, unreleased) implements the interface for Sui and passes the conformance suite on testnet. Publishing it is a separate word.
**Force:** the `enforces` declaration is held to evidence. Every limit it labels `chain` has a recorded Sui refusal (`packages/sui/test/conformance/fixture.test.ts` fails if one is missing), and every limit it labels `nobody` is refused at `open()` (`packages/sui/test/receipts.test.ts`).
**Date:** 2026-10-14 (draft) · 2026-11-06 (accepted) · **Ticket:** DAN-1259 · **Extends:** ADR 0001 (authority is in-process possession) and the `SECURITY.md` boundary that money limits are not the kernel's job.

## Context

The kernel (`mandate`, `gate`, `verify`) names no chain and makes no chain call. That is deliberate and it is what makes the zero-dependency claim true. But the kernel's own honest limit says the money cap belongs to an on-chain program, and nothing in 0.4.0 or 0.5.0 says how a host reaches one.

The one seam that existed before 0.4.0, `ChainCage`, was drawn around a retired custom Move cage: it took funds *into* an escrow, had no rate, and its only adapter wrapped a testnet package rather than `sui::allowance`. It was kept out of the publish for that reason. Every primitive that actually exists is the opposite shape: **a delegated allowance against the owner's live balance**. `sui::allowance` (on mainnet; read there 2026-11-06 at protocol 141), SPL Token `approve`, Squads spending limits, Permit2 and Coinbase Spend Permissions all fit that sentence; none fits an escrow.

The 10-14 ruling fixed the delivery order: the interface is chain-agnostic, the first and only adapter for now is Sui, and Solana and Base are documented contracts until a named user asks or a Sui agent product absorbs the Sui adapter. The principle that governs every line below, in Danny's words of 10-14 late evening: *money limits belong to wherever they are available that is wisest.* When the chain offers a limit, the chain enforces it, because a contract's rule binds every caller and in-process TypeScript can be routed around. When the chain does not offer it, the library holds it in-process and the receipt says so. Squads and Spend Permissions are audited on-chain programs and qualify. (An earlier phrasing, "never to our process," was his word too extreme; it is withdrawn.)

On 2026-11-06 he added the rule that governs the inventory below: *"Anything in the Sui stack or repos ecosystem that is going to help us, we have got to leverage."* So no limit is labeled `library` until the Sui primitives that could hold it on chain have been listed, and the receipt names that successor.

## The rulings (Danny, 2026-11-06)

1. **Degrade with labels, and refuse what nobody can hold.** The chain holds what it can; the library holds what it can of the rest; every receipt labels each limit `chain` or `library`. A limit nobody can hold is refused at `open()`, never silently dropped. (This answers draft question 1. Fail-closed-on-anything-unheld-by-the-chain was the alternative; it was not taken, because it would refuse every allowance with a recipient list on Sui today.)
2. **Build first; teach from running code.** The draft's rule that no types or adapter code exist before the design sitting is withdrawn by its owner. Sitting 4 of the SweeTrust course teaches from the running adapter.
3. **The package is `sweetrust-sui`.** Pushing to the public repository and publishing to npm are separate words.

And one standing instruction for the receipts, in his words: *"be very communicative on the receipt about WHY SweeTrust judged something outside a limit."*

## Decision

**One interface, `DelegatedAllowance`, describing what a principal grants a spender against the principal's own balance:** the network (a CAIP-2 string), the asset, the spender, and the limits: a lifetime cap, a rate (amount per window), a start and an expiry, an optional recipient list, and an optional per-spend maximum. Four verbs: `open` · `spend` · `revoke` · `remaining`. It lives in the adapter package (`packages/sui/src/interface.ts`), not in the kernel, and a second adapter implements the same types.

**Every adapter declares, limit by limit, who holds each limit on its chain: `chain`, `library` or `nobody`.** One `enforces` declaration per adapter. Every receipt repeats the label on a line per limit, `{ limit, value, heldBy, verdict, why }`, so "past the cap is impossible" is a per-chain, per-limit fact a reader can check on the receipt. `open()` refuses an allowance that carries a limit labeled `nobody`, with a receipt that says so and names the limit's on-chain successor.

**Refusals are results, never thrown errors, and they say why.** A refusal carries a neutral `code` (the same word on every chain: `rate-exceeded`, `lifetime-cap-exceeded`, `not-started`, `expired`, `recipient-not-allowed`, `limit-unheld`, …), who refused (`chain` or `library`), the chain's own words quoted beside it (`native: { module, abortName, abortCode, rawAbortCode }`, or null when the library refused), and a `why` in plain English with the numbers that decided it. A library refusal says it was refused in-process and that this protects only spends routed through the library. A pre-flight check of the chain's own rules (Sui's `ENoLimit`, `ENoExpiration`) explains the rule in words and quotes the abort the chain would have raised.

**A spend executes for real.** The adapter submits the transaction; when the chain refuses, the refusal is a failed transaction with a digest, which costs the spender gas and is exactly what makes it a record a stranger can look up. On Sui this needed one deliberate choice: the gRPC and GraphQL transports resolve every transaction by simulating it server-side and throw when the simulation aborts, so a refused spend would never reach the chain and would leave no digest (Basecamp's 2026-10-08 refusal has none for this reason). The adapter builds with the SDK's generic resolver, which simulates only to estimate gas, and always sets the gas budget.

**Receipts carry the network and the transaction digest,** and can be appended to a SweeTrust `ReceiptLog` or `SignedReceiptLog`, so `verifySignedChain` re-checks them beside every other receipt the host signs. The adapter's account enters that log at tier `untrusted`: it is a claim, and the digest is what a stranger checks.

**Adapters wrap audited on-chain programs; they never ship a program of their own.** The Sui adapter wraps `sui::allowance` through the **plain path**: `allowance::new` (signed by the funder, no app module) and `allowance::balance_spend` (signed by the spender). The app-bound path (`propose_for_app<T, A>`) is out of 0.1. It is the slot a Sui agent product (Agent Payments, Agent Pass) fills when one ships a public package, and it is where recipients and a per-payment cap could move on chain. Each adapter is its own package with its chain SDK as a peer; the kernel package stays at zero dependencies and no chain subpath.

**Reserve and commit are deferred, not dropped.** The draft gave spend two steps for chains that settle in batches. Sui settles each spend, so the 0.1 interface has one `spend`. The two-step shape is additive and arrives with the first adapter whose chain batches.

**The conformance suite is the contract.** Any adapter must show: every limit it labels `chain` refused by the chain in a recorded transaction, abort quoted; every limit it labels `library` refused in-process before sending; every limit it labels `nobody` refused at `open()`; and every receipt labeling each limit. For Sui: `packages/sui/test/receipts.test.ts` (mocked fullnode) and `packages/sui/test/conformance/` (testnet, env-gated, digests committed).

## What on Sui could hold each limit

The inventory Danny's 11-06 rule requires before anything is labeled `library`. "Verified" means read from source or exercised on chain in this change; every other row is marked with where it came from.

| Limit / need | Sui primitive that can hold it | Status 2026-11-06 | 0.1 label |
|---|---|---|---|
| lifetime cap, rate, start, expiry | `sui::allowance`, plain `new` | **Verified:** module read from source (`allowance.move`); `new`, `balance_spend`, `revoke` present on mainnet (protocol 141) and testnet (protocol 140); all four limits refused on testnet by this package's conformance run. Mainnet-live since 2026-10-09 per an earlier check, not re-verified here | `chain` |
| revocation | `sui::allowance::revoke` + the funder's soulbound `AllowanceCap` | **Verified:** source, and exercised on testnet | `chain` |
| recipients / allowed payees | (a) `sui::allowance` app-bound path, `propose_for_app<T, A>`: needs an audited app module `A`; (b) Sui Agent Payments' grant, "allowed services" | (a) **Verified** present on mainnet and testnet; that no audited public app module exists from Mysten is **unverified** (none found). (b) **Not re-verified here:** read by the vision lane at sui.io/agentpayments on 2026-11-06 as testnet only, invite-only, no public package or docs | `library`, successor (b) named on every receipt |
| per-payment cap | Sui Agent Payments' grant, "per-payment cap" ("enforced onchain at settlement") | **Not re-verified here:** same source as (b) | `nobody`: refused at `open()`, successor named |
| receipt storage | Walrus (blob storage) | Live, per the coordinator's inventory; **unverified here** | out of 0.1; note only |
| receipt anchor (tail-truncation defense) | a Sui transaction or object carrying the chain head, in `sweetrust/verify`'s anchor-memo convention | The convention and `parseAnchorMemo` exist in the kernel (**verified**, source); writing the anchor on Sui is possible today and not built | out of 0.1; note only |
| who may decrypt receipts or stored secrets | Seal | Live, per the coordinator's inventory; **unverified here** | not a payment limit; note only |
| intent, judge | Agent Pass, Warrant, "Verifiable Agent Arbiter" | Announced, no code, per the 2026-11-06 Sui pulse; **unverified here** | out |

Why the per-payment cap is `nobody` rather than `library`: a cap on one spend held in-process is undone by splitting a payment into several, and the rate and the lifetime cap, which Sui holds, already bound the total. Holding it in the library would put a label on the receipt without a guarantee behind it. When a Sui primitive with a public package can hold it, the adapter moves it to `chain` and `open()` stops refusing it.

## Consequences

- The kernel's public API does not change. `packages/trust/package.json` is untouched, the kernel keeps zero runtime dependencies, and there is no chain subpath. The interface and the adapter are additive and live outside the kernel's export map.
- `sweetrust-sui` declares `@mysten/sui` (≥ 2.35.0, tested on 2.35.0) and `sweetrust` (0.5.x, for the `ReceiptLog` type) as peers, and needs Node ≥ 22 because `@mysten/sui` does. The kernel's own floor stays Node 20.19.
- A host that chooses a chain whose primitive lacks a limit (SPL `approve` has no rate and no expiry) gets the limit from the library, labeled as such, in-process, with the honest limit attached. It is not silently the same guarantee.
- A refused spend costs the spender gas. That is the price of a refusal a stranger can look up, and the README says so.
- Library-held limits (recipients) live in the handle `open()` returns, not on chain. A host that restarts and keeps spending through the library must persist that handle.
- Nothing here claims Agent Pass or Agent Payments is usable. As of 2026-11-06 neither has a public package; the app-bound path is the slot, not the product.

## Alternatives considered

1. **Keep `ChainCage` and add a rate.** Rejected: the escrow shape is the error, not a missing field.
2. **One SweeTrust per chain.** Rejected: three kernels is fragmentation, and the authority intents live above the chain.
3. **Three adapters at once.** Withdrawn 10-14 on Danny's ruling: his attention per adapter design is the scarce input; one translator proves the design.
4. **Refuse to open an allowance the chain cannot fully enforce** (fail closed). Not taken, ruling 1. Kept for the limit nobody can hold.
5. **The app-bound path for 0.1, with an intent module for recipients and per-spend** (the draft's proposal; Basecamp's `intent.move`). Not taken, ruling 2: no Move of our own, ever. Basecamp's module was demo code.
6. **Let the library pre-check the chain-held limits before sending,** so a refused spend costs no gas. Not taken in 0.1: the refusal would then come from the library and leave nothing on chain, which is the opposite of what the `chain` label promises. A host that wants a free pre-check can call `remaining()`.

## The draft's questions, answered

1. **Degrade with labels, or refuse to open?** Degrade with labels; refuse only what nobody can hold (ruling 1).
2. **`sui::allowance` alone, or with an intent module?** Alone, on the plain path (ruling 2). The app-bound slot is reserved for a Sui agent product with a public package.
3. **Does `remaining()` mean anything when the chain is the source of truth?** Yes, because it reads the chain: the shared `Allowance` object (lifetime cap minus `current_spend`; the rate's `spent` in the current window, reset exactly as `charge` resets it; start and expiry) and the chain's `Clock`. It mirrors nothing in memory. It does not read the funder's balance, which can be lower, and it says so.
4. **Where does the agent's key live?** On the host, as the spender. The adapter's job is to put that key on a bounded allowance against the principal's balance; a hijacked host holds the key and can spend whatever the chain-held limits allow. That is stated in the README's honest limits, not solved here.
5. **The refusal enum, and is quoting the native abort enough?** The neutral codes are in `packages/sui/src/interface.ts`. Quoting is enough when paired with the digest: the abort sits in the failed transaction's effects, and the conformance suite re-reads each recorded refusal from the chain by digest rather than trusting the adapter's receipt.
6. **CAIP-2 for Sui.** `sui:mainnet`, `sui:testnet`, `sui:devnet`, following the Mysten-authored x402 Sui spec (x402-foundation/x402#3081, commit `f5b8e476`). Whether the ChainAgnostic registry itself lists a `sui` namespace is still unverified.
