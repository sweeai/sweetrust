---
title:       "ADR 0008: no on-chain verdict check, so an unjudged spend is made findable instead"
kind:        adr
status:      accepted
updated:     2026-11-08
owner:       sweetrust maintainers
verified_by: "git ls-files '*.move' | wc -l prints 0 (this repository ships no Move program). That checks the absence of a program and nothing else; the reconciliation this decision relies on ships in 0.6.0 and has its own tests."
---

# ADR 0008: no on-chain verdict check, so an unjudged spend is made findable instead

**Status:** Accepted, 2026-11-07, when Danny approved the intent-layer spec. The rule it applies is Danny's, from 2026-10-14.
**Implementation:** upheld. This repository contains no Move program. The reconciliation described below is built: `chainSpends` in `packages/sui`, `reconcile` in `sweetrust/verify`.
**Force:** principle. The absence of Move source can be checked mechanically, but the condition for revisiting this decision is a judgment about what Sui has shipped.
**Date:** 2026-11-08 · **Extends:** ADR 0003 (adapters wrap audited on-chain programs and never ship their own)

## Context

The intent layer judges an action in the host, before the action runs. That protects against an
agent acting outside what its owner asked for. It does not protect against a compromised server,
because a server holding the spender key can call the chain without ever calling the judge.

Exactly one design closes that gap: a Move wrapper that refuses any spend lacking an attested
verdict. The chain's native primitive does not do this. The abort conditions `sui::allowance`
declares cover the spender, the funder, expiry, the lifetime cap, the rate limit and the like, and
none of them concerns a verdict or an attestation (`packages/sui/src/allowance-move.ts` lists them).
So the wrapper would be a program of our own.

Danny's standing rule decides that question. His words, 2026-10-14:

> "Money limits belong to wherever they're available that is wisest. So if Sui itself provides it on-chain, let's use it; if it's not, we have no choice but to not use an on-chain program."

A verdict check is a condition on whether money may move, so the rule governs it as it governs a
cap. ADR 0003 applies the same rule to the adapter: adapters wrap audited on-chain programs and
never ship a program of their own. That ADR also declined the app-bound path with an intent module,
which is the same shape as this wrapper.

## Decision

**SweeTrust ships no on-chain program that checks a verdict. Intent is enforced in the host, the cap
stays on the chain, and a spend that escaped the judge is made provable afterward.**

1. **The judge's answer is enforced in-process.** In enforce mode, a judged sink runs `execute` only
   on a match, or on an owner's signed approval of a held action.
2. **The payment names its verdict.** `spend` takes `authorizedBy: { verdictDigest, paymentDigest }`.
   A `sweetrust-sui` adapter built with `requireAuthorization: true` refuses a spend without it, or
   one whose payment digest differs from the digest it recomputes, before anything is signed. That
   is a library refusal, and it binds only spends routed through the adapter.
3. **The money limit stays with the chain's primitive.** On Sui, `sui::allowance` holds the cap, as
   ADR 0003 decided.
4. **An unjudged spend is findable.** `sweetrust-sui` exports `chainSpends`, which reads the
   transactions touching an allowance. `reconcile` in `sweetrust/verify` is pure and joins those
   transactions to the receipts. It reports an orphan spend for a spend with no receipt, a receipt
   whose verdict matches no executed gate receipt, a payment that differs from the chain's record,
   or more than one on-chain spend under one verdict.

## When to revisit

Revisit this decision when Sui ships a primitive that can check an attestation before an allowance
spend. At that point the rule quoted above points the other way, and the chain should hold the
check. The `attestation` field on the verdict is reserved as `null` for an attested judge, which
such a check would read, so filling it later does not break the format.

## What this does not do

- **It does not make intent survive a compromised server.** A server holding the spender key can
  spend without the judge, up to the cap. The chain will not refuse. The cap bounds the loss, and
  reconciliation proves the bypass afterward. Neither of them prevents it.
- **It does not catch a forged verdict.** A server holding the log key can write a `match` verdict
  that never happened, and reconciliation will pass it. Catching forgery needs a judge on a separate
  host that signs what it decided, with a hardware attestation. That is a later version.

## Alternatives considered

1. **A Move wrapper that refuses any spend without an attested verdict.** Not taken, and this is the
   strongest design on the table. It is the only way to make intent survive a compromised server.
   It is also our own on-chain program, which the rule above excludes, and it would add a deployed
   package to audit and upgrade.

## Consequences

- The repository stays free of Move, and the kernel keeps zero runtime dependencies and makes no
  chain call. `reconcile` receives its chain data from the adapter as an argument.
- Reading the guarantee correctly takes care. The in-process judge narrows what an honest host does.
  The chain bounds what a dishonest host can lose. `reconcile`, joining the log to the chain's
  transaction history, proves what a dishonest host skipped, as far as the indexer it reads is honest
  and complete (`SECURITY.md`).
  Documentation must keep those three claims apart.
- `sweetrust-sui` gains a read path against the chain's transaction history, and that path depends
  on how much history an indexer retains.
