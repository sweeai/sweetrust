---
title:       "ADR 0005: a capability limit lives in the grant event and is counted from the audit log"
kind:        adr
status:      accepted
updated:     2026-11-08
owner:       sweetrust maintainers
verified_by: "pnpm -C packages/trust test (test/mandate/limits.test.ts, 30 cases watched RED on 2026-10-31 before the implementation; test/intake-poison.test.ts, the limits case)"
---

# ADR 0005: a capability limit lives in the grant event and is counted from the audit log

**Status:** Accepted
**Force:** invariant. The check is `test/mandate/limits.test.ts`, "the limit lives in the grant event, and the spend lives in the log".
**Date:** 2026-11-01 · **Extends:** ADR 0001 (authority is possession), ADR 0004 (the store is bound at construction)

## Context

Through 0.4.0 a mandate could say *which* capabilities an agent holds and nothing about *how much*.
The 2026-10-31 dogfood-readiness review put it plainly: "no amount/budget/limit type anywhere in
mandate." The rule the kernel is being built to hold, in its owner's words, is "under $30 I just
trust you." A kernel that cannot write that sentence down cannot enforce it, and the host would
have to keep the budget in a counter of its own, in memory, next to the agent.

A counter next to the agent has two failures. It dies with the process, so a restart is a refund.
And it lives where the holder of the scope can reach it, so the thing being limited can reset the
limit.

## Decision

A grant may carry `limits`, a per-capability `CapabilityLimit { amount?, count?, windowMs?, unit? }`.

1. **The limit is recorded in the grant event.** The scope carries a frozen mirror for the host's
   convenience, but enforcement reads the event. Under a signed store the event cannot be
   rewritten; under any store it cannot be edited through the scope.
2. **The spend is summed from the invoke events of the same log at every use.** `useCapability`
   takes an `amount`; the kernel records it on the invoke event and, before allowing the next use,
   sums the amounts (and counts the events) already in the log for that mandate and capability,
   inside the rolling window if one is set. There is no counter in memory. The verdict after a
   restart is the verdict before it.
3. **A child may only tighten.** At delegation the child's limit on every capped capability it
   carries must exist and be at least as tight as the grantor's *recorded* limit: no larger
   `amount` or `count`, the same `unit`, and a window that cannot out-spend the parent's. The
   window direction is the one that reads backwards: for a fixed amount a *shorter* window is
   *looser* (100 an hour is 2,400 a day) and no window is a lifetime cap, the tightest. So a
   lifetime parent needs a lifetime child, and a windowed parent accepts a child with no window
   or a window at least as long. The first draft had this inverted; a blind review on 2026-11-01
   caught it before it shipped. The refusal is `LimitNotWithinGrantor`, naming the field.
4. **Fail closed on what cannot be counted.** A capped capability refuses an invoke that declares
   no amount (`MandateAmountRequired`). An amount that is not a finite non-negative number is
   refused whether or not the capability is capped (`MandateAmountInvalid`). A refused invoke
   records nothing.
5. **A bad limit at issue is a programmer error, a bad amount at use is a refusal.** No authority
   decision has been made at issue, so a malformed `limits` throws `TypeError`, as `createTrust`
   does for a bad store. A use is an authority decision, so it goes through `MandateFailure`.

## What this does not do

- **A cap binds a leaf, and only a leaf.** Spend counts against the scope's own cap. A holder of
  a capped scope that can still delegate (org or project tier) may mint any number of children
  each capped at the same amount, so a cap on a delegable scope bounds nothing by itself. Cap the
  agent-tier scope you hand the agent. Summing a subtree needs the store to answer "every invoke
  under this ancestor", which `MandateAuditService` does not offer today; that is its own
  decision, not a quiet extension of this one.
- **`amount` is the host's declaration.** The kernel enforces declared spend; it does not see
  what a sink moved. The host, never the agent, calls `useCapability` with the true figure, and
  the chain's own primitives are where money is bounded for real (AGENTS.md, TCB honesty).
- **Amounts are summed as JavaScript numbers.** Use integers in minor units for money; a cap of
  0.3 refuses 0.1 + 0.2. The error is fail-closed.
- **One writer per store file.** Two processes appending to one JSONL file can each read 25 and
  each spend 10 under a cap of 30; SECURITY.md already states the one-writer rule, and this
  decision inherits it.
- **`unit` is a label.** The kernel compares it for equality at delegation and never converts.
- **A scope still does not survive a restart.** The *spend* does (it is in the log); the scope
  object is possession (ADR 0001) and must be re-issued. Resuming authority from the log is its
  own decision.

## Consequences

- The FREE tier of a three-tier host (never / ask / free) can now be stated in the grant and
  enforced by the kernel rather than by host glue.
- `MandateGrantEvent` gains an optional `limits`; `MandateInvocationEvent` gains an optional
  `amount`. Both are additive, so a 0.4.0 log reads unchanged and a 0.4.0 reader ignores them.
- Four new members on `MandateError`. Consumers that switch on `_tag` exhaustively will need the
  new cases.

## Amended 2026-11-08

ADR 0011 changes one step of how a limit is counted. An invoke that carries a `holdId` and has one
valid `settle` event counts at that event's `actual` instead of its `amount`, at its own timestamp and
still as one call. Every other invoke counts as decision 2 above says.
