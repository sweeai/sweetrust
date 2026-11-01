---
title:       "ADR 0005: a capability limit lives in the grant event and is counted from the audit log"
kind:        adr
status:      accepted
updated:     2026-11-01
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
   carries must be at least as tight as the grantor's *recorded* limit in every field the grantor
   set, and must exist. The refusal is `LimitNotWithinGrantor`, naming the field.
4. **Fail closed on what cannot be counted.** A capped capability refuses an invoke that declares
   no amount (`MandateAmountRequired`). An amount that is not a finite non-negative number is
   refused whether or not the capability is capped (`MandateAmountInvalid`). A refused invoke
   records nothing.
5. **A bad limit at issue is a programmer error, a bad amount at use is a refusal.** No authority
   decision has been made at issue, so a malformed `limits` throws `TypeError`, as `createTrust`
   does for a bad store. A use is an authority decision, so it goes through `MandateFailure`.

## What this does not do

- **A parent's limit is not a shared budget across its children.** Spend counts against the
  leaf's own cap. Two siblings each capped at 20 under a parent capped at 30 can together spend
  40. Aggregating across a subtree needs the store to answer "every invoke under this ancestor",
  which the `MandateAuditService` surface does not offer today; it is the next ticket, not a
  quiet extension of this one.
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
