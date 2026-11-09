---
title:       "ADR 0011: a hold settles to its real cost, as a new event the counter reads"
kind:        adr
status:      accepted
updated:     2026-11-08
owner:       sweetrust maintainers
verified_by: "pnpm -C packages/trust test (test/mandate/settle.test.ts, watched RED before the implementation and against a per-guard mutation run; test/intake-poison.test.ts, the settleCapability case)"
---

# ADR 0011: a hold settles to its real cost, as a new event the counter reads

**Status:** Accepted
**Force:** invariant. The check is `test/mandate/settle.test.ts`.
**Date:** 2026-11-08 · **Amends:** ADR 0005 (how a limit is counted) · **Design of record:** the SweeBroker reconcile spec, § 2 and § 4

## Context

ADR 0005 sums the `amount` of every invoke in the log. For a metered caller the amount is a hold: the
most the call could cost, declared before the call is made. A model call held at 0.56¢ that really
cost 0.03¢ used up 0.56¢ of the budget for good. The caller knows the real cost only after the reply
ends, and by then the invoke is already a signed record that cannot change.

The owner's words, 2026-11-08: "shouldn't it reconcile when it says, 'Oh, it actually cost this, so
let me reconcile it and do the actual amount that was spent.'"

## Decision

A new event type, `settle`, records the real cost against a named hold, and the counter reads it.

1. **An invoke may carry a `holdId`,** 32 lowercase hex characters chosen by the caller. A malformed
   id is a `TypeError`. An invoke with none keeps its signed bytes exactly.
2. **`settleCapability` appends a `settle` event** naming the mandate, the capability, the hold id and
   `actual`. Nothing is edited, because the log is append-only.
3. **One counting rule.** An invoke counts at its settle's `actual` when one valid settle exists, and at
   `amount` otherwise. A settled invoke keeps its own timestamp for the window and still counts as one
   call, so settling never moves spend into another window and frees dollars, never calls.
4. **A settle is valid only if** exactly one invoke on the mandate carries the hold id, exactly one
   settle carries it, the settle follows that invoke in log order and names its capability, and `actual`
   is finite and within 0…`amount`. Anything else is ignored and its invoke counts at `amount`, so a malformed
   line can never lower the count. On an unsigned store, a well-formed planted settle can.
5. **`settleCapability` refuses to write what the rule would ignore,** and refuses writing nothing:
   `MandateSettleUnknownHold`, `MandateSettleNoAmount`, `MandateSettleAboveAmount`,
   `MandateSettleDuplicate`, `MandateSettleAmbiguousHold`, and `MandateAmountInvalid` for an `actual`
   that is not a finite non-negative number.
6. **Settling is allowed on a revoked mandate.** A settle records a call made before the revoke and can
   only lower the count. So it runs `assertIssued` and `assertBoundTo`, and never `walkChain`, which
   throws on a revoked mandate.
7. **`verifyAuditChain` is unchanged.** It signs and checks a payload it does not inspect, so a settle
   is one more signed record.

## What this does not do

- **`actual` is the host's declaration,** as `amount` is (ADR 0005). The kernel enforces the figure it
  is told, so a caller that reports too little lowers the count too far. Whoever holds the client can
  settle, so hand an agent its scope, never the client (ADR 0004).
- **A hold can only settle down.** A real cost above the hold counts at the hold.
- **A settle has no time bound after a revoke.** It skips the chain walk on purpose, so a client holder
  can still append one after the kill switch, or under a broken chain. It changes the count a dead
  mandate can no longer spend against, but a reader of the log should weigh a settle timed after the
  revoke accordingly.
- **A reused hold id un-settles.** `useCapability` does not refuse a hold id the mandate has already
  used. The second invoke makes the hold ambiguous, so the settle stops counting and both invokes count
  at `amount`. That errs toward too cautious, and a 128-bit random id does not collide by accident.
- **An unsettled hold stays counted at `amount`.** Nothing expires a hold or refunds it for being old.
- **A hold id is not a secret or a capability.** It names one call on one mandate, and possession of
  the scope is the authority, as ever (ADR 0001).

## Consequences

- The `MandateAuditEvent` union gains a sixth member and `MandateError` gains five. Both unions are
  unstable in 0.x; a consumer that switches on them exhaustively needs the new cases.
- A log holding `settle` events read by an older reader still verifies, and an older counter ignores
  the event, so it counts every invoke at `amount`, the over-cautious direction.
