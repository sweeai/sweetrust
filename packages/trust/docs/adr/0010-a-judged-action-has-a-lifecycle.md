---
title:       "ADR 0010: a judged action has a lifecycle, issued once, bound to its purpose, consumed once"
kind:        adr
status:      accepted
updated:     2026-11-08
owner:       sweetrust maintainers
verified_by: "pnpm -C packages/trust test (test/gate/action-lifecycle.test.ts) and pnpm -C packages/sui test (spend authorization section of test/receipts.test.ts)."
---

# ADR 0010: a judged action has a lifecycle, issued once, bound to its purpose, consumed once

**Status:** Accepted, 2026-11-08, cut in DAN-1406 from the 2026-11-08 audit (rows L1 to L7).
**Implementation:** built, in the same change as this record.
**Force:** invariant. `test/gate/action-lifecycle.test.ts` holds it.
**Date:** 2026-11-08 · **Extends:** ADR 0007 (one async path), ADR 0008 (the payment names its verdict), ADR 0009 (the verdict on the receipt).

## Context

A verdict was a repeatable sample recorded as a digest. Nothing issued it once, bound it to one
purpose and one action, or consumed it once, and a block or a hold lasted for one call. So:

- An agent that retried a blocked action resampled the judge until it said `match`.
- A held action could be re-judged to `match`, and then approved, and paid twice. Five concurrent
  identical calls all ran.
- `requireAuthorization` accepted an invented verdict digest, and the same one three times.
- In warn and observe, a confident mismatch was passed on as `authorizedBy`, and one undeclared
  argument switched the judge off.
- A failed log write after `execute` left an approval reusable through a second sink.

The trap in fixing it: `actionDigest` has no nonce, so refusing a digest forever breaks two
legitimate identical payments. Stickiness has to belong to the open block or hold, and repeats have
to be named by someone other than the agent.

## Decision

**In enforce, each judged action is one record per sink, in one of four states: blocked, held,
executing, executed. It is claimed synchronously before the first await.**

1. **Stickiness keys on the action alone.** A block holds for a window (`judgment.blockWindowMs`,
   default one hour, never below the 15-minute approval window). An open hold stays held until it is
   resolved or expires. A new call on either returns the existing answer on a new receipt and does
   not call the judge, so retries are free and learn nothing.
2. **Execution dedupe keys on the action plus an idempotency key.** The sink's second argument is
   `{ idempotencyKey }`, supplied by the host and never agent-controlled, and it enters the action
   digest. With no key, an identical action that has already been attempted is refused as a
   duplicate. An idempotency key cannot evade a block or a hold, because stickiness ignores it.
3. **The claim is synchronous.** Concurrent identical calls yield one judge call and one execution.
   The others wait for the first decision and answer from it.
4. **A durable intent record precedes `execute`.** An `attempted` receipt carrying the verdict is
   appended first, and its presence means the action may have run. A log that refuses the write
   stops the action. A log that fails after the action can no longer make an approval reusable,
   because the second sink finds the record.
5. **The record is rebuilt from the log.** Blocks, holds and attempts are read back from
   `log.all()`, so a restart or a per-request sink inherits them: `attempted` is the executing
   state, and an outcome receipt after it is executed. A judged enforce sink needs a log with
   `all()`. Only a judge call in flight lives in memory.
6. **The verdict names what was judged.** `Verdict` gains `purposeHash`, the digest of the purpose
   the judge saw, and `unkeyedActionDigest`, the action's digest as if it carried no key, which is
   what stickiness reads back. Both are inside `verdictDigest`. `verifyVerdictPurpose` in
   `sweetrust/verify`, and `reconcile` given `grants`, compare a verdict with the signed grant.
7. **Doubt is not authority.** In warn and observe a flagged action runs without `authorizedBy`, and
   an undeclared argument no longer switches the judge off.
8. **`requireAuthorization` consumes a token.** A sink hands `execute` a one-shot
   `SpendAuthorization`, branded by this module and bound to the verdict and payment. `spend` takes it
   as `authorization` and consumes it. A digest typed by a caller is not an authorization.
9. **`reconcile` counts executions per action** and reports one action executed twice as
   `duplicate-action`, even under two different verdicts.
10. **The refusal string no longer quotes the judge's rationale by default.** The refusal goes to
    the agent, and the rationale would teach it what to change. `judgment.rationaleInRefusal` opts in.
    The receipt's `reason` is unchanged, and still redacted per `redact`.

## What this does not do

- **It does not enforce in warn or observe.** Those modes run the action by definition, so they keep
  no block, hold or dedupe. Only `reconcile` sees a repeat there.
- **It does not bind a mismatched `granted` at the sink.** `granted` is `{ purpose, grantHash }`, and
  the gate cannot recompute a grant's hash without the grant event. A host that pairs a real hash
  with a different purpose is caught afterward, by `verifyVerdictPurpose`, not refused at the call.
- **It does not make the log trustworthy.** A holder of the log key can write or omit these records
  (ADR 0008). A log that does not return what was appended breaks stickiness and dedupe.
- **An idempotency key is host-attested.** A host that forwards an agent's value as the key has
  given the agent the repeat decision.

## Alternatives considered

1. **Refuse a repeated action digest forever.** Rejected: it breaks two legitimate identical
   payments, and the audit named it as the trap.
2. **Key stickiness on the action plus the idempotency key.** Rejected: an agent that can vary the
   key, directly or through a confused host, would escape every block.
3. **Keep the records in memory only.** Rejected: a per-request sink would forget every block.

## Consequences

- **`Verdict` changes shape, so every `verdictDigest` changes.** This is a 0.x break and is why it
  had to land before 0.6.0 ships. An unjudged receipt is untouched.
- **`Receipt.decision` gains `attempted`.** A judged enforce run leaves two receipts, `attempted`
  then its outcome.
- **The testnet record `packages/sui/test/conformance/intent-e2e.json` is stale** until
  `packages/sui/scripts/intent-e2e.ts` is re-run, and says so.
