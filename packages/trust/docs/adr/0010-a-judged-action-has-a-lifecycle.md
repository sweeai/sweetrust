---
title:       "ADR 0010: a judged action has a lifecycle, issued once, bound to its purpose, consumed once"
kind:        adr
status:      accepted
updated:     2026-11-09
owner:       sweetrust maintainers
verified_by: "pnpm -C packages/trust test (test/gate/action-lifecycle.test.ts, including ReceiptLog.fromReceipts and SignedReceiptLog.fromSigned) and pnpm -C packages/sui test (spend authorization section of test/receipts.test.ts)."
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
   not call the judge, so retries are free and learn nothing. Only a real assessment sticks: a
   judge that timed out, threw or answered with something that is not a verdict still holds the
   call, on a `judgment-held` receipt with `scored: false`, but leaves no standing hold, so the next
   call asks the judge again. An outage is not an answer. An owner may still approve that hold,
   and the approval is refused as a replay if a later call has already run the action.
   **Amended 2026-11-09 (DAN-1443): a real doubt outlives its window.** When a scored block or hold
   expires, the next identical call is judged again, so the owner gets a fresh hold to approve, but
   a `match` on it is held rather than run. A `mismatch` blocks. Only an `attempted` receipt carrying
   the owner's approval of that doubt clears it, so a late `errored`, a run on a warn sink or the
   release of an earlier outage hold cannot. A sink with no `approvalKey` can never release one, so
   that exact action stays held under that grant, whatever its idempotency key. Before this, an
   agent could wait out each window and resample the judge until it said `match`, which is the retry
   this record exists to stop.
   **Amended 2026-11-09 (DAN-1466): on a payment, a doubt stands on the payment.** When the sink's
   purpose names a payment (the verdict's `paymentDigest` is not null), a block or a hold answers
   every action with the same `paymentDigest`, so the same payee, amount, asset and network under
   another memo, or any other changed argument, is held or blocked without a judge call while the
   doubt's window is open, and after it is judged again and held on a `match` or blocked on a
   confident `mismatch`, by the rule above. The hold it gets names the doubted action (its
   `actionDigest` and `verdictDigest`, with `underAnotherAction: true`), so the owner's approval still
   releases only the exact action the owner was shown. Once that approved action is attempted, the
   doubt on the payment is answered and a memo the judge has not doubted goes back to the judge. An
   action's own doubt is kept apart from the payment's: approving memo B never answers a doubt the
   judge scored on memo A, so A stays held for its owner. A duplicate of an action that already ran is
   refused before another memo's doubt is consulted. The in-process `judging` claim covers the
   payment too, within one sink object. Dedupe and approvals stay on the exact action.
   A sink with no payment keeps exact-action stickiness: two null digests are never one payment.
   Doubt broadly, allow narrowly. Before this, a reworded memo was a new action and a fresh judge
   sample, which the agent could ask for as often as it liked.
2. **Execution dedupe keys on the action plus an idempotency key.** The sink's second argument is
   `{ idempotencyKey }`, supplied by the host and never agent-controlled, and it enters the action
   digest. With no key, an identical action that has already been attempted is refused as a
   duplicate. An idempotency key cannot evade a block or a hold, because stickiness ignores it.
3. **The claim is synchronous.** Within one sink object, concurrent identical calls yield one judge
   call and one execution. The others wait for the first decision and answer from it. Two sink
   objects over one log may each ask the judge, so the log is read again after the judge answers,
   with no await between that read and `execute`: the first to get there acts, and the other
   answers from what it did.
4. **A durable intent record precedes `execute`.** An `attempted` receipt carrying the verdict is
   appended first, and its presence means the action may have run. A log that refuses the write
   stops the action. A log that fails after the action can no longer make an approval reusable,
   because the second sink finds the record.
5. **The record lasts exactly as long as the log.** Blocks, holds and attempts are read back from
   `log.all()`, so a per-request sink over the same log inherits them: `attempted` is the executing
   state, and an outcome receipt after it is executed. A judged enforce sink needs a log with
   `all()`. Only a judge call in flight lives in memory. `ReceiptLog` and `SignedReceiptLog` are
   in-memory, so a new one is empty and a process that restarts forgets everything unless it
   seeds the new log: `ReceiptLog.fromReceipts` checks the hash chain, and
   `SignedReceiptLog.fromSigned` also verifies every signature under the signer's key. Saving the
   receipts as they are written is the host's job. The record is scoped to one sink name, grant and
   purpose: receipts under another grant or purpose neither answer for this action nor clear it.
6. **The verdict names what was judged.** `Verdict` gains `purposeHash`, the digest of the purpose
   the judge saw, and `unkeyedActionDigest`, the action's digest as if it carried no key, which is
   what stickiness reads back. Both are inside `verdictDigest`. `verifyVerdictPurpose` in
   `sweetrust/verify`, and `reconcile` given `grants`, compare a verdict with the signed grant.
7. **Doubt is not authority.** In warn and observe a flagged action runs without `authorizedBy`, and
   an undeclared argument no longer switches the judge off. A call the sink raised any violation on
   carries no `authorizedBy` or token either, even on a confident match.
8. **`requireAuthorization` consumes a token.** A sink hands `execute` a one-shot
   `SpendAuthorization`, branded by this module and bound to the verdict and payment. `spend` takes it
   as `authorization` and consumes it. A digest typed by a caller is not an authorization.
9. **`reconcile` counts executions per action** and reports one action executed twice as
   `duplicate-action`, even under two different verdicts. It accepts a verdict from the records of a
   run the judge let through: `executed`, `attempted` (all a log failure after `execute` leaves) and
   an `observed` with no violation. A `warned` run, or an `observed` with a violation, carries no
   authority, so a spend naming one stays `no-verdict`.
10. **The refusal string carries no assessment, confidence, rationale or block-versus-hold label by default.** The refusal
    goes to the agent, and each of those would teach it what to change. `judgment.rationaleInRefusal`
    opts back in to all three. The receipt is unchanged: its verdict and its `reason`, redacted per
    `redact`, still hold them, so a host must not hand the receipt to the agent.

## What this does not do

- **It does not enforce in warn or observe.** Those modes run the action by definition, so they keep
  no block, hold or dedupe. Only `reconcile` sees a repeat there.
- **It does not stop fresh samples through a changed payment.** Since 2026-11-09 (DAN-1466) a doubt
  on a payment covers every action of that payment, so a changed memo or other free-text argument
  is answered by the doubt. A changed payee, amount, asset or network is a different payment and gets
  a new judge call: an agent that changes an amount by one base unit asks again. On a sink with no
  payment, stickiness still holds one exact action, so any changed argument asks again. Withholding
  the score removes what it would climb on, and purpose fields and on-chain limits still bound it.
  This design does not prevent the new call.
- **It does not bind a mismatched `granted` at the sink.** `granted` is `{ purpose, grantHash }`, and
  the gate cannot recompute a grant's hash without the grant event. A host that pairs a real hash
  with a different purpose is caught afterward, by `verifyVerdictPurpose`, not refused at the call.
- **It does not make the log trustworthy.** A holder of the log key can write or omit these records
  (ADR 0008). A log that does not return what was appended breaks stickiness and dedupe, and a saved
  log cut at its tail loads as a valid shorter chain, so the cut records are forgotten.
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
- **`Verdict` also gains `scored`,** which separates a judge's real `unsure` from the gate's own
  after a failure, so stickiness can read it back from the log.
- **`Receipt.decision` gains `attempted`.** A judged enforce run leaves two receipts, `attempted`
  then its outcome.
- **The testnet record `packages/sui/test/conformance/intent-e2e.json` is stale** until
  `packages/sui/scripts/intent-e2e.ts` is re-run, and says so.
