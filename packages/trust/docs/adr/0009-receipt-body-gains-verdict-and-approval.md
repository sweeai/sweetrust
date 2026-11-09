---
title:       "ADR 0009: receiptBody gains optional verdict and approval, and unjudged receipts keep their 0.5.0 hash"
kind:        adr
status:      accepted
updated:     2026-11-08
owner:       sweetrust maintainers
verified_by: "N/A — narrative until 0.6.0 is built. The premise that canonicalJSON drops an undefined key is checked today by pnpm -C packages/trust test (test/mandate/canonical-property.test.ts). The hash-compatibility test against a 0.5.0 fixture ships with the code."
---

# ADR 0009: `receiptBody` gains optional `verdict` and `approval`, and unjudged receipts keep their 0.5.0 hash

**Status:** Accepted, 2026-11-07, when Danny approved the intent-layer spec.
**Implementation:** not started. The package is at 0.5.0, and this decision ships in 0.6.0.
**Force:** invariant once built. The check will be a test that a 0.5.0 fixture log of unjudged receipts verifies unchanged under 0.6.0. No such test exists yet.
**Date:** 2026-11-08 · **Extends:** ADR 0002 (the interior hash is over canonical JSON)

## Context

`AGENTS.md` requires an ADR for any change to the shape of the receipt body, and ADR 0002 is the
precedent. This is such a change.

A judged receipt in 0.5.0 says very little. A `match` leaves a receipt reading `executed`, with no
provider, no model and no confidence. A blocked or flagged action records the judge's words in
`reason`, as prose. An auditor cannot tell which model decided, what it decided about, or whether a
given payment was judged at all.

The fix has to live inside the hash. `ReceiptLog.nextReceipt` spreads the whole entry onto the
committed receipt, so a new key would be recorded today. `receiptBody`, however, names seven fields
and ignores everything else. A key it does not name is on the receipt and outside the hash. The
interior chain would say nothing about it, and editing that key in a copy of the log would leave
every recomputed hash unchanged.

## Decision

**`receiptBody` becomes `canonicalJSON({ seq, prevHash, at, sink, decision, args, reason, verdict,
approval })`. `verdict` and `approval` are optional top-level keys.**

- **`verdict`** is the kernel's verdict object, stored exactly as digested: `assessment`,
  `confidence`, `rationaleHash`, `provider`, `model`, `actionDigest`, `paymentDigest`, `grantHash`,
  `judgedAt` and `attestation`. Because the receipt holds the exact object, a verifier can recompute
  `verdictDigest = sha256Hex(canonicalJSON(verdict))` from the receipt alone. The rationale's text
  stays in `reason`, redacted per `sink.redact` as in 0.5.0, and the verdict holds only its hash.
- **`approval`** appears on the `executed` receipt of a held action that an owner approved. It is
  `{ verdictDigest, actionDigest, grantHash, expiresAt, signature }`.
- **A receipt with no verdict omits the key.** It must never write `null`. `canonicalJSON` drops a
  key whose value is undefined, and it serializes a key whose value is `null`, so only omission
  leaves the old bytes intact. We checked both cases against `src/canon.ts` while writing this
  record.
- **`Receipt.decision` gains `judgment-held`.** That is a new value of an existing field, so it does
  not change the hashing of any receipt that does not use it.

## Compatibility

- **Forward: an old log verifies.** A receipt without the two keys produces byte-identical input to
  the hash, so its 0.5.0 hash stands. That covers every receipt a 0.5.0 sink could write, including
  its `judgment-blocked` and `judgment-flagged` receipts, because those carried the judge's words
  only in `reason`.
- **Backward: an old verifier refuses a judged receipt, loudly.** The 0.5.0 `receiptBody` names
  seven fields, so it recomputes a judged receipt's hash without the two keys and gets a different
  answer. A 0.5.0 `verifySignedChain` returns `hash-mismatch`. Unjudged
  receipts written by 0.6.0 still verify under 0.5.0.
- **Signatures need no change.** `signedPreimage` is computed over the whole payload, so a
  `SignedReceiptLog` already signs any key on the receipt.

## What this does not do

- **It does not change the shape of an unjudged receipt.** Only a judged receipt, or one resumed
  from a hold, has either key.
- **It does not make a verdict unforgeable.** A holder of the log key can write a `match` verdict
  that never happened (ADR 0008).
- **It does not cover the other two records.** `MandateInvocationEvent` gains an optional
  `verdictDigest`, and an event without it signs as before. `sweetrust-sui` moves to a separate
  `receipt@2` before its first public version, so no public consumer of `receipt@1` will exist.

## Alternatives considered

1. **Have `receiptBody` always emit both keys, as `null` when absent.** Rejected. The shape would
   be uniform, and every hash in every existing log would change for no information gained. ADR 0002 paid that cost
   once, and only because the fix required it.
2. **Carry the verdict on the receipt, outside `receiptBody`.** Rejected. The record would sit
   outside the hash that exists to protect it, as the Context section explains.
3. **Link the records by their position in the log.** Rejected. Neighbors in a log make no claim
   about each other, and a truncated or reordered export breaks such a link silently.
4. **Have the spend name the gate receipt's hash.** Rejected. The gate receipt is written after
   `execute` runs, so its hash does not exist yet when the spend needs it. The verdict digest
   exists before `execute`, which is why it is the link.

## Consequences

- **The hashed format changes, so this is a breaking 0.x change with a CHANGELOG entry,** although
  by construction it does not change the hash of any existing receipt. The sentence in `AGENTS.md`
  that says a body change "still changes every hash" is true of a mandatory field and overstates
  an optional one. That file's description of the body as seven fields changes when the code does.
- **Exhaustive switches on `decision` need a `judgment-held` case.**
- **A key added to `verdict` later changes `verdictDigest`,** and so it needs its own record. The
  reserved `attestation` field exists to avoid that for the one addition already planned.
