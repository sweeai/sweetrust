---
title:       "ADR 0006: a mandate is resumed from the audit log, never re-minted at boot"
kind:        adr
status:      accepted
updated:     2026-11-01
owner:       sweetrust maintainers
verified_by: "pnpm -C packages/trust test (test/mandate/resume.test.ts, 13 cases watched RED on 2026-11-01 before the implementation; test/intake-poison.test.ts, the resume case)"
---

# ADR 0006: a mandate is resumed from the audit log, never re-minted at boot

**Status:** Accepted
**Force:** invariant. The check is `test/mandate/resume.test.ts`, "a second process over the same JSONL file continues the budget, not a fresh one".
**Date:** 2026-11-01 · **Extends:** ADR 0001 (authority is possession), ADR 0004 (the store is bound at construction), ADR 0005 (limits are counted from the log)

## Context

A scope is an object, and authority is possession of that object (ADR 0001). An object does not
survive a process, so until now every boot of a host re-minted its mandates from the org grant.
The 2026-10-31 review named the cost: "authority dies at restart; every session re-mints, so the
agent's process holds root." ADR 0005 made it worse in a specific way: a limit is counted per
mandate id from the log, so a re-mint at boot is a fresh id with a fresh budget. A $30-a-day rule
that resets on restart is not a rule.

## Decision

`trust.resume({ mandateId, capabilities, tier? })` returns a genuine, bound scope for a mandate
this store recorded.

1. **The same walk decides.** Resume runs the one revocation walk `useCapability` runs
   (`walkChain`, shared code, not a copy): refused as `MandateRevoked`, `AncestorMandateRevoked`,
   `DelegationChainBroken` or `MandateNotIssued` exactly where use would be.
2. **The caller declares, the log confirms.** The declared capability set must equal the recorded
   grant's set (order-insensitive); a declared tier must equal the tier the chain's depth gives.
   Either mismatch is `ResumeMismatch`, naming the field and both lists. Tier is not written on
   the grant event; the depth of the chain is the record of it.
3. **The scope is minted and bound like any issued scope.** It passes `ISSUED` and `BOUND`, so
   every forged-scope and foreign-store check is unchanged. Ancestor copies on it are detached and
   carry no authority, as on an issued scope.
4. **It is on the record.** A `resume` event is appended (additive type; a 0.4.0 reader ignores
   it). It never counts toward a limit.
5. **Who may call it: whoever holds the store.** ADR 0004 names the store as the root credential
   of a domain; it could already mint a fresh org mandate. Resume grants nothing new and removes
   the reason to mint at boot. A host must still hand an agent its scope and never the client.

## What this does not do

- **Resuming twice yields two genuine objects** over one recorded authority. Possession is per
  object; the log is the truth. Revoking the id revokes both.
- **No scope is persisted.** Only the id crosses the process boundary; the host stores it.
- **Nothing is resumed by name, grantor or capability.** The id is the only key.

## Consequences

- A sidecar boots by resuming the ids it stored, not by re-granting; the budget continues.
- `MandateAuditEvent` gains a `resume` member. Exhaustive switches on `type` need a case.
- `grantorId(string)` ships alongside, so a host never casts a string to `GrantorId`.
