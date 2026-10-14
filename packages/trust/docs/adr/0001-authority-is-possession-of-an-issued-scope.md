---
title:       "ADR 0001: authority is possession of an issued scope, in-process"
kind:        adr
status:      accepted
updated:     2026-10-13
owner:       sweetrust g4
verified_by: "pnpm -C packages/trust test (authority-binding.test.ts) + the six mutation witnesses in the DAN-1157 commit message + the 2026-10-13 getter-split block (8 tests, 7 watched RED)"
---

# ADR 0001: authority is possession of an issued scope, in-process

**Status:** Accepted
**Implementation:** shipped (`23c67d1`)
**Force:** invariant. The check is `test/mandate/authority-binding.test.ts`, and each of its six
defenses has a recorded mutation witness in the `23c67d1` commit message.
**Date:** 2026-09-23 · **Ticket:** DAN-1157 · **Extends:** DAN-637

## Context

`sweetrust/mandate` bound authority to strings. `useCapability` trusted the caller-supplied
`mandate.id`; `revokeMandate` trusted a `revoker: GrantorId`. Both strings are printed in the audit
log that every audit reader can see. So the least-privileged agent could invoke as its ancestors
(F1) and permanently revoke the org root (F2). The tier ladder existed only at compile time (F3).

The fix proposed alongside the failing tests was to require the presented scope to *match its grant
event*. That cannot work. `MandateGrantEvent` does not record `tier`, and it prints `grantor` and
`parentMandateId`, so a copy of every public field matches by construction.

A second path needed no string at all. `issueProjectMandate` and `issueAgentMandate` stored the
**genuine** grantor object in `parentScope`, typed as the parent scope. An agent reached the org
root with `agent.parentScope.parentScope`: no cast, no forgery, and every check passed. DAN-637 had
already ruled that this pointer must not be a *revocation* input. Nobody had asked whether it was an
*authority* input.

## Decision

**Authority is possession of a scope object this module issued.**

- A module-private `WeakSet` records every scope an issuer mints. Issued scopes and their
  capability lists are frozen, so once a scope passes the check its `tier` and `grantor` are fact.
- `useCapability` and every delegating issuer refuse a scope that was not issued
  (`MandateScopeForged`). The check runs *after* the existing audit-log checks, so a scope that is
  also wrong on data keeps its more specific verdict.
- `revokeMandate` takes `revokerScope` and **drops** `revoker`. It authorizes when the presented
  scope was issued and is the target or one of its ancestors. `revokedBy` is read from that scope.
- `parentScope` is a **detached**, frozen copy: the same fields, so the typed chain reads the same,
  but never issued, so it carries no authority.
- The tier ladder is enforced at runtime (`TierLadderViolation`) in all three delegating issuers,
  including the legacy `issueMandate`. That function stamps `"organization"` on what it mints, so any
  other grantor tier was a side door. (`issueMandate` and `issueRootMandate` were removed later on
  2026-10-13; see the second amendment below.)

This matches a sibling in the same package. Gate's `Sourced` constructor is module-private for the
same reason: the only way to hold one is to be handed one.

## Consequences

- **In-process only, by design.** A scope that crosses a process boundary (JSONL, an issue-tracker
  round trip, an HTTP body) arrives as data and **cannot invoke**. That makes `README.md`'s
  "deserialized payloads do not get through" literally true. Cross-process authority belongs to the
  chain's own primitives, which are the unforgeable layer (`SECURITY.md` § *Honest limits*).
- **The host's job is now explicit:** hand each agent its own scope and nothing above it. Whoever
  holds a reference holds its authority. That is the object-capability contract, and it is what the
  detached `parentScope` protects.
- **Still not unforgeable.** Code that can import this module can call `issueOrgMandate` and mint a
  new root. It cannot act inside an existing tree it was not handed. An agent that receives only a
  scope and a sink (the daemon's shape) cannot mint roots.
- **Breaking against the unpublished 0.3.0:** `revokeMandate`'s signature, frozen return values,
  and a new `MandateError` variant. Consumers outside this repo that must migrate:
  `sweeai/integrations/linear` (revoke with the scope from its existing `creatorScopeLookup`) and
  the SweeAI daemon (present the org scope it already holds).

## Amended 2026-10-13

The 2026-10-13 mandate audit showed that this ADR's promise, "cannot act inside an existing tree
it was not handed", rested on an unstated condition: that the object `assertIssued` checks is the
object the function then acts on. Every exported function re-read its caller-supplied `args`
fields at each site, so a getter on `args` could present the genuine scope to the possession check
and forged data to the subset checks, the mint and the record. Four escalations followed from a
held leaf alone, under the same in-process precondition this ADR accepts.

**Possession is now checked on a single captured reference.** Each function reads each
caller-supplied field exactly once, at its top, resolves each capability `key` exactly once, and
uses only those locals; the last describe block of `test/mandate/authority-binding.test.ts` pins
the read count at one per field for every export. The decision above stands. This names the
condition it depended on.

## Amended 2026-10-13, later the same day

The v0.0 pair `issueMandate` / `issueRootMandate` is removed (chunk 4 of the rail audit). The
tiered issuers are the API, and the side door this ADR closed at runtime no longer exists at all:
a `TierLadderViolation` with `requestedTier: "organization"` was reachable only through
`issueMandate` and is now unreachable. The ladder's remaining runtime checks live in
`issueProjectMandate` (grantor must be org) and `issueAgentMandate` (grantor must be project), and
`test/mandate/authority-binding.test.ts` pins all four refusals by name: agent → project,
project → project, agent → agent, org → agent. The read-count block covers the five exports that
remain.

## Alternatives considered

1. **Match the presented scope against its grant event** (the `7893cc3` proposal). Rejected: every
   field it could match is public or unrecorded.
2. **An explicit `caller` parameter** (the test-suite audit's recommendation). Rejected as the
   *mechanism*: a caller string is one more thing the caller mints. Its *intent* is kept, because
   every new security test names two principals.
3. **A per-mandate bearer secret** whose sha256 is committed in the grant event. This works across
   processes and is **the named upgrade path** if a TypeScript consumer ever needs a rehydrated
   scope to invoke. Not taken now: no consumer needs it, it adds secret-handling hazards (scopes are
   logged and printed), and cross-process authority belongs to the chain's own primitives.
