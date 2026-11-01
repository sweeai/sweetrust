---
title:       "ADR 0004: the audit store is bound at construction, never passed per call"
kind:        adr
status:      accepted
updated:     2026-10-31
owner:       sweetrust maintainers
verified_by: "pnpm -C packages/trust test (test/mandate/audit-bound-client.test.ts, 8 cases watched RED on 2026-10-31 before the fix; test/intake-poison.test.ts createTrust case) + the reproduction script run against the published 0.4.0 dist"
---

# ADR 0004: the audit store is bound at construction, never passed per call

**Status:** Accepted
**Force:** invariant. The check is `test/mandate/audit-bound-client.test.ts`, case (a).
**Date:** 2026-10-31 · **Extends:** ADR 0001 (authority is possession of an issued scope)

## Context

Through 0.4.0, the five mandate entry points were free functions, and each took the audit store as
a trailing argument: `useCapability(args, audit)`, `revokeMandate(args, audit)`, the three issuers
likewise. Every audit-log check the kernel makes (`MandateNotIssued`, `MandateScopeForged`,
`AncestorMandateRevoked`, `DelegationChainBroken`) ran against *that* argument.

A stranger's review of the published package on 2026-10-31 read what that meant, and a second
reader reproduced it against `dist/mandate.mjs`:

1. The host issues org → project → agent on its store and hands the agent its scope.
2. The host revokes the org root. Through the host's store the agent is refused,
   `AncestorMandateRevoked`, as designed.
3. The agent calls `makeInMemoryAuditLive()`, records one `grant` event for its own id with
   `parentMandateId: null`, and calls `useCapability({ mandate: agent, capability }, mine)`.
4. **Allowed.** Possession passed, because the scope was genuine. Every log check passed, because
   the log was the agent's. README said the kill switch was "structural, not advisory."

ADR 0001 had bound authority to an object the caller cannot mint. It had not asked which *log*
that object belonged to. Possession proved the scope was real; nothing proved the store was.

## Decision

**The store is bound once, at construction, and a scope is bound to the store that recorded its
grant.**

- `createTrust({ store })` is the only public door. It returns a frozen client whose verbs
  (`issueOrgMandate`, `issueProjectMandate`, `issueAgentMandate`, `useCapability`,
  `revokeMandate`) take the same `args` as before and no store. `audit` on the client is a
  read-only view (`query`, `isRevoked`); the client writes, callers read.
- Inside `mandate.ts`, a module-private `WeakMap<MandateAuditService, WeakSet<scope>>` records,
  for each store object, every scope minted against it. `useCapability`, `revokeMandate` and the
  two delegating issuers refuse an issued scope that is not in the presented store's set with the
  new `MandateScopeForeign { mandateId }`. The check runs *after* `assertIssued`, so an object the
  module never issued keeps its more specific verdict, `MandateScopeForged`.
- The binding is to the **store object**, not to the client object. Two clients constructed over
  the same store agree; a client over a different store refuses. That keeps construction cheap and
  composable without weakening anything: an attacker who holds the store itself can already write
  to it, so binding to the client would add no strength.
- The free functions are no longer exported from `sweetrust/mandate` or the root. They remain the
  implementation the client calls. 0.x: a minor may break (CHANGELOG § Versioning), and this is a
  **Breaking** bullet in 0.5.0, not a deprecation. Re-exporting them would reopen the hole.

## Consequences

- The reproduction above now ends in `MandateScopeForeign`, and nothing is recorded in the
  attacker's store. Same-client revocation still cascades (`AncestorMandateRevoked`).
- A host that needs the store in more than one place constructs a client in each place over the
  same store. A host must not hand an agent the store or the client; it hands the agent its own
  scope, as ADR 0001 and `SECURITY.md` already said.
- **Honest limit, unchanged from ADR 0001.** Code in the same process that can call
  `createTrust` with a store of its own can mint a fresh org mandate on that store and act under
  it. The process holds root. This decision closes "a genuine scope judged by a foreign log"; it
  does not and cannot close "in-process code can be root." That boundary is a process boundary,
  which belongs to a host design (one process holds the store and the credentials; the agent runs
  in another), not to this package.
- The test suites written against the old call shape run through `test/helpers/via-client.ts`,
  which routes every call through `createTrust`; the assertions did not change, the door did.

## Alternatives considered

- **Keep the free functions and validate the store argument.** There is nothing to validate it
  against: a store is a plain object with three functions, and the attacker's one is as well-formed
  as the host's. The argument itself was the hole.
- **Bind per client, not per store.** Considered and rejected above: equal strength, worse
  composition.
- **A per-mandate secret committed in the grant event** (ADR 0001's named cross-process path).
  Orthogonal. It would let a scope cross a process boundary; it would not have stopped a caller
  from choosing the log that judges it.
