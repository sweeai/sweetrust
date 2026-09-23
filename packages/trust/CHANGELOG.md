# Changelog — `@swee/trust`

All notable changes to this package. Format follows [Keep a Changelog](https://keepachangelog.com);
this package follows [Semantic Versioning](https://semver.org).

## [Unreleased]

### Security

- **Mandate authority is now possession of an issued scope, not a string** (DAN-1157, ADR 0001).
  Before this, an agent could invoke as its ancestors by naming their mandate id, or by reading
  `agent.parentScope.parentScope`. That second path needed no cast. The same agent could also
  permanently revoke the org root by naming its grantor. Scopes the module did not issue are now
  refused with `MandateScopeForged`. That covers copies, JSON round trips, and literals that copy
  every public field. `parentScope` is now a detached view with no authority.
- **The tier ladder holds at runtime**, not only at compile time. Agent → agent, org → agent and
  non-org grantors through `issueMandate` now throw the new `TierLadderViolation`.

### Changed

- **Breaking:** `revokeMandate` takes `revokerScope` (the scope you hold) in place of `revoker`
  (a name). It succeeds when that scope is the target or one of its ancestors.
- **Breaking:** issued scopes and their capability lists are frozen.

## [0.3.0] — first public release

First release under the `@swee` scope. The package's development history predates this repository
and is not carried forward.

### Added

- **`@swee/trust/mandate`** — type-enforced multi-tier capability mandates on an Ed25519-signed
  hash chain. Authority is issued, delegated and revoked against an append-only audit log; the
  signed preimage binds the chain link, sequence, timestamp and a domain tag, so a record cannot be
  relinked, reordered, retimed or replayed as a different protocol's message without breaking a
  signature.
- **`@swee/trust/gate`** — `Sourced<T>` provenance tiers with sticky taint, three audited
  declassifiers as the only ways a value can rise, fail-closed sinks that declare their appetite,
  and tamper-evident receipts for every decision — allowed *and* refused.
- **`@swee/trust/verify`** — signed receipt chains re-checkable from public material alone, plus a
  Sui anchor convention that makes tail truncation detectable.
- **Zero runtime dependencies.** Node builtins only.

### Notes

- Read `SECURITY.md` § *Honest limits* before adopting. It names what this package does **not**
  protect — in particular that the TypeScript revocation and the on-chain revocation are two
  separate kill switches, and only the on-chain one stops money.
