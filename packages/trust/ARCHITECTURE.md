# @swee/trust — ARCHITECTURE.md

> Living document describing how `@swee/trust` works NOW. Updated alongside CHANGELOG when an architectural change ships. Per the ARCHITECTURE convention: each subsystem section carries STATUS / FLOW / SOURCE / LAST VERIFIED metadata so staleness is visible.
>
> **Scope note (2026-07-30):** this file was `@sweetrust/mandate`'s. The three packages merged into one, so it now covers the whole rail. Sections 1–4 and 8 are mandate's, carried over with their original LAST VERIFIED dates intact; sections 9 and 10 (gate, verify) were added at the merge. **A date that has not moved is telling the truth** — do not refresh one without re-verifying the section.

## High-level architecture

One package, three primitives, one direction of flow:

```
  @swee/trust/mandate  ──▶  @swee/trust/gate  ──▶  @swee/trust/verify
   issue authority        enforce it at         prove it happened
   in bounded tiers       the sink boundary     to a stranger
```

Each is independently importable — the arrows are how they *compose*, not what they *require*. `gate` has no knowledge of `mandate`. `verify` is the only one that reaches across, and it reaches for exactly one thing: mandate's signer, so the rail has one canonicalization rather than two that drift.

1. **Authority** (`src/mandate/`) — issue, use, revoke, across organization → project → agent tiers. Subset gates enforced by the compiler and re-checked at runtime. Every act on an Ed25519-signed hash chain.
2. **Enforcement** (`src/gate/`) — `Sourced<T>` provenance tags, the four-tier lattice, three audited declassifiers as the only ascent paths, fail-closed sinks, the judgment seam, and the receipt log.
3. **Evidence** (`src/verify/`) — signs gate's receipts *through* mandate's signer, exports JSONL, and re-verifies from public material alone plus an optional on-chain anchor.
4. **Adapters** — anything needing a network lives outside the package. Keeping adapters out is what makes the zero-dependency claim true.

**Dependency injection without a framework.** The `makeXLive` naming survives from an Effect-TS era that ended 2026-07-20 (DAN-600). These are now plain factory functions returning plain service objects. The *discipline* is unchanged — tests and production run identical calling code and differ only in which factory was wired at the entry point — but there is no Effect runtime, no `Layer`, no `Tag`, and no fiber. Do not reintroduce them.

## Data flow

Core: issue/use/revoke → `MandateAudit.record` → `MandateSigner.sign` (Ed25519 over the full envelope + previousHash) → `SignedMandateAuditEvent` → `verifyAuditChain`.

Enforcement: extraction boundary → `Sourced` tag → (optional declassifier) → sink appetite check → `ReceiptLog.append` → (with verify wired) Ed25519 signature + wrapper chain → JSONL → `verifySignedChain`.


## Subsystems

### 1. Type substrate

- **STATUS:** LIVE
- **FLOW:** Compile-time only. All v1.0 type definitions are exported from `src/types.ts` and consumed by every other module.
- **SOURCE:** `src/types.ts` exports `MandateScope<Caps, Tier, ParentScope>`, `MandateTier`, `MandateAuditEvent` union (4 variants), `SignedMandateAuditEvent` wrapper, `MandateError` union (9 variants — added `AncestorMandateRevoked`, `MandateNotIssued`, `MandateScopeForged` at 2026-05-07 audit pass; `DelegationChainBroken` at 2026-07-22 DAN-640), `TriggerSource`, `VerifyAuditChainResult`. Backward-compat: `MandateScope<Caps>` defaults `Tier = "organization"` + `ParentScope = null` so v0.0/v0.1 callers type-check unchanged.
- **LAST VERIFIED:** 2026-05-07 (`npx tsc --noEmit` clean; 0 errors in `packages/`).

### 2. Mandate flow (issue / use / revoke)

- **STATUS:** LIVE
- **FLOW:** v0.0 functions (`issueRootMandate`, `issueMandate`, `useCapability`, `revokeMandate`) preserved unchanged at the type-surface level. v1.0 adds three named tier-specific issue functions (`issueOrgMandate`, `issueProjectMandate`, `issueAgentMandate`) with per-tier compile-time subset gates. Agent-tier mandates are leaves — type system structurally refuses upward delegation. **Post-2026-05-07 audit pass**, three runtime gates strengthened: (a) `useCapability` rejects if ANY ancestor is revoked (`AncestorMandateRevoked` error); (b) `useCapability` requires a `grant` event in the audit log AND verifies claimed capabilities are a subset of granted capabilities (`MandateNotIssued` / `MandateScopeForged` errors close the forged-scope-literal bypass); (c) all child issue functions call `audit.isRevoked(grantorScope.id)` before recording (closes the revoke-vs-issue race that produced orphan children). `useCapability`'s signature generalized to `<Caps, Cap, Tier, ParentScope>` so multi-tier mandates can be invoked directly without type gymnastics. **Post-2026-07-22 battle-test (DAN-637):** gate (a) now reconstructs the ancestor chain from the AUDIT LOG via each grant event's `parentMandateId` (walking up from `mandate.id`, the same primitive `revokeMandate` uses), NOT from the in-memory `parentScope` pointer. The pointer was not load-bearing truth — `issueMandate` sets `parentScope: null`, deserialized mandates lose the object graph, and a forged `{...realScope, parentScope: null}` severed the walk — so revoking a root never disabled a child and the org kill-switch was silently inert. `parentScope` no longer participates in any security decision; the `AnyMandateScope` alias was removed.
- **SOURCE:** `src/mandate.ts`. Type-level subset gate: `Cap extends Caps[number]` (v0.1.1 fix; load-bearing per LESSONS) generalized to walk the parent-tier chain in `issueProjectMandate` (`ProjectCaps extends ReadonlyArray<OrgCaps[number]>`) and `issueAgentMandate` (`AgentCaps extends ReadonlyArray<ProjectCaps[number]>`). Runtime fallback subset check handles any-cast escape hatches. **Post-2026-07-22 (DAN-639):** the in-memory fallback is backed by `assertRequestedCapsBackedByGrantorGrant`, which re-checks every requested capability against the grantor's RECORDED grant event (`audit.query(grantorScope.id).find(grant).capabilities`) in all three derived issue functions — a forged in-memory `grantorScope.capabilities` can no longer mint a capability the grantor was never granted (`MandateScopeForged`; a wholly-fabricated grantor with no grant event → `MandateNotIssued`). Audit-log-is-truth now holds at issuance, not only use/verify. `generateMandateId` uses `crypto.randomBytes(8).toString("hex").slice(0, 10)` — entropy-strong, attacker cannot pre-compute IDs. Helper `checkGrantorNotRevoked` centralizes the issue-time revocation guard. Ancestor-revocation walk in `useCapability` uses `audit.query(cursorId).find(grant).parentMandateId` to climb the chain. **Post-2026-07-22 (DAN-640):** that walk fails CLOSED — a non-leaf cursor with no grant event (a tampered/truncated log that severs the chain) throws `DelegationChainBroken` instead of silently stopping, so a revoked ancestor above a broken link can't be missed; the leaf-with-no-grant case still routes to `MandateNotIssued` (legitimate forged-fake-id).
- **LAST VERIFIED:** 2026-07-22 (62/62 mandate-package tests incl. `test/audit-log-is-truth.test.ts` (ancestor + cycle-guard + issue-time forged-grantor + broken-chain fail-closed regressions); 0 typecheck errors).

### 3. Audit log (unsigned + signed)

- **STATUS:** LIVE
- **FLOW:** Two parallel factory families sharing the same `MandateAuditService` interface for record/query/isRevoked. Unsigned (`makeInMemoryAuditLive`, `makeJsonlAuditLive`) records raw `MandateAuditEvent` objects. Signed (`makeInMemorySignedAuditLive`, `makeJsonlSignedAuditLive`) wraps every record in `SignedMandateAuditEvent` using an injected signer; previousHash chains records via SHA-256 of canonical JSON. The `read → sign → append` critical section must not interleave, or two recorders observe the same chain head and fork the chain. **Mechanism changed 2026-07-20 (DAN-600):** the Effect version guarded it with a single-permit `Effect.makeSemaphore(1)`; the plain-TS rewrite is fully synchronous, so the critical section is inherently serialized and no lock is needed (`src/mandate/audit.ts:67` states this at the site). **The property is unchanged; only its enforcement is.** The JSONL family's cross-process append is NOT locked — single writer per store.
- **SOURCE:** `src/mandate/audit.ts`. The signed factories return both the `MandateAudit` and `SignedMandateAudit` surfaces backed by one shared array, so state stays consistent across the two views.
- **LAST VERIFIED:** 2026-05-07 for the chain semantics (multi-tier-demo runs end-to-end with a 4-event signed chain; `verifyAuditChain` returns valid:true on intact, signature-mismatch on tamper, hash-chain-broken on removal). **Serialization mechanism re-verified 2026-07-30** against the merged source.

### 4. Cryptographic signer

- **STATUS:** LIVE
- **FLOW:** Three production-ready signer factories (one new at 2026-05-07). *(Formerly a `MandateSigner` Effect Tag with three Layers; plain factories since DAN-600. Where this section says a call "dies the fiber", it now throws.)* **Payload-generic since v1.1.0 (2026-07-07):** `sign`/`verify` accept any payload `P` and return `Signed<P>` (`SignedMandateAuditEvent` is now the alias `Signed<MandateAuditEvent>`); the signer signs canonical bytes and never inspects payload structure, so external record types (first consumer: SweeVerify receipts, `sweeai/src/verify.ts`) share this one implementation. `makeInMemorySignerLive` produces deterministic test signatures (`inmem-<sha256>`) for use in tests + non-cryptographic demos. `makeEd25519SignerLive(config)` uses `node:crypto` Ed25519 primitives; signs canonical JSON of the payload; verifies against the per-record `signerPublicKeyHex` (NOT the Layer's own key). `makeEd25519VerifierLive(config)` is a verifier-only Layer added 2026-05-07 — accepts `publicKeyPem` only; `sign()` dies the fiber with a programmer-error message; `verify()` works against the per-record key. Closes spec mandate-v0-2 reconstruction-test #8 (cross-process audit verification). The per-record-key verify pattern enables external auditors to validate chains without holding signing authority + future key rotation (v0.2.1 per spec I11).
- **SOURCE:** `src/signer.ts`. Includes `canonicalJSON` (recursive sort-keys + no-whitespace serializer; sufficient for `MandateAuditEvent` — strings/null/literals — AND for JS-only generic payloads containing Numbers, since ECMAScript fully specifies number→string serialization and both sign/verify sides run JS; BigInt/Date/NaN payloads would throw or drift — upgrade to RFC 8785 / JCS before any cross-language verifier consumes these chains) and `sha256Hex` helpers. `verifyAuditChain` walks a log and returns `{ valid, firstInvalidIndex, reason }` discriminator covering signature-mismatch, hash-chain-broken, missing-signature, and (2026-07-22) untrusted-signer failures. `signerPublicKeyHex` is hex-encoded SPKI-DER (~88 hex chars / ~44 bytes), NOT raw 32-byte (cross-runtime verifiers like browser WebCrypto / Sui Move must strip the ASN.1 wrapper themselves; v0.2.1 candidate to add `rawPublicKeyHex`). **Post-2026-07-22 battle-test (DAN-638):** `verifyAuditChain` takes a REQUIRED `opts.trustedSignerPublicKeyHex` and rejects any record whose `signerPublicKeyHex` differs *before* the signature check (`untrusted-signer`). Verifying against the record's OWN embedded key proves internal consistency, not authorship — an attacker who obtained the log could re-sign every record under their own key and pass. The trust root is now a key pinned out-of-band by the caller, mirroring `@sweetrust/verify`'s `verifySignedChain`. Per-record `verify()` still uses the embedded key (that is what makes verifier-only Layers and future key rotation work); the pinning gate sits above it in `verifyAuditChain`.
- **LAST VERIFIED:** 2026-07-22 (52/52 mandate vitest incl. attacker-key-substitution + cycle-guard regressions; verify 13/13 + linear 31/31 stay green; 2026-07-07 + 2026-05-07 checks all still covered by the suite).

### 5–7. Linear integration, resilience layer, scheduler — EXTRACTED

> audit (`docs/KERNEL-AUDIT-2026-07-19.md`): adapters do not live inside SweeTrust proper.

### 8. Demos (runnable talk scripts)

- **STATUS:** LIVE
- **FLOW:** Two demo scripts here, each runnable via `node packages/trust/src/mandate/<demo>.ts`:
  - `demo.ts` — v0.0 capability subset gate proof (Arthur → AgentA single-tier flow)
  - `multi-tier-demo.ts` — v1.0 multi-tier + signed audit + tamper-detection demo (org → project → agent + verifyAuditChain on intact, tampered, removed-record logs)
- **SOURCE:** `src/{demo,multi-tier-demo}.ts`. Each is intentionally readable as a verbal narration matching the planned talk script.
- **LAST VERIFIED:** 2026-05-04 (all three run end-to-end without errors; output formatted for stage clarity).

### 9. Enforcement kernel — `@swee/trust/gate`

- **STATUS:** LIVE
- **FLOW:** Extraction boundary → `Sourced<T>` tag carrying tier + provenance (origin, ancestry, audit chain, optional confidence) → tags propagate through combination, taking the **minimum** tier (Rule 1: taint is sticky) → optionally through one of exactly three declassifiers (Rule 3) → sink appetite check (Rule 4, fail-closed) → judgment seam → `ReceiptLog.append`. Every decision lands on the log, allow *and* refuse. `fromLLM` returns untrusted unconditionally (Rule 2: inference is not evidence). Adoption ladder `observe → warn → enforce` (Rule 5) lets it be installed into a running system without breaking it.
- **SOURCE:** `src/gate/trust.ts` — one file, deliberately, so the kernel is auditable in a sitting. The `Sourced` constructor and `ascend` are **module-private**; `allowlisted` / `corroborate` / `humanConfirm` are the only doors. Implements the trust-types specification §4–§5. Zero dependencies, `node:crypto` only.
- **Architecture Invariant — a check and the promotion it authorizes name the SAME binding.** `allowlisted` returns the **registry's** `Sourced`, never the caller's candidate. The candidate is compared and then discarded; its identity survives only in the ascent event's `evidence`. This is not a style preference: serialization is not identity, so a candidate can compare equal and *be* something else, and promoting the compared-against record is what makes the comparison mean anything. Callers must not assume they get their own object back.
- **Architecture Invariant — an ABSENCE: nothing in the sink path reads a key off a prototype.** Membership is `Object.hasOwn`, never `in`; the receipt's `args` bag is `Object.create(null)`, never `{}`; redaction policy is read through an own-key helper. Argument names are chosen by whoever wrote the tool schema — which, for this package's stated target, is not us. An argument named `constructor` or `__proto__` must be as visible to enforcement as one named `amount`.
- **TCB honesty:** in-process TypeScript is observe/warn/dev-time authority. Code that can import this module and lie about an authority name can mint verified values. Unforgeable enforcement belongs to the Move `SpendCage` (testnet `0x5c1588…fdfa`). The honest-limits comment block in the source is load-bearing — do not remove it.
- **LAST VERIFIED:** 2026-08-31 pre-publish adversarial audit — **two further unconditional fail-opens found in `enforce` mode against built `dist/`**, both invisible to the then-169-test suite, both now closed with regressions proven red against the pre-fix code. Package total 177/177. (Prior: 2026-07-25 pass, five fail-opens; 51/51 at that date.)

### 10. Evidence kernel — `@swee/trust/verify`

- **STATUS:** LIVE
- **FLOW:** Wraps gate's `ReceiptLog` with authorship. `SignedReceiptLog extends ReceiptLog` and drops into `makeSink`'s `log:` — wrap, never fork. Each receipt is Ed25519-signed at append time through mandate's signer. **Two chains, both checked:** the interior kernel chain (`Receipt.prevHash`/`hash`, computed by gate) and the wrapper chain (`Signed.previousHash = sha256(canonicalJSON(previous signed record))`, per mandate audit-chain semantics, spec I8). `exportJSONL` produces the artifact handed to an auditor; `verifySignedChain` re-checks every signature, both hash links, and sequence, holding only public material.
- **SOURCE:** `src/verify/verify.ts`. `trustedSignerPublicKeyHex` is **required**, not optional — verifying a record against the key it carries proves internal consistency, not authorship. Interior-hash recomputation must mirror gate's `ReceiptLog.append` byte-for-byte on JSON body key order; changing that body shape is a cross-subsystem change.
- **Honest limits (proven by tests, not asserted):** tail truncation leaves a valid shorter chain and is catchable *only* by the on-chain anchor, and only by an `"anchor"` seal — a per-decision `"receipt"` memo proves the chain through its own seq, never the whole chain. A compromised host can sign lies going forward; it cannot rewrite the past behind an anchor or forge under a key it does not hold.
- **LAST VERIFIED:** 2026-07-25 adversarial pass (malformed input now returns a verdict instead of throwing). Merged-tree run 2026-07-30: verify suites 34/34 within the package's 161.

---

*Living document. Widened from mandate-only to the whole rail 2026-07-30 at the three-into-one package merge. Last full review of the mandate sections: 2026-05-04, at the v1.0 substrate-complete milestone close — the per-section LAST VERIFIED dates above are the ones to trust.*
