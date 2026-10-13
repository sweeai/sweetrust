/**
 * @sweetrust/mandate — core types
 *
 * Implements the mandate capability-declaration specification v0.0.
 *
 * The wedge primitive: type-enforced agent capability declaration. A
 * MandateScope structurally constrains what capabilities an agent can
 * invoke. The TypeScript compiler refuses to satisfy a function whose
 * Effect.R-channel requires a capability not declared in the agent's scope.
 *
 * v0.0 ships:
 *   - Capability tagging (via Effect.Context.Tag)
 *   - MandateScope with provenance (delegation DAG)
 *   - Typed errors (MandateError union)
 *   - MandateAudit Layer interface (implementation in audit.ts)
 *
 * v0.1+ deferred:
 *   - Runtime mandate-check on every capability invocation
 *   - Linear-as-state-machine integration (per Tim/Lalph pattern)
 *   - On-chain settlement integration (per s402)
 *   - Multi-tier mandate hierarchy
 *   - Cryptographic signing of audit records
 */
/**
 * A capability is identified by a stable string `key`. The compiler tracks
 * the LITERAL key type via the `Id` generic parameter, so two capabilities
 * with different keys are distinct types — that literal-branding is what
 * powers the compile-time subset gate (`RequestedCaps extends
 * ReadonlyArray<GrantorCaps[number]>`) without any external DI machinery.
 *
 * Construct capabilities via `defineCapability("...")` (see mandate.ts). The
 * runtime carries only the `key`; the type carries the distinctness.
 */
export interface Capability<Id extends string = string> {
  readonly key: Id
}

/**
 * Branded ID types for the mandate flow. A `MandateId` is sortable (a base36
 * millisecond prefix), carries 64 bits of `node:crypto` randomness, and is
 * never minted twice into the same log: an issuer refuses an id the log already
 * has an event for (the 2026-10-13 mandate audit). It leaks no timing
 * information beyond ms-precision. It is not globally "collision-free", which
 * is what this comment said while the suffix was 40 bits and unchecked: two
 * independent logs can, in principle, mint the same id.
 */
export type MandateId = string & { readonly __brand: "MandateId" }
export type GrantorId = string & { readonly __brand: "GrantorId" }
export type ISO8601 = string & { readonly __brand: "ISO8601" }

/**
 * MandateTier — discriminator for the three-tier mandate hierarchy per
 * the mandate multi-tier + signing specification v0.2 I2. The tier is
 * tracked at the type level via the `Tier` generic parameter on
 * MandateScope.
 *
 * Tier semantics (spec I4 — strictly decreasing scope, no upward delegation):
 *   - "organization": root tier; the workspace's "company charter" of all
 *     capabilities ANY agent in this workspace may EVER hold. Set at
 *     workspace bootstrap; rarely modified. ParentScope MUST be null.
 *   - "project": derived from organization-tier via issueProjectMandate;
 *     bounded subset of org-tier capabilities; the project's "team budget."
 *   - "agent": derived from project-tier via issueAgentMandate; bounded
 *     subset of project-tier capabilities; the agent's "job description."
 *     Agent-tier mandates are LEAVES — they cannot delegate further.
 */
export type MandateTier = "organization" | "project" | "agent"

/**
 * MandateScope<Caps, Tier, ParentScope> — typed bundle of capabilities
 * granted at a specific tier with a typed parent-scope chain.
 *
 * Generic parameters:
 *   - Caps: tuple of Capability Tags this scope grants (same shape as v0.0).
 *   - Tier: the tier this scope sits at; defaults to "organization" so v0.0
 *     callers (single-tier MandateScope<Caps>) continue to type-check
 *     unchanged. Existing code that uses `MandateScope<readonly [CapA]>`
 *     gets `MandateScope<readonly [CapA], "organization", null>`
 *     structurally.
 *   - ParentScope: the parent-tier scope this scope was derived from, or
 *     null for organization-tier (root) scopes, which `issueOrgMandate`
 *     mints with `parentScope: null`.
 *
 * The scope is IMMUTABLE post-construction (per v0.0 I2). To "add" a
 * capability, issue a new MandateScope via re-grant (per v0.0 I7).
 *
 * Per spec I3, the type-level chain enforces multi-tier subset gating
 * structurally — issuing a project-tier mandate from an organization-tier
 * grantor requires `ProjectCaps extends ReadonlyArray<OrgCaps[number]>`,
 * and similarly for project→agent. The compile-time gate is the load-
 * bearing security primitive; runtime fallback is belt-and-suspenders.
 */
export interface MandateScope<
  Caps extends ReadonlyArray<Capability>,
  Tier extends MandateTier = "organization",
  ParentScope extends MandateScope<any, any, any> | null = null,
> {
  readonly _tag: "MandateScope"
  readonly tier: Tier
  readonly id: MandateId
  readonly capabilities: Caps
  readonly grantor: GrantorId
  readonly grantTimestamp: ISO8601
  readonly grantRationale: string
  readonly parentMandateId: MandateId | null
  readonly parentScope: ParentScope
}

/**
 * MandateError — typed union covering every failure mode of the mandate
 * flow. Per spec I9, no untyped errors leak; every failure has a
 * discriminated _tag the caller can pattern-match on.
 */
export type MandateError =
  | { readonly _tag: "CapabilityNotInGrantorScope"; readonly capability: string }
  | {
      readonly _tag: "MaliciousMandateMetadata"
      readonly inputKind: "rationale" | "capability-identifier"
      readonly matchedPatternId: string
      readonly evidence: string
    }
  | {
      readonly _tag: "RevokerNotInDelegationChain"
      readonly mandateId: MandateId
      readonly revoker: GrantorId
    }
  | {
      readonly _tag: "MandateRevoked"
      readonly mandateId: MandateId
      readonly revokedAt: ISO8601
      readonly revokedBy: GrantorId
      readonly rationale: string
    }
  | {
      readonly _tag: "AncestorMandateRevoked"
      readonly mandateId: MandateId
      readonly revokedAncestorId: MandateId
      readonly revokedAt: ISO8601
    }
  | {
      readonly _tag: "MandateNotIssued"
      readonly mandateId: MandateId
    }
  | {
      readonly _tag: "MandateScopeForged"
      readonly mandateId: MandateId
      readonly capability: string
    }
  | {
      // Raised at enforcement time (useCapability) when the delegation chain
      // cannot be fully reconstructed from the audit log because a non-leaf
      // ancestor's grant event is missing (a tampered / truncated log). The
      // invocation is denied fail-CLOSED — an unreconstructable chain could
      // hide a revoked ancestor above the break. (DAN-640.)
      readonly _tag: "DelegationChainBroken"
      readonly mandateId: MandateId
      readonly brokenAncestorId: MandateId
    }
  | {
      readonly _tag: "DirectConstructionRejected"
      readonly reason: string
    }
  | {
      // Raised at issue time when the grantor's tier cannot delegate the
      // requested tier: agent → anything, org → agent (skipping project), or
      // a non-org grantor through `issueProjectMandate`. The compiler refuses
      // these for typed callers; this is the runtime half for `as any` and
      // JavaScript callers. (A `requestedTier` of "organization" was reachable
      // only through the v0.0 `issueMandate`, removed 2026-10-13; nothing
      // raises it now.)
      // `grantorTier` is read from an issued, frozen scope, so it is fact.
      // (DAN-1157, F3.)
      readonly _tag: "TierLadderViolation"
      readonly grantorMandateId: MandateId
      readonly grantorTier: MandateTier
      readonly requestedTier: MandateTier
    }
  | {
      // Raised by a durable (JSONL) audit store when its file cannot be
      // trusted as a record: a line that does not parse, or, in the signed
      // store, a chain that does not verify under the store's pinned key.
      // Fail-CLOSED: every read throws, including a direct `isRevoked`, and
      // the signed store refuses to append past it. A bad line is never
      // skipped (dropping a revoke while keeping its grant resurrects a revoked
      // mandate) and never read as an empty log (which flipped `isRevoked` from
      // true to false, F5). An unreadable file (permissions, not a file)
      // propagates its own I/O error instead: unreadable is not corrupt.
      // (DAN-1159, F4.)
      readonly _tag: "AuditLogCorrupt"
      readonly storePath: string
      /** 1-based line number in the store file. */
      readonly line: number
      readonly reason: "unparseable" | Exclude<VerifyAuditChainResult["reason"], "ok" | "empty-chain">
      readonly detail?: string
    }

/**
 * TriggerSource — forensic primitive distinguishing audit records that
 * originated from a direct code call (`"code"`) versus a Linear-issue-driven
 * flow (`"linear"`). Per mandate-v0-1-linear-integration.allium I11.
 *
 * When something goes wrong, "did a human do this via Linear, or did a code
 * path do this directly?" must be answerable instantly. Both are legitimate;
 * both must be auditable; the distinction matters for trust analysis.
 *
 * Default for every entry point (the three issuers, useCapability,
 * revokeMandate) is `"code"`. A Linear-triggered flow passes `"linear"`
 * explicitly.
 */
export type TriggerSource = "linear" | "code"

/**
 * MandateGrantEvent — append-only audit record for an issuance.
 */
export interface MandateGrantEvent {
  readonly type: "grant"
  readonly mandateId: MandateId
  readonly grantor: GrantorId
  readonly capabilities: ReadonlyArray<string>
  readonly rationale: string
  readonly parentMandateId: MandateId | null
  readonly timestamp: ISO8601
  readonly triggerSource: TriggerSource
}

/**
 * MandateInvocationEvent — append-only audit record for a capability use.
 * Captured per spec I6 + INV-EVAL-1.
 */
export interface MandateInvocationEvent {
  readonly type: "invoke"
  readonly mandateId: MandateId
  readonly capability: string
  readonly timestamp: ISO8601
  readonly triggerSource: TriggerSource
}

/**
 * MandateRevokeEvent — append-only audit record for revocation.
 */
export interface MandateRevokeEvent {
  readonly type: "revoke"
  readonly mandateId: MandateId
  readonly revokedBy: GrantorId
  readonly rationale: string
  readonly timestamp: ISO8601
  readonly triggerSource: TriggerSource
}

/**
 * MandateHumanContextEvent — documentation-only audit record streamed from
 * Linear comments on a mandate-linked issue. Per
 * mandate-v0-1-linear-integration.allium I8: comments on a mandate-linked
 * issue do NOT trigger state changes; they are documentation queryable
 * alongside the typed grant/invoke/revoke events for forensic analysis.
 *
 * Only ever has `triggerSource: "linear"` — code paths cannot manufacture
 * "human context" out of nowhere; this event class only exists because a
 * human wrote a comment on a Linear issue.
 */
export interface MandateHumanContextEvent {
  readonly type: "human-context"
  readonly mandateId: MandateId
  readonly linearCommentUrl: string
  readonly linearIssueId: string
  readonly author: string
  readonly body: string
  readonly timestamp: ISO8601
  readonly triggerSource: "linear"
}

export type MandateAuditEvent =
  | MandateGrantEvent
  | MandateInvocationEvent
  | MandateRevokeEvent
  | MandateHumanContextEvent

/**
 * SignedMandateAuditEvent — v1.0 cryptographically-signed wrapper around an
 * audit event per the mandate multi-tier + signing specification v0.2
 * I6 + I7 + I9.
 *
 * Wraps any MandateAuditEvent with:
 *   - signature: Ed25519 signature over the canonical-JSON ENVELOPE
 *     (domain + payload + previousHash + signedAt — see signer.signedPreimage),
 *     NOT the payload alone. Because previousHash and signedAt are inside the
 *     signed bytes, deletion/reorder/retiming of records is detectable even
 *     against an adversary who recomputes the (public) hash links: any relink
 *     breaks a signature they cannot reforge (DAN-641). (Tail truncation of the
 *     most recent records remains catchable only by an external anchor, exactly
 *     as @sweetrust/verify documents for its receipt chain.)
 *   - signerPublicKeyHex: the public key the signature was computed with
 *     (per I10, persisted on every record so a verifier-only Layer can
 *     verify without knowing the private key; future-proofs key rotation).
 *     NB: this proves internal consistency, not authorship — pinning the
 *     EXPECTED operator key is the caller's job (DAN-642).
 *   - signedAt: timestamp at signing (authenticated — inside the signature)
 *   - previousHash: SHA-256 of canonical JSON of the previous signed event
 *     in the same audit log, or null for the first event (authenticated —
 *     inside the signature, per I8 + I9).
 *   - domain: domain-separation tag (e.g. MANDATE_AUDIT_DOMAIN) binding the
 *     signature to its protocol context so it cannot be replayed as another
 *     record type under a shared key (DAN-641).
 *
 * Consumers without a MandateSigner Layer in scope continue to see raw
 * MandateAuditEvent objects (v0.0 + v0.1 + v0.1.1 backward compat). The
 * signed wrapper is opt-in via the SignedMandateAudit Layer composition.
 */
export interface Signed<P> {
  readonly payload: P
  readonly signature: string
  readonly signerPublicKeyHex: string
  readonly signedAt: ISO8601
  readonly previousHash: string | null
  readonly domain: string
}

export type SignedMandateAuditEvent = Signed<MandateAuditEvent>

/**
 * VerifyAuditChainResult — return shape for verifyAuditChain. Identifies the
 * first index where verification fails (or null if all valid) plus a typed
 * reason discriminator so callers can pattern-match.
 */
export interface VerifyAuditChainResult {
  readonly valid: boolean
  readonly firstInvalidIndex: number | null
  readonly reason:
    | "ok"
    | "signature-mismatch"
    | "hash-chain-broken"
    | "missing-signature"
    | "untrusted-signer"
    | "domain-mismatch"
    /** No records at all. Nothing to check is not a pass (DAN-1159). */
    | "empty-chain"
    /** A record too malformed to check: not an object, a bad key or signature encoding, a value canonicalJSON cannot encode. */
    | "malformed-record"
  /** Human-readable context for `empty-chain` and `malformed-record`. Never parse it. */
  readonly detail?: string
}

/**
 * MandateAudit — Layer interface for the append-only audit log. Mirrors the
 * EvalRecorder pattern from sense/evals/. v0.0 ships JSONL recording;
 * v0.1+ adds cryptographic signing.
 */
export interface MandateAuditService {
  readonly record: (event: MandateAuditEvent) => void
  readonly query: (mandateId: MandateId) => ReadonlyArray<MandateAuditEvent>
  readonly isRevoked: (mandateId: MandateId) => boolean
}
