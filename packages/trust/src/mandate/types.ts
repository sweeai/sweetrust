/**
 * sweetrust/mandate — core types
 *
 * Type-enforced agent capability declaration. A `MandateScope` is a typed
 * bundle of capabilities at a tier. The compiler refuses a `useCapability`
 * call whose capability is not in the scope's tuple (`Cap extends
 * Caps[number]`) and refuses a delegation whose capabilities are not a subset
 * of the grantor's (`ChildCaps extends ReadonlyArray<ParentCaps[number]>`);
 * the issuers re-check both at runtime for callers with no compiler in the
 * loop. Every grant, invocation and revocation lands on an append-only audit
 * log, signed and hash-chained when a signer is wired. Refusals are the typed
 * `MandateError` union, thrown as `MandateFailure`.
 */
import type { Purpose } from "../purpose.ts"

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
 * CapabilityLimit — how much of one capability a grant allows (DAN-1319).
 *
 * `amount` caps the SUM of `amount`s passed to `useCapability` for the
 * capability; `count` caps the number of uses; `windowMs` makes both rolling
 * (only uses inside the last `windowMs` count), and absent means for the life
 * of the mandate. `unit` is a label the kernel compares for equality at
 * delegation and never interprets: "USD", "SUI", "emails" are all fine.
 *
 * The limit is recorded in the GRANT EVENT, so it is immutable and, under a
 * signed store, unforgeable; the spend is summed from the INVOKE EVENTS of the
 * same log at every use. No counter lives in memory, so a restart alone
 * changes nothing. A log whose tail was cut is a valid shorter log and does
 * refund what it lost (SECURITY.md). Every capability key is resolved before
 * the log is read, so no holder's object can run between the check and the
 * record (the 2026-11-08 audit, K1).
 *
 * Three honest limits. (1) A cap binds a LEAF: a holder of a capped scope that
 * can still delegate may mint children each capped at the same amount, so cap
 * the agent-tier scope you hand the agent, never only its parents; subtree
 * summation is a later decision. (2) `amount` is what the HOST declares to
 * `useCapability`; the kernel enforces declared spend, so the host, never the
 * agent, must make that call with the true figure. (3) Amounts are summed as
 * JavaScript numbers; use integers in minor units (cents) for money, or a
 * cap of 0.3 will refuse 0.1 + 0.2.
 */
export interface CapabilityLimit {
  /** Cap on the sum of invocation `amount`s. A capped capability refuses an invoke that declares none. */
  readonly amount?: number
  /** Cap on the number of invocations. */
  readonly count?: number
  /** Rolling window in milliseconds; absent = the life of the mandate. */
  readonly windowMs?: number
  /** A label for `amount`; compared for equality at delegation, never interpreted. */
  readonly unit?: string
}

/** Per-capability limits, keyed by capability key. */
export type CapabilityLimits = Readonly<Record<string, CapabilityLimit>>

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
 * MandateTier — discriminator for the three-tier mandate hierarchy. The tier is
 * tracked at the type level via the `Tier` generic parameter on
 * MandateScope.
 *
 * Tier semantics (strictly decreasing scope, no upward delegation):
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
 * The scope is IMMUTABLE post-construction. To "add" a capability, issue a
 * new MandateScope via re-grant.
 *
 * The type-level chain enforces multi-tier subset gating
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
  /** Mirrors the grant event's limits (`{}` when none). The EVENT is what enforcement reads. */
  readonly limits: CapabilityLimits
  readonly grantor: GrantorId
  readonly grantTimestamp: ISO8601
  readonly grantRationale: string
  readonly parentMandateId: MandateId | null
  readonly parentScope: ParentScope
}

/**
 * ResumedScope — the scope `resume` returns for a declared tier (DAN-1320).
 * The parent chain is typed by tier so a resumed project can be handed to
 * `issueAgentMandate` without a cast; with no tier declared the scope is
 * typed loosely (any tier, any parent) and the host narrows on `tier`.
 */
export type ResumedScope<Caps extends ReadonlyArray<Capability>, Tier extends MandateTier> =
  MandateTier extends Tier ? MandateScope<Caps, MandateTier, MandateScope<any, any, any> | null>
  : Tier extends "organization" ? MandateScope<Caps, "organization", null>
  : Tier extends "project" ? MandateScope<Caps, "project", MandateScope<any, "organization", null>>
  : Tier extends "agent" ? MandateScope<Caps, "agent", MandateScope<any, "project", MandateScope<any, "organization", null>>>
  : never

/**
 * MandateError — typed union covering every failure mode of the mandate
 * flow. No untyped errors leak: every failure has a discriminated _tag the
 * caller can pattern-match on, and is thrown as `MandateFailure`.
 */
export type MandateError =
  | { readonly _tag: "CapabilityNotInGrantorScope"; readonly capability: string }
  | {
      readonly _tag: "MaliciousMandateMetadata"
      readonly inputKind: "rationale" | "capability-identifier" | "purpose"
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
      // Raised when a scope this module DID issue is presented to a client
      // bound to a different audit store than the one that recorded its grant:
      // at use (`mandate`), at revoke (`revokerScope`) and at delegation
      // (`grantorScope`). Before the store was bound at construction, a caller
      // could present a genuine, revoked scope together with a log of its own
      // holding one forged grant line, and be allowed (the 2026-10-31 review).
      // A scope the module never issued keeps its more specific verdict,
      // `MandateScopeForged`; this one names the store mismatch alone.
      readonly _tag: "MandateScopeForeign"
      readonly mandateId: MandateId
    }
  | {
      // Raised at use when the spend or count this invoke would bring the
      // capability to exceeds the limit recorded in the mandate's grant event
      // (DAN-1319). `used` is what the audit log already holds inside the
      // window; `requested` is this invoke's amount (0 when none was given).
      // Nothing is recorded for a refused invoke.
      readonly _tag: "MandateLimitExceeded"
      readonly mandateId: MandateId
      readonly capability: string
      readonly limit: CapabilityLimit
      readonly used: { readonly amount: number; readonly count: number }
      readonly requested: number
    }
  | {
      // Raised at use when the grant caps the capability by `amount` and the
      // invoke declares none. Fail closed: an unstated spend against a budget
      // is a spend the budget cannot count.
      readonly _tag: "MandateAmountRequired"
      readonly mandateId: MandateId
      readonly capability: string
    }
  | {
      // Raised at use when `amount` is not a finite, non-negative number
      // (NaN, ±Infinity, negative, a string). Refused whether or not the
      // capability is capped: a value the kernel cannot add is not recorded.
      readonly _tag: "MandateAmountInvalid"
      readonly mandateId: MandateId
      readonly capability: string
      readonly received: unknown
    }
  | {
      // Raised at delegation when the child's limit on a capability is looser
      // than the grantor's RECORDED limit, or absent where the grantor has
      // one: a larger `amount` or `count`, a
      // different `unit`, a SHORTER window (more per day), or a window where
      // the grantor's cap is for life. A child may only tighten. `field`
      // names the first field that failed.
      readonly _tag: "LimitNotWithinGrantor"
      readonly grantorMandateId: MandateId
      readonly capability: string
      readonly field: "amount" | "count" | "windowMs" | "unit"
    }
  | {
      // A delegated purpose that would widen its grantor's recorded one, spec
      // I9 (DAN-1384). A child that omits the purpose or a field the grantor
      // set is refused too, because omission would widen. `field` names the
      // first failure.
      readonly _tag: "PurposeNotNarrowing"
      readonly grantorMandateId: MandateId
      readonly field: "purpose" | "statement" | "payees" | "maxPerAction" | "actions"
    }
  | {
      // Raised by `resume` when what the caller declares about the mandate
      // (its capability set, its tier) is not what the log recorded
      // (DAN-1320). Both lists are sorted. A host that resumes with the wrong
      // shape is a host that would type-check the wrong calls.
      readonly _tag: "ResumeMismatch"
      readonly mandateId: MandateId
      readonly field: "capabilities" | "tier"
      readonly declared: ReadonlyArray<string>
      readonly recorded: ReadonlyArray<string>
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
 * TriggerSource — which kind of caller produced an audit record: a direct code
 * path (`"code"`), or a host-side flow driven from outside this process — a
 * human acting through an issue tracker, a chat command, a ticket
 * (`"external"`).
 *
 * When something goes wrong, "did a person do this through a tool, or did a
 * code path do this directly?" must be answerable from the log alone. Both are
 * legitimate; both are audited; the distinction is for forensics.
 *
 * Every entry point (the three issuers, `useCapability`, `revokeMandate`)
 * defaults to `"code"`. A host that drives them from an external system passes
 * `"external"` explicitly.
 */
export type TriggerSource = "external" | "code"

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
  /** Per-capability limits (DAN-1319). Absent when the grant set none. This is the record enforcement reads. */
  readonly limits?: CapabilityLimits
  /** What the owner granted this for, signed with the grant (DAN-1384). Absent when the grant set none, so a purposeless grant's bytes do not move. */
  readonly purpose?: Purpose
}

/**
 * MandateInvocationEvent — append-only audit record for a capability use.
 */
export interface MandateInvocationEvent {
  readonly type: "invoke"
  readonly mandateId: MandateId
  readonly capability: string
  readonly timestamp: ISO8601
  readonly triggerSource: TriggerSource
  /** The amount this use spent, when the caller declared one (DAN-1319). Summed by later limit checks. */
  readonly amount?: number
  /** The digest of the verdict that approved this use, as the host states it: 64 lowercase hex (DAN-1385). Signed with the event, never recomputed or checked against a verdict here. Absent when the host named none, so an unjudged invoke's bytes do not move. */
  readonly verdictDigest?: string
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
 * ExternalRef — where, outside this process, a record came from: the system's
 * name as the host names it (an issue tracker, a chat tool, a mail system), the
 * record's id inside that system, and a URL when the system has one. This
 * package never produces or follows one; it records what the host hands it.
 */
export interface ExternalRef {
  readonly system: string
  readonly id: string
  readonly url?: string
}

/**
 * MandateHumanContextEvent — a documentation-only audit record a HOST appends
 * when a human says something about a mandate in an external system (a comment
 * on a ticket, a message in a channel). It changes no state. It is queryable
 * alongside the typed grant / invoke / revoke events so a forensic reader sees
 * what people said next to what the code did.
 *
 * Nothing in this package produces one. Its `triggerSource` is always
 * `"external"`: a code path cannot manufacture human context.
 */
export interface MandateHumanContextEvent {
  readonly type: "human-context"
  readonly mandateId: MandateId
  readonly externalRef: ExternalRef
  readonly author: string
  readonly body: string
  readonly timestamp: ISO8601
  readonly triggerSource: "external"
}

/**
 * MandateResumeEvent — a process picked an issued mandate back up from the
 * log with `trust.resume`. It changes no authority: the grant is the
 * authority, and the chain walk at resume is the same one `useCapability`
 * runs. It is recorded so forensics can see every process that held the
 * mandate, and it never counts toward a limit (DAN-1320).
 */
export interface MandateResumeEvent {
  readonly type: "resume"
  readonly mandateId: MandateId
  /** Who picked it up, as the host names them; the kernel never resolves it. */
  readonly resumedBy: GrantorId
  readonly timestamp: ISO8601
  readonly triggerSource: TriggerSource
}

export type MandateAuditEvent =
  | MandateGrantEvent
  | MandateInvocationEvent
  | MandateRevokeEvent
  | MandateHumanContextEvent
  | MandateResumeEvent

/**
 * Signed<P> — the cryptographically-signed wrapper around a record;
 * `SignedMandateAuditEvent` is `Signed<MandateAuditEvent>`.
 *
 * Wraps any MandateAuditEvent with:
 *   - signature: Ed25519 signature over the canonical-JSON ENVELOPE
 *     (domain + payload + previousHash + signedAt — see signer.signedPreimage),
 *     NOT the payload alone. Because previousHash and signedAt are inside the
 *     signed bytes, deletion/reorder/retiming of records is detectable even
 *     against an adversary who recomputes the (public) hash links: any relink
 *     breaks a signature they cannot reforge (DAN-641). (Tail truncation of the
 *     most recent records remains catchable only by an external anchor, exactly
 *     as sweetrust/verify documents for its receipt chain.)
 *   - signerPublicKeyHex: the public key the signature was computed with
 *     (persisted on every record so a verifier-only consumer can verify
 *     without the private key; future-proofs key rotation).
 *     NB: this proves internal consistency, not authorship — pinning the
 *     EXPECTED operator key is the caller's job (DAN-642).
 *   - signedAt: timestamp at signing (authenticated — inside the signature)
 *   - previousHash: SHA-256 of canonical JSON of the previous signed event
 *     in the same audit log, or null for the first event (authenticated —
 *     inside the signature).
 *   - domain: domain-separation tag (e.g. MANDATE_AUDIT_DOMAIN) binding the
 *     signature to its protocol context so it cannot be replayed as another
 *     record type under a shared key (DAN-641).
 *
 * The unsigned audit factories record raw `MandateAuditEvent` objects; the
 * signed factories (`makeInMemorySignedAuditLive`, `makeJsonlSignedAuditLive`)
 * wrap each one in this envelope.
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
 * MandateAuditService — the append-only audit log every issuer, `useCapability`
 * and `revokeMandate` take. Four factories produce one: `makeInMemoryAuditLive`
 * and `makeJsonlAuditLive` (unsigned), and the `mandateAudit` half of
 * `makeInMemorySignedAuditLive` / `makeJsonlSignedAuditLive` (signed and
 * hash-chained).
 */
export interface MandateAuditService {
  readonly record: (event: MandateAuditEvent) => void
  readonly query: (mandateId: MandateId) => ReadonlyArray<MandateAuditEvent>
  readonly isRevoked: (mandateId: MandateId) => boolean
}
