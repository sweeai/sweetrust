/**
 * sweetrust/mandate — createTrust, the one door to issue, use and revoke.
 *
 * Until 0.5.0 the five entry points were free functions, each taking the audit
 * store as a trailing argument. On 2026-10-31 a stranger's review of the
 * published package found what that argument meant, and a second reader
 * reproduced it against `dist/`: a caller holding its own genuine, revoked
 * scope built a fresh in-memory store, recorded one forged `grant` line for its
 * own id, passed that store in, and was allowed. Every audit-log check ran. It
 * ran against a log the caller had just written. README promised a kill switch
 * that was "structural, not advisory"; it was as strong as the second argument.
 *
 * The store is now bound ONCE, here, and never named per call again. The
 * client's verbs have the same `args` as the old functions minus the store, so
 * a scope issued by this client is judged by this client's store, and a scope
 * minted against a different store is refused as `MandateScopeForeign`
 * (mandate.ts, the note above `BOUND`). Two clients over the SAME store object
 * agree, because the binding is to the store, not to the client; that is what
 * lets a host construct a client where it needs one.
 *
 * `audit` on the client is a read-only view: `query` and `isRevoked`, no
 * `record`. The store object the host passed in still has `record`, and it is
 * the root credential of this trust domain: hand an agent its own scope, never
 * the store and never the client (SECURITY.md § Honest limits).
 *
 * What this does not close, as ADR 0001 and ADR 0004 say: code that can call
 * `createTrust` with a store of its own can mint a fresh org mandate on it.
 * In-process, the process holds root. The remedy is a process boundary.
 *
 * Intake: `config` is read once (`store`), and the verbs forward their `args`
 * object untouched to the implementations, which read each field exactly once
 * (AGENTS.md § Non-negotiables, "Intake"; test/intake-poison.test.ts).
 */
import {
  issueAgentMandate as issueAgentMandateImpl,
  grantedPurpose as grantedPurposeImpl,
  issueOrgMandate as issueOrgMandateImpl,
  issueProjectMandate as issueProjectMandateImpl,
  resumeMandate as resumeMandateImpl,
  revokeMandate as revokeMandateImpl,
  settleCapability as settleCapabilityImpl,
  useCapability as useCapabilityImpl,
} from "./mandate.ts"
import type { GrantedPurpose, Purpose } from "../purpose.ts"
import type {
  Capability,
  CapabilityLimits,
  GrantorId,
  MandateAuditEvent,
  MandateAuditService,
  MandateId,
  MandateScope,
  MandateTier,
  ResumedScope,
  TriggerSource,
} from "./types.ts"

export interface TrustConfig {
  /**
   * The audit store every grant, invoke and revoke of this client is recorded
   * in and judged by. Build it with `makeInMemoryAuditLive`, `makeJsonlAuditLive`,
   * or the signed factories (`makeInMemorySignedAuditLive(signer).mandateAudit`,
   * `makeJsonlSignedAuditLive(path, signer).mandateAudit`).
   */
  readonly store: MandateAuditService
}

/** The store, readable. No `record`: the client writes, callers read. */
export interface AuditView {
  readonly query: (mandateId: MandateId) => ReadonlyArray<MandateAuditEvent>
  readonly isRevoked: (mandateId: MandateId) => boolean
}

export interface TrustClient {
  /** Bootstrap the organization tier: the root of a trust domain. No parent. */
  readonly issueOrgMandate: <Caps extends ReadonlyArray<Capability>>(args: {
    readonly grantor: GrantorId
    readonly capabilities: Caps
    readonly rationale: string
    readonly triggerSource?: TriggerSource
    /** Per-capability caps, keyed by capability key (DAN-1319). */
    readonly limits?: CapabilityLimits
    /** What this grant is for, signed into it. The statement is at most 280 characters (DAN-1384). */
    readonly purpose?: Purpose
  }) => MandateScope<Caps, "organization", null>

  /** Derive a project tier from an org scope this client issued; a compile-time subset. */
  readonly issueProjectMandate: <
    OrgCaps extends ReadonlyArray<Capability>,
    ProjectCaps extends ReadonlyArray<OrgCaps[number]>,
  >(args: {
    readonly grantor: GrantorId
    readonly grantorScope: MandateScope<OrgCaps, "organization", null>
    readonly capabilities: ProjectCaps
    readonly rationale: string
    readonly triggerSource?: TriggerSource
    /** Per-capability caps; at least as tight as the grantor's on every capped capability carried (DAN-1319). */
    readonly limits?: CapabilityLimits
    /** What this grant is for; only ever narrows the grantor's recorded purpose, and may not be omitted if it has one (DAN-1384). */
    readonly purpose?: Purpose
  }) => MandateScope<ProjectCaps, "project", MandateScope<OrgCaps, "organization", null>>

  /** Derive an agent tier, a leaf, from a project scope this client issued. */
  readonly issueAgentMandate: <
    OrgCaps extends ReadonlyArray<Capability>,
    ProjectCaps extends ReadonlyArray<OrgCaps[number]>,
    AgentCaps extends ReadonlyArray<ProjectCaps[number]>,
  >(args: {
    readonly grantor: GrantorId
    readonly grantorScope: MandateScope<ProjectCaps, "project", MandateScope<OrgCaps, "organization", null>>
    readonly capabilities: AgentCaps
    readonly rationale: string
    readonly triggerSource?: TriggerSource
    /** Per-capability caps; at least as tight as the grantor's on every capped capability carried (DAN-1319). */
    readonly limits?: CapabilityLimits
    /** What this grant is for; only ever narrows the grantor's recorded purpose, and may not be omitted if it has one (DAN-1384). */
    readonly purpose?: Purpose
  }) => MandateScope<
    AgentCaps,
    "agent",
    MandateScope<ProjectCaps, "project", MandateScope<OrgCaps, "organization", null>>
  >

  /**
   * Invoke a capability under a scope this client issued. Refused if the scope
   * or any ancestor is revoked, if the scope was never issued or was minted
   * against another store, or if the capability is outside the scope.
   */
  readonly useCapability: <
    Caps extends ReadonlyArray<Capability>,
    Cap extends Caps[number],
    Tier extends MandateTier = "organization",
    ParentScope extends MandateScope<any, any, any> | null = null,
  >(args: {
    readonly mandate: MandateScope<Caps, Tier, ParentScope>
    readonly capability: Cap
    readonly triggerSource?: TriggerSource
    /** What this use spends; required when the grant caps the capability by amount (DAN-1319). */
    readonly amount?: number
    /** The digest of the verdict that approved this use, recorded on the invoke event: 64 lowercase hex, else a TypeError (DAN-1385). */
    readonly verdictDigest?: string
    /** Your name for this hold, so `settleCapability` can point at it: 32 lowercase hex, else a TypeError (ADR 0011). */
    readonly holdId?: string
  }) => void

  /**
   * Record what a held invoke really cost, so the limit counts `actual` in place
   * of the invoke's `amount`, at the invoke's own time and still as one call
   * (ADR 0011). A hold settles down, at most once, and never moves spend into
   * another window. Allowed on a revoked mandate: it records a call made before
   * the revoke and can only lower the count. Refused, writing nothing, as
   * `MandateSettleUnknownHold`, `MandateSettleNoAmount`, `MandateSettleAboveAmount`,
   * `MandateSettleDuplicate`, `MandateSettleAmbiguousHold` or `MandateAmountInvalid`.
   */
  readonly settleCapability: <
    Caps extends ReadonlyArray<Capability>,
    Cap extends Caps[number],
    Tier extends MandateTier = "organization",
    ParentScope extends MandateScope<any, any, any> | null = null,
  >(args: {
    readonly mandate: MandateScope<Caps, Tier, ParentScope>
    readonly capability: Cap
    /** The `holdId` the invoke carried: 32 lowercase hex, else a TypeError. */
    readonly holdId: string
    /** What the call really cost: finite, non-negative, at most the invoke's `amount`. */
    readonly actual: number
    readonly triggerSource?: TriggerSource
  }) => void

  /** Revoke a mandate; the revoker proves position by possessing the target or an ancestor. */
  readonly revokeMandate: (args: {
    readonly mandateId: MandateId
    readonly revokerScope: MandateScope<any, any, any>
    readonly rationale: string
    readonly triggerSource?: TriggerSource
  }) => void

  /**
   * Pick an issued, unrevoked mandate back up from this store's log, as the
   * same mandate with the same budget (DAN-1320). Declare the capability set
   * you expect, and the tier if you want it typed; both are checked against
   * the record, and every link of the rebuilt chain is re-checked for subset
   * and tightness. Refused as use would refuse: revoked, ancestor revoked,
   * never issued, chain broken. A client holder can resume ANY mandate in
   * this store's log, so it can act as any holder: hand an agent its scope,
   * never the client.
   */
  readonly resume: <Caps extends ReadonlyArray<Capability>, Tier extends MandateTier = MandateTier>(args: {
    readonly mandateId: MandateId
    readonly capabilities: Caps
    /** Who is picking the mandate up; recorded on the resume event. */
    readonly resumedBy: GrantorId
    readonly tier?: Tier
    readonly triggerSource?: TriggerSource
  }) => ResumedScope<Caps, Tier>

  /**
   * The purpose this scope's grant event records and the hash naming that
   * grant, for the host to hand a judged sink. Read from the log. A copy of a
   * scope, a scope from another store, and a mandate that is revoked or has a
   * revoked ancestor are refused; a grant with no purpose is a TypeError
   * (DAN-1384).
   */
  readonly grantedPurpose: (scope: MandateScope<any, any, any>) => GrantedPurpose

  readonly audit: AuditView
}

const isStore = (x: unknown): x is MandateAuditService =>
  typeof x === "object" &&
  x !== null &&
  typeof (x as MandateAuditService).record === "function" &&
  typeof (x as MandateAuditService).query === "function" &&
  typeof (x as MandateAuditService).isRevoked === "function"

/**
 * Construct the client for one audit store. A `TypeError` here is a programmer
 * error, not a refusal: no authority decision has been made yet, so this does
 * not go through `MandateFailure`.
 */
export const createTrust = (config: TrustConfig): TrustClient => {
  // Read once (the intake rule). Everything below closes over this local.
  const store: unknown = (config as { readonly store?: unknown } | null | undefined)?.store
  if (!isStore(store)) {
    throw new TypeError(
      "createTrust: config.store must be a MandateAuditService (record, query, isRevoked); " +
        "build one with makeInMemoryAuditLive, makeJsonlAuditLive or a signed factory's .mandateAudit",
    )
  }

  const audit: AuditView = Object.freeze({
    query: (mandateId: MandateId) => store.query(mandateId),
    isRevoked: (mandateId: MandateId) => store.isRevoked(mandateId),
  })

  // The verbs hand `args` through untouched: the implementations snapshot each
  // field once, and a second read here would be the TOCTOU hole the intake
  // rule exists to prevent.
  const client: TrustClient = {
    issueOrgMandate: (args) => issueOrgMandateImpl(args, store),
    issueProjectMandate: (args) => issueProjectMandateImpl(args, store),
    issueAgentMandate: (args) => issueAgentMandateImpl(args, store),
    useCapability: (args) => useCapabilityImpl(args, store),
    settleCapability: (args) => settleCapabilityImpl(args, store),
    revokeMandate: (args) => revokeMandateImpl(args, store),
    resume: (args) => resumeMandateImpl(args, store),
    grantedPurpose: (scope) => grantedPurposeImpl(scope, store),
    audit,
  }
  return Object.freeze(client)
}
