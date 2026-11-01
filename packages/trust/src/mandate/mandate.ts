/**
 * sweetrust/mandate — issuance, invocation, revocation flows
 *
 * This module imports the constitutional pre-check
 * primitive from ./security.ts (formerly a standalone package, folded back into mandate 2026-07-19). Mandate metadata (rationale strings and, since the
 * 2026-10-13 mandate audit, capability identifiers) is exactly the attack
 * surface the pre-check exists to defend.
 */
import { randomBytes } from "node:crypto"
import { constitutionalPreCheck } from "./security.ts"
import { MandateFailure } from "./errors.ts"
import type {
  Capability,
  CapabilityLimit,
  CapabilityLimits,
  GrantorId,
  ISO8601,
  MandateAuditEvent,
  MandateAuditService,
  MandateError,
  MandateGrantEvent,
  MandateId,
  MandateScope,
  MandateTier,
  ResumedScope,
  TriggerSource,
} from "./types.ts"

/**
 * failMandate — throw a typed MandateError as a `MandateFailure`: a real Error
 * whose own properties ARE the discriminated union, so callers still catch it
 * and pattern-match on `_tag` (DAN-1159 item 4c; see errors.ts).
 */
const failMandate = (error: MandateError): never => {
  throw new MandateFailure(error)
}

/**
 * defineCapability — construct a capability from a stable string key. The
 * returned value carries only the `key` at runtime; the LITERAL key type is
 * preserved so the compile-time subset gate can distinguish capabilities.
 *
 * A capability is just an identity with a name; no dependency-injection
 * framework is involved, and the runtime object carries nothing but `key`.
 */
export const defineCapability = <const Id extends string>(key: Id): Capability<Id> => {
  // Fail where the string was authored (the 2026-10-13 mandate audit). The
  // issuers screen again at the persistence site, because a capability can
  // reach them without passing through here: `capabilityKey` tolerates a bare
  // string or any object with a `key`.
  assertCapabilityIdentifierClean(key)
  return { key }
}

/**
 * grantorId — brand a string as a `GrantorId` (DAN-1320, asked for by the
 * README: `"ARTHUR" as GrantorId` was the only cast left in the examples).
 * A grantor is a name the host chooses and the log prints; the kernel never
 * resolves it. Empty is refused because an empty name in a grant event is a
 * record that says nobody granted it.
 */
export const grantorId = (id: string): GrantorId => {
  if (typeof id !== "string" || id.length === 0) {
    throw new TypeError("grantorId: expected a non-empty string")
  }
  return id as GrantorId
}

/**
 * Extract the canonical string key for a `Capability`.
 *
 * A capability carries a stable `key`. This helper centralizes the lookup
 * (and tolerates any-cast escape hatches where a bare string sneaks in): the
 * one branded-object-or-string fallback, where several copies used to live.
 */
export const capabilityKey = (cap: Capability): string => {
  const branded = cap as unknown as { key?: string }
  return branded.key ?? String(cap)
}

/**
 * Screen a capability identifier before it is persisted. AGENTS.md: any
 * function that persists an authored string runs `constitutionalPreCheck`
 * first. Identifiers reach grant events through each issuer's resolved
 * `capabilityIds`, and until the 2026-10-13 mandate audit they did so
 * unscreened; `MandateError` had reserved `inputKind: "capability-identifier"`
 * for exactly this. `useCapability` needs no screen of its own: the capability
 * it records must be in the mandate's recorded grant, which was screened here.
 */
const assertCapabilityIdentifierClean = (key: string): void => {
  const match = constitutionalPreCheck(key)
  if (match) {
    failMandate({
      _tag: "MaliciousMandateMetadata",
      inputKind: "capability-identifier",
      matchedPatternId: match.patternId,
      evidence: match.evidence,
    })
  }
}

/**
 * Generate a sortable identifier with crypto-strong randomness.
 *
 * Format: MAN_<base36-ms-timestamp>_<16-hex-chars-from-crypto.randomBytes>.
 * The timestamp prefix preserves ULID-like ordering for forensic readability;
 * the 64-bit suffix uses node:crypto so an attacker cannot predict the next
 * mandate ID and pre-compute hash-chain or audit-log forgeries. Until the
 * 2026-10-13 mandate audit it kept 10 of the 16 hex characters, 40 bits, and
 * nothing consulted the log at issue time; `freshMandateId` does now.
 */
const generateMandateId = (): MandateId => {
  const ts = Date.now().toString(36).padStart(10, "0")
  const rand = randomBytes(8).toString("hex")
  return (`MAN_${ts}_${rand}`.toUpperCase()) as MandateId
}

/**
 * An id this log has never seen (the 2026-10-13 mandate audit). The random
 * suffix makes a collision unlikely; this makes reuse impossible within one
 * log. An issuer never records a second grant under an id the log already
 * knows, which would let `useCapability`'s `find(grant)` resolve the new scope
 * against the OLD mandate's capabilities. ANY event counts, not only a grant:
 * adopting an id that already carries a revoke would mint a mandate born
 * revoked. One `query` per issue; the loop runs again only on a hit.
 */
const freshMandateId = (audit: MandateAuditService): MandateId => {
  for (;;) {
    const id = generateMandateId()
    if (audit.query(id).length === 0) return id
  }
}

const nowISO = (): ISO8601 => new Date().toISOString() as ISO8601

// ============================================================================
// Possession is the authority (DAN-1157)
// ============================================================================
//
// A scope's authority used to be bound to strings: `mandate.id` at use,
// `revoker` at revocation. Both are caller-supplied, and both are printed in
// the audit log. Matching a presented scope against its grant event cannot fix
// that: every field a grant event records is public, so a full-field copy
// matches by construction (and `tier` is not recorded at all).
//
// So authority binds to something a caller cannot mint: the scope OBJECT this
// module returned. `ISSUED` is module-private, in the same way `Sourced`'s
// constructor is private to gate/trust.ts. A spread, a JSON round-trip or a
// hand-built literal is a different object, and it is refused however
// faithfully it copies the fields. Issued scopes are frozen, so the object in
// the set IS the record: its `tier` and `grantor` can be read as fact once
// `ISSUED.has` passes.
//
// This is the object-capability model: whoever holds the reference holds the
// authority, so a host must hand an agent its own scope and nothing above it.
// That is why `parentScope` is DETACHED. Before DAN-1157 it held the genuine
// grantor object, so an agent holding a read-only scope reached the org root
// by reference, with no cast and no forgery. DAN-637 had already ruled that the
// pointer is not a REVOCATION input. This makes it no AUTHORITY input either.
//
// Scope: in-process. A scope that crosses a process boundary arrives as data
// and cannot invoke. Cross-process authority belongs to the chain's own
// primitives; the named upgrade path, if a TS consumer ever needs it, is a per-mandate secret
// whose hash is committed in the grant event (docs/adr/0001).
//
// The reference, once (the 2026-10-13 mandate audit). Possession is checked
// on an OBJECT, so what is checked and what is acted on must be the same
// object. Every exported function therefore reads each caller-supplied field
// of `args` exactly once, at its top, into a local, and `mint` and
// `audit.record` consume those locals. Before this each site re-read
// `args.mandate`, `args.grantorScope`, `args.mandateId`, `args.capabilities`
// and `args.rationale` for itself, so a caller holding only its own genuine
// leaf could define a getter that returned the genuine object on the read
// `assertIssued` performed and forged data on the others. Four escalations
// followed from a held leaf alone: an unheld capability invoked and recorded
// under another mandate's id; a genuine project-tier scope minted outside the
// leaf's subtree; the org root revoked through `mandateId`; a child whose
// scope and grant both carried a capability outside its grantor's grant.
// Capability KEYS are resolved once as well (`resolveCapabilityIds`), since a
// `key` getter is the same hole one object down. SECURITY.md already records
// the lesson: a check and the decision it authorizes must name the same
// binding. `test/mandate/authority-binding.test.ts` pins the read count.

const ISSUED = new WeakSet<object>()

/** Freeze a freshly built scope (and its capability list) and record it as issued. */
const mint = <S extends MandateScope<any, any, any>>(scope: S): S => {
  const frozen = Object.freeze({
    ...scope,
    capabilities: Object.freeze([...scope.capabilities]),
  }) as S
  ISSUED.add(frozen)
  return frozen
}

/**
 * A read-only view of a grantor scope for a child's `parentScope`: the same
 * fields, so the typed parent chain still reads correctly, but a different
 * object that was never issued, so it carries no authority.
 */
const detach = <S extends MandateScope<any, any, any>>(scope: S): S =>
  Object.freeze({ ...scope }) as S

const isIssued = (scope: unknown): scope is MandateScope<any, any, any> =>
  typeof scope === "object" && scope !== null && ISSUED.has(scope)

// ============================================================================
// Binding to the store (2026-10-31)
// ============================================================================
//
// Possession says the scope is genuine. It does not say which LOG the scope
// belongs to. Until 0.5.0 every entry point took the audit store as a trailing
// argument, so a caller holding its own genuine, revoked scope could build a
// fresh in-memory store, record one forged grant line for its own id, pass that
// store in, and be allowed: every audit-log check ran, against a log the caller
// wrote. The kill switch was as strong as the second argument.
//
// So a scope is bound to the store that recorded its grant, by object identity
// on both sides: `BOUND` maps a store to the set of scopes minted against it.
// `createTrust` (client.ts) holds the store and is the only public door, so a
// caller never names a store per call again; this map is what makes two clients
// over the SAME store agree, and a client over a DIFFERENT store refuse. The
// verdict for a genuine scope on the wrong store is `MandateScopeForeign`; an
// unissued object keeps `MandateScopeForged`, the more specific one.
//
// What this does not close, stated here as in ADR 0001: code that can call
// `createTrust` with a store of its own can still mint a fresh org mandate on
// it. In-process, the process holds root. The boundary that fixes that is a
// process boundary, not this map.

const BOUND = new WeakMap<MandateAuditService, WeakSet<object>>()

/** Record that `scope` was minted against `audit`. Called once per issue, after `mint`. */
const bindTo = (audit: MandateAuditService, scope: object): void => {
  let set = BOUND.get(audit)
  if (set === undefined) {
    set = new WeakSet<object>()
    BOUND.set(audit, set)
  }
  set.add(scope)
}

/**
 * Refuse an issued scope that was minted against a different store. Call only
 * after `assertIssued`, so a forged object has already received its own verdict.
 */
const assertBoundTo = (audit: MandateAuditService, scope: object, mandateId: MandateId): void => {
  if (!(BOUND.get(audit)?.has(scope) ?? false)) {
    failMandate({ _tag: "MandateScopeForeign", mandateId })
  }
}

/**
 * Refuse a scope this module did not issue. Runs AFTER the older audit-log
 * checks, so a scope that is ALSO wrong on data (never issued, capabilities
 * inflated past its grant) keeps its more specific verdict.
 */
const assertIssued = (scope: unknown, mandateId: MandateId, capability: string): void => {
  if (!isIssued(scope)) {
    failMandate({ _tag: "MandateScopeForged", mandateId, capability })
  }
}

/**
 * The tier ladder, at runtime. The compiler already refuses these delegations
 * for typed callers; this is the half that holds for an `as any` or a
 * JavaScript caller. Call only after `assertIssued`: `tier` on an issued scope
 * is frozen fact, while on anything else it is whatever the caller typed.
 */
const assertGrantorTier = (
  grantorScope: MandateScope<any, any, any>,
  required: MandateTier,
  requestedTier: MandateTier,
): void => {
  if (grantorScope.tier !== required) {
    failMandate({
      _tag: "TierLadderViolation",
      grantorMandateId: grantorScope.id,
      grantorTier: grantorScope.tier,
      requestedTier,
    })
  }
}

/**
 * A caller's capability list, read once (the 2026-10-13 mandate audit). The
 * spread iterates the caller's array exactly once and lands every element as a
 * data property, so the frozen copy has no getter left to answer a later read
 * differently. Same elements, same order, which is what makes the cast back to
 * `Caps` sound.
 */
const captureCapabilities = <Caps extends ReadonlyArray<Capability>>(caps: Caps): Caps =>
  Object.freeze([...caps]) as unknown as Caps

/**
 * The string keys of a captured capability list, each `key` read exactly once
 * (the 2026-10-13 mandate audit). The subset checks, the grant event and the
 * error reports all consume THIS list. A `key` getter that answers differently
 * on a later read can then disagree only with itself, never with what was
 * checked: the recorded grant is what the checks saw, so at use time such a
 * capability can at most fail its own subset check.
 */
const resolveCapabilityIds = (caps: ReadonlyArray<Capability>): ReadonlyArray<string> =>
  Object.freeze(caps.map((c) => capabilityKey(c)))

// ============================================================================
// Capability limits (DAN-1319)
// ============================================================================
//
// A grant may cap a capability by amount, count and rolling window. The cap is
// written into the grant event, which is the only record enforcement reads;
// the spend is summed from the invoke events of the same log. No counter is
// kept in memory, so a restart changes nothing and nothing the holder can
// reach can lower what was spent. The scope carries a frozen mirror of the
// limits for the host's convenience; it is not consulted for the verdict.
//
// A bad limit at ISSUE is a programmer error (a `TypeError`, as `createTrust`
// throws for a bad store): no authority decision has been made yet. A bad
// AMOUNT at use is a refusal (`MandateAmountInvalid`): a use is an authority
// decision, and a value the kernel cannot add is not allowed through.

const isFiniteNonNegative = (x: unknown): x is number =>
  typeof x === "number" && Number.isFinite(x) && x >= 0

const EMPTY_LIMITS: CapabilityLimits = Object.freeze({})

/** A frozen copy of a RECORDED limits map (a JSONL read hands back a fresh, writable object). */
const freezeLimits = (raw: CapabilityLimits | undefined): CapabilityLimits => {
  if (raw === undefined) return EMPTY_LIMITS
  const out: Record<string, CapabilityLimit> = {}
  for (const key of Object.keys(raw)) out[key] = Object.freeze({ ...raw[key] })
  return Object.freeze(out)
}

/**
 * Snapshot and validate the caller's `limits` once (the intake rule). Every
 * key must name a capability in this grant; every field must be usable: a
 * finite non-negative `amount`, a non-negative integer `count`, a positive
 * finite `windowMs`, a string `unit`, and at least one of `amount` / `count`
 * (a window alone caps nothing). Returns a frozen copy with frozen entries.
 */
const captureLimits = (raw: unknown, capabilityIds: ReadonlyArray<string>): CapabilityLimits => {
  if (raw === undefined) return EMPTY_LIMITS
  if (typeof raw !== "object" || raw === null) {
    throw new TypeError("limits must be an object keyed by capability key")
  }
  const granted = new Set(capabilityIds)
  const out: Record<string, CapabilityLimit> = {}
  for (const key of Object.keys(raw)) {
    if (!granted.has(key)) {
      throw new TypeError(`limits names "${key}", which is not a capability of this grant`)
    }
    const l: unknown = (raw as Record<string, unknown>)[key]
    if (typeof l !== "object" || l === null) throw new TypeError(`limits["${key}"] must be an object`)
    const { amount, count, windowMs, unit } = l as Record<string, unknown>
    if (amount !== undefined && !isFiniteNonNegative(amount)) {
      throw new TypeError(`limits["${key}"].amount must be a finite non-negative number`)
    }
    if (count !== undefined && !(isFiniteNonNegative(count) && Number.isInteger(count))) {
      throw new TypeError(`limits["${key}"].count must be a non-negative integer`)
    }
    if (windowMs !== undefined && !(isFiniteNonNegative(windowMs) && windowMs > 0)) {
      throw new TypeError(`limits["${key}"].windowMs must be a positive finite number of milliseconds`)
    }
    if (unit !== undefined && typeof unit !== "string") {
      throw new TypeError(`limits["${key}"].unit must be a string`)
    }
    if (amount === undefined && count === undefined) {
      throw new TypeError(`limits["${key}"] caps nothing: set amount and/or count`)
    }
    out[key] = Object.freeze({
      ...(amount === undefined ? {} : { amount }),
      ...(count === undefined ? {} : { count }),
      ...(windowMs === undefined ? {} : { windowMs }),
      ...(unit === undefined ? {} : { unit }),
    })
  }
  return Object.freeze(out)
}

/**
 * A child may only tighten. For every capability the child carries that the
 * grantor's RECORDED grant caps, the child must carry a cap of its own that is
 * at least as tight in every field the grantor set: no larger `amount` or
 * `count`, the same `unit`, and a window that cannot out-spend the parent's.
 *
 * The window direction is the one that is easy to get backwards, and the
 * first draft of this function did (caught by a blind review, 2026-11-01):
 * for a fixed amount, a SHORTER window is LOOSER (100 per hour is 2,400 per
 * day), and no window at all is a lifetime cap, the tightest there is. So:
 * a parent with no window (lifetime) needs a child with no window; a parent
 * with a window accepts a child with no window or with a window at least as
 * LONG. (The exact rule, `child.amount × ceil(parent.window / child.window)
 * ≤ parent.amount`, admits a few more children; this one is a sound subset.)
 * Read from the grantor's grant event, never from the in-memory scope.
 */
const assertLimitsWithinGrantor = (
  audit: MandateAuditService,
  grantorMandateId: MandateId,
  capabilityIds: ReadonlyArray<string>,
  childLimits: CapabilityLimits,
): void => {
  const grantEvent = audit.query(grantorMandateId).find((e) => e.type === "grant") as
    | MandateGrantEvent
    | undefined
  assertLimitsTighterThan(grantorMandateId, grantEvent?.limits, capabilityIds, childLimits)
}

/** The comparison itself, over two RECORDED limit maps; `resume` re-runs it on every link of a chain it rebuilds. */
const assertLimitsTighterThan = (
  grantorMandateId: MandateId,
  parentLimits: CapabilityLimits | undefined,
  capabilityIds: ReadonlyArray<string>,
  childLimits: CapabilityLimits,
): void => {
  if (parentLimits === undefined) return
  for (const capId of capabilityIds) {
    const parent = parentLimits[capId]
    if (parent === undefined) continue
    const child = childLimits[capId]
    const refuse = (field: "amount" | "count" | "windowMs" | "unit"): never =>
      failMandate({ _tag: "LimitNotWithinGrantor", grantorMandateId, capability: capId, field })
    if (parent.amount !== undefined && (child?.amount === undefined || child.amount > parent.amount)) refuse("amount")
    if (parent.count !== undefined && (child?.count === undefined || child.count > parent.count)) refuse("count")
    if (parent.windowMs === undefined) {
      if (child?.windowMs !== undefined) refuse("windowMs")
    } else if (child?.windowMs !== undefined && child.windowMs < parent.windowMs) {
      refuse("windowMs")
    }
    if (parent.unit !== undefined && child?.unit !== parent.unit) refuse("unit")
  }
}

/**
 * The limit verdict at use. `events` is the one snapshot of the mandate's log
 * this call already took; `amountRaw` is the caller's `amount`, read once.
 * Returns the validated amount to record (or undefined when none was given).
 */
const assertWithinLimit = (
  events: ReadonlyArray<MandateAuditEvent>,
  grantEvent: MandateGrantEvent,
  mandateId: MandateId,
  capId: string,
  amountRaw: unknown,
  now: number,
): number | undefined => {
  if (amountRaw !== undefined && !isFiniteNonNegative(amountRaw)) {
    failMandate({ _tag: "MandateAmountInvalid", mandateId, capability: capId, received: amountRaw })
  }
  const amount = amountRaw as number | undefined
  const limit = grantEvent.limits?.[capId]
  if (limit === undefined) return amount
  if (limit.amount !== undefined && amount === undefined) {
    failMandate({ _tag: "MandateAmountRequired", mandateId, capability: capId })
  }
  const since = limit.windowMs === undefined ? Number.NEGATIVE_INFINITY : now - limit.windowMs
  let usedAmount = 0
  let usedCount = 0
  for (const e of events) {
    if (e.type !== "invoke" || e.capability !== capId) continue
    if (Date.parse(e.timestamp) < since) continue
    usedCount += 1
    usedAmount += e.amount ?? 0
  }
  const requested = amount ?? 0
  const overCount = limit.count !== undefined && usedCount + 1 > limit.count
  const overAmount = limit.amount !== undefined && usedAmount + requested > limit.amount
  if (overCount || overAmount) {
    failMandate({
      _tag: "MandateLimitExceeded",
      mandateId,
      capability: capId,
      limit,
      used: { amount: usedAmount, count: usedCount },
      requested,
    })
  }
  return amount
}

/**
 * checkGrantorNotRevoked — issue-time guard against the revoke-vs-issue race.
 *
 * Without this, a revoke recorded against the grantor mandate AFTER the
 * grantor's `MandateScope` reference was captured but BEFORE the child issue
 * fires would silently produce an orphan child mandate (parent revoked, child
 * still callable until ancestor-chain check at use time catches it). The
 * issue-time check stops the orphan from ever entering the audit log.
 */
const checkGrantorNotRevoked = (
  audit: MandateAuditService,
  grantorScope: { readonly id: MandateId; readonly grantor: GrantorId },
): void => {
  const revoked = audit.isRevoked(grantorScope.id)
  if (!revoked) return
  const events = audit.query(grantorScope.id)
  const revokeEvent = events.find((e) => e.type === "revoke")
  failMandate({
    _tag: "MandateRevoked",
    mandateId: grantorScope.id,
    revokedAt: revokeEvent?.timestamp ?? nowISO(),
    revokedBy:
      revokeEvent?.type === "revoke" ? revokeEvent.revokedBy : grantorScope.grantor,
    rationale:
      revokeEvent?.type === "revoke" ? revokeEvent.rationale : "grantor revoked",
  })
}

/**
 * assertRequestedCapsBackedByGrantorGrant — issue-time forged-scope defense (DAN-639).
 * The grantor's IN-MEMORY `capabilities` list is attacker-forgeable
 * (any-cast escape, untrusted-deserialization rehydrate) — it is the very
 * thing the per-function subset check above trusts, so that check cannot
 * defend the "dynamic capability lists from external sources" case its own
 * comment names. The only unforgeable record of what the grantor actually
 * holds is its grant event in the audit log. Every capability being delegated
 * to a child MUST appear in that recorded grant; otherwise the grantor scope
 * was forged to claim authority it never received, and the issue path would
 * launder that forgery into a real, legitimate-looking child grant event.
 *
 * Runs AFTER the in-memory subset check so an honest over-request (a cap not
 * even in the claimed scope) keeps reporting `CapabilityNotInGrantorScope`;
 * this check adds the stronger `MandateScopeForged` verdict for a cap the
 * grantor CLAIMS in memory but was never actually granted. Mirrors the
 * use-time forged-scope defense in useCapability and the audit-log fixes (DAN-637/638):
 * audit-log-is-truth must hold at EVERY security decision — here, issuance.
 */
const assertRequestedCapsBackedByGrantorGrant = (
  audit: MandateAuditService,
  grantorMandateId: MandateId,
  requestedCapIds: ReadonlyArray<string>,
): void => {
  const grantEvent = audit.query(grantorMandateId).find((e) => e.type === "grant") as
    | MandateGrantEvent
    | undefined
  if (!grantEvent) {
    // No grant event → the grantor scope itself was never issued (a wholly
    // fabricated grantor). Nothing can be derived from authority that does not
    // exist in the log.
    failMandate({ _tag: "MandateNotIssued", mandateId: grantorMandateId })
    return
  }
  const grantedCapIds = new Set(grantEvent.capabilities)
  for (const capId of requestedCapIds) {
    if (!grantedCapIds.has(capId)) {
      failMandate({
        _tag: "MandateScopeForged",
        mandateId: grantorMandateId,
        capability: capId,
      })
    }
  }
}


/**
 * walkChain — the one revocation walk, shared by `useCapability` and
 * `resume` (DAN-1320) so the two can never disagree. From `mandateId` up
 * through each grant event's `parentMandateId`, refusing on the first revoked
 * node (`MandateRevoked` for the leaf, `AncestorMandateRevoked` above it) and
 * on a non-leaf whose grant is missing from the log (`DelegationChainBroken`,
 * fail closed). Returns the grant events leaf-first; empty when the leaf
 * itself has no grant, which the caller reports as `MandateNotIssued`.
 * `fallbackGrantor` fills `revokedBy` only when a revoke event is somehow
 * absent for a mandate the store says is revoked.
 */
const walkChain = (
  audit: MandateAuditService,
  mandateId: MandateId,
  fallbackGrantor: GrantorId,
): { readonly chain: ReadonlyArray<MandateGrantEvent>; readonly cyclic: boolean } => {
  const chain: MandateGrantEvent[] = []
  const seen = new Set<MandateId>()
  let cursorId: MandateId | null = mandateId
  while (cursorId !== null && !seen.has(cursorId)) {
    seen.add(cursorId)
    if (audit.isRevoked(cursorId)) {
      const events = audit.query(cursorId)
      const revokeEvent = events.find((e) => e.type === "revoke")
      if (cursorId === mandateId) {
        failMandate({
          _tag: "MandateRevoked",
          mandateId,
          revokedAt: (revokeEvent?.timestamp ?? nowISO()),
          revokedBy:
            revokeEvent?.type === "revoke" ? revokeEvent.revokedBy : fallbackGrantor,
          rationale:
            revokeEvent?.type === "revoke" ? revokeEvent.rationale : "unknown",
        })
      }
      failMandate({
        _tag: "AncestorMandateRevoked",
        mandateId,
        revokedAncestorId: cursorId,
        revokedAt: revokeEvent?.timestamp ?? nowISO(),
      })
    }
    const grantEvent = audit.query(cursorId).find((e) => e.type === "grant") as
      | MandateGrantEvent
      | undefined
    if (!grantEvent) {
      // A NON-leaf cursor with no grant event means the chain references a
      // parent whose grant is ABSENT from the log (tampering / truncation /
      // corruption). We can no longer certify that this ancestor — or anything
      // above it — is unrevoked, so a revoked grandparent above the break would
      // be silently missed. Fail CLOSED with an integrity error rather than
      // fail OPEN (DAN-640: the DAN-637 walk stopped here, hiding the ancestor).
      if (cursorId !== mandateId) {
        failMandate({
          _tag: "DelegationChainBroken",
          mandateId,
          brokenAncestorId: cursorId,
        })
      }
      // The LEAF with no grant event is the legitimate forged-fake-id case:
      // stop here and let the forged-scope defense below report the precise
      // MandateNotIssued. (An unissued leaf, not a broken chain.)
      break
    }
    chain.push(grantEvent)
    cursorId = grantEvent.parentMandateId
  }
  // A non-null cursor here means `seen` stopped the walk: the log holds a
  // cycle. Use tolerates it (every reachable node was checked for revocation);
  // resume must not mint a scope from a chain that has no root.
  return { chain, cyclic: cursorId !== null }
}

/**
 * useCapability — invoke a capability under a mandate.
 *
 * The type system enforces this at the call site via the
 * `Cap extends Caps[number]` constraint — passing a capability not in the
 * mandate's scope is a TYPE ERROR at the call site, not a runtime error.
 * At runtime, this helper also checks that the mandate is not revoked AND
 * records the invocation; runtime gates handle the any-cast escape hatch.
 *
 * Generic-parameter ordering note: `Caps` is declared FIRST so the inference
 * pass settles `Caps` from `mandate.capabilities` before `Cap` is constrained
 * against `Caps[number]`. Reversing the order breaks subset enforcement.
 */
export const useCapability = <
  Caps extends ReadonlyArray<Capability>,
  Cap extends Caps[number],
  Tier extends MandateTier = "organization",
  ParentScope extends MandateScope<any, any, any> | null = null,
>(args: {
  readonly mandate: MandateScope<Caps, Tier, ParentScope>
  readonly capability: Cap
  readonly triggerSource?: TriggerSource
  /** What this use spends, in the grant's `unit`. Required when the grant caps the capability by amount (DAN-1319). */
  readonly amount?: number
}, audit: MandateAuditService): void => {
  // Every caller-supplied field is read exactly once, here, and only these
  // locals are used below (the 2026-10-13 mandate audit; the note above
  // `ISSUED` has the shape of the hole). `mandate` is the one object the
  // walk, the log checks, the possession check and the record all name.
  const { mandate, capability } = args
  const triggerSource: TriggerSource = args.triggerSource ?? "code"
  const amountRaw: unknown = args.amount
  const mandateId: MandateId = mandate.id

  // A mandate is invocable iff the leaf AND every
  // ancestor in the delegation chain is unrevoked. Revoking the org-tier
  // mandate must structurally disable every descendant; otherwise the
  // org-tier "kill switch" is silently inert (the substrate's load-bearing
  // termination-protocol claim).
  //
  // The chain is reconstructed from the AUDIT LOG via each grant event's
  // parentMandateId — NOT from the in-memory `parentScope` pointer — exactly
  // as revokeMandate does below. The pointer is not load-bearing for this
  // decision: the v0.0 `issueMandate` (removed 2026-10-13) recorded the real
  // parentMandateId while setting parentScope: null, deserialized mandates
  // (JSONL, cross-process handoff) lose the object graph entirely, and a
  // forged {...realScope, parentScope: null} severs the pointer on purpose.
  // All three defeat a pointer walk; none
  // defeats the audit log, which is the only unforgeable record of who granted
  // what. (LESSONS 2026-07-22: audit-log-is-truth must hold at EVERY security
  // decision, not just most.)
  // `seen` guards against a cyclic or self-referential parentMandateId in the
  // audit log. A legitimate chain is always a DAG (fresh crypto-random IDs;
  // parents are issued strictly before children), so a cycle only arises from a
  // corrupted/attacker-tampered log — but because DAN-637 made this walk the
  // load-bearing revocation decision, an unguarded walk on such a log is an
  // unkillable synchronous hang. Revisiting a node is safe to stop on: every
  // reachable ancestor has already had isRevoked checked at the top of its
  // iteration before we could return to it, so revocation is still fully
  // enforced across the reachable set. (Battle-test follow-up 2026-07-22.)
  void walkChain(audit, mandateId, mandate.grantor)

  // Defense-in-depth against forged-scope literals: verify a grant event
  // exists in the audit log AND that the mandate's claimed capabilities
  // are a subset of what was actually granted. Without this, a caller
  // (or deserialized payload) holding `{ _tag: "MandateScope", id: "FAKE",
  // capabilities: [...] }` would pass the capability-membership check
  // trivially because the forged scope's own capability list was the only
  // thing being checked.
  const events = audit.query(mandateId)
  const grantEvent = events.find((e) => e.type === "grant") as
    | MandateGrantEvent
    | undefined
  if (!grantEvent) {
    failMandate({
      _tag: "MandateNotIssued",
      mandateId,
    })
    return
  }
  const grantedCapIds = new Set(grantEvent.capabilities)
  const claimedCapIds = mandate.capabilities.map((c) => capabilityKey(c))
  for (const claimed of claimedCapIds) {
    if (!grantedCapIds.has(claimed)) {
      failMandate({
        _tag: "MandateScopeForged",
        mandateId,
        capability: claimed,
      })
    }
  }

  const capId = capabilityKey(capability)

  // DAN-1157 (F1): everything above reads the log through `mandateId`,
  // which the caller chooses. That defeats a FAKE id and misses a REAL id that
  // is not the caller's. A copy of someone else's scope, or of every public
  // field in their grant event, names a real mandate and passes each check
  // above. The object itself is what the caller cannot mint.
  assertIssued(mandate, mandateId, capId)
  // The store this scope was minted against is the only store its invocation
  // may be judged by (2026-10-31; the binding note above `BOUND`).
  assertBoundTo(audit, mandate, mandateId)

  // Compile-time check: this function's signature requires the mandate to
  // include the capability. The runtime check is for any-cast escape hatches.
  const mandateCapIds = new Set(claimedCapIds)
  if (!mandateCapIds.has(capId)) {
    failMandate({
      _tag: "CapabilityNotInGrantorScope",
      capability: capId,
    })
  }

  // The limit, if the grant set one, judged against the same `events`
  // snapshot the forged-scope check read: the log is the counter (DAN-1319).
  const timestamp = nowISO()
  const amount = assertWithinLimit(events, grantEvent, mandateId, capId, amountRaw, Date.parse(timestamp))

  audit.record(Object.freeze({
    type: "invoke",
    mandateId,
    capability: capId,
    timestamp,
    triggerSource,
    ...(amount === undefined ? {} : { amount }),
  }))
}

/**
 * revokeMandate — remove a mandate from the active pool.
 *
 * The revoker must be in the delegation chain. Since the authority
 * binding fix (DAN-1157, F2) that means PROVEN by possession, not claimed by name. The caller presents
 * `revokerScope`, a scope this module issued, and it must BE the target or one
 * of the target's ancestors (the chain is walked from the audit log via
 * parentMandateId). The old `revoker: GrantorId` is gone rather than
 * validated. It was a string printed in the grant event any audit reader can
 * see, so the least-privileged agent could name the org's grantor and revoke
 * the whole tree, permanently. The recorded `revokedBy` is the grantor of the
 * presented scope, which after `isIssued` is frozen fact.
 *
 * A revoked holder can still revoke inside its own subtree. This grants
 * nothing: if the revoker's mandate is revoked, so is everything below it via
 * the ancestor cascade, and the call only makes that explicit in the log. It
 * also keeps double-revoke idempotent. Once revoked, useCapability throws
 * MandateRevoked.
 */
export const revokeMandate = (args: {
  readonly mandateId: MandateId
  readonly revokerScope: MandateScope<any, any, any>
  readonly rationale: string
  readonly triggerSource?: TriggerSource
}, audit: MandateAuditService): void => {
  // Every caller-supplied field is read exactly once (the 2026-10-13 mandate
  // audit). `mandateId` is the one id the chain walk, the authorization and
  // the revoke record all name.
  const { mandateId, revokerScope, rationale } = args
  const triggerSource: TriggerSource = args.triggerSource ?? "code"

  // rationale pre-check
  const rationaleCheck = constitutionalPreCheck(rationale)
  if (rationaleCheck) {
    failMandate({
      _tag: "MaliciousMandateMetadata",
      inputKind: "rationale",
      matchedPatternId: rationaleCheck.patternId,
      evidence: rationaleCheck.evidence,
    })
  }

  const events = audit.query(mandateId)

  // Walk the delegation chain: collect every mandate ID from this mandate up
  // to the root via parentMandateId. `seen` guards against a cyclic /
  // self-referential parentMandateId in a corrupted log (same hazard and
  // rationale as the useCapability walk above — a legitimate chain is a DAG,
  // but an unguarded walk on a tampered log hangs synchronously). A node with
  // no grant event ends the walk and is not collected; it is not a mandate.
  const mandatesInChain = new Set<MandateId>()
  const seen = new Set<MandateId>()
  let currentMandateId: MandateId | null = mandateId
  while (currentMandateId !== null && !seen.has(currentMandateId)) {
    seen.add(currentMandateId)
    const grantEvent = audit.query(currentMandateId).find((e) => e.type === "grant") as
      | MandateGrantEvent
      | undefined
    if (!grantEvent) break
    mandatesInChain.add(currentMandateId)
    currentMandateId = grantEvent.parentMandateId
  }

  // Possession, then position. An unissued scope (a copy, a literal, a
  // rehydrated payload) proves nothing however well it names an ancestor.
  const presented: unknown = revokerScope
  if (!isIssued(presented) || !mandatesInChain.has(presented.id)) {
    // `revoker` in the error is the grantor the presented scope CLAIMS. It is
    // verified only when the scope was issued. Nothing is written to the log
    // for a refused revocation, so an unverified claim never reaches evidence.
    const claimed = (presented as { readonly grantor?: unknown } | null | undefined)?.grantor
    failMandate({
      _tag: "RevokerNotInDelegationChain",
      mandateId,
      revoker: (typeof claimed === "string" ? claimed : "unknown") as GrantorId,
    })
  }
  const revoker = (presented as MandateScope<any, any, any>).grantor
  // Names the PRESENTED scope, as the issuers do for a foreign grantor: the
  // mismatch is between that scope and this store, not about the target.
  assertBoundTo(audit, presented as object, (presented as MandateScope<any, any, any>).id)

  // Idempotent: if already revoked, do not double-record.
  const alreadyRevoked = events.some((e) => e.type === "revoke")
  if (alreadyRevoked) {
    return
  }

  audit.record(Object.freeze({
    type: "revoke",
    mandateId,
    revokedBy: revoker,
    rationale,
    timestamp: nowISO(),
    triggerSource,
  }))
}

// ============================================================================
// Multi-tier issue functions
// ============================================================================
//
// Three named entry points encode the tier-transition discipline at the API
// surface. Agent-tier mandates are LEAVES — there is no function whose
// `grantorScope` parameter accepts an agent-tier scope; the type system
// structurally refuses upward or peer-tier delegation from agent-tier.
//
// The type system is only half of that claim: an `as any` or a JavaScript
// caller walks through it. `assertGrantorTier` is the runtime half, and it
// reads `tier` only from an issued (frozen) grantor (DAN-1157, F3).
//
// Each function preserves the invariants:
//   - constitutional pre-check on rationale strings BEFORE persistence
//   - Audit recording with triggerSource discriminator
//   - Branded ULID-shaped MandateId
//   - Immutable scope; re-grant via new function call
//
// And adds:
//   - Per-tier subset gate at compile time via Cap extends ParentCaps[number]
//   - Typed parent-scope chain via the ParentScope generic parameter

/**
 * issueOrgMandate — bootstrap an organization-tier mandate (the root tier).
 * The grantor is the human-in-the-loop or any root
 * authority; there is no parent scope (this IS the root).
 */
export const issueOrgMandate = <Caps extends ReadonlyArray<Capability>>(args: {
  readonly grantor: GrantorId
  readonly capabilities: Caps
  readonly rationale: string
  readonly triggerSource?: TriggerSource
  /** Per-capability caps, keyed by capability key (DAN-1319). */
  readonly limits?: CapabilityLimits
}, audit: MandateAuditService): MandateScope<Caps, "organization", null> => {
  // Every caller-supplied field is read exactly once (the 2026-10-13 mandate audit).
  const { grantor, rationale } = args
  const capabilities = captureCapabilities(args.capabilities)
  const capabilityIds = resolveCapabilityIds(capabilities)
  const limits = captureLimits(args.limits, capabilityIds)
  capabilityIds.forEach(assertCapabilityIdentifierClean)
  const triggerSource: TriggerSource = args.triggerSource ?? "code"

  const rationaleCheck = constitutionalPreCheck(rationale)
  if (rationaleCheck) {
    failMandate({
      _tag: "MaliciousMandateMetadata",
      inputKind: "rationale",
      matchedPatternId: rationaleCheck.patternId,
      evidence: rationaleCheck.evidence,
    })
  }

  const newId = freshMandateId(audit)
  const grantTimestamp = nowISO()

  const scope = mint<MandateScope<Caps, "organization", null>>({
    _tag: "MandateScope",
    tier: "organization",
    id: newId,
    capabilities,
    limits,
    grantor,
    grantTimestamp,
    grantRationale: rationale,
    parentMandateId: null,
    parentScope: null,
  })

  bindTo(audit, scope)

  audit.record(Object.freeze({
    type: "grant",
    mandateId: newId,
    grantor,
    capabilities: capabilityIds,
    rationale,
    parentMandateId: null,
    timestamp: grantTimestamp,
    triggerSource,
    ...(Object.keys(limits).length === 0 ? {} : { limits }),
  }))

  return scope
}

/**
 * issueProjectMandate — derive a project-tier mandate from an
 * organization-tier grantor scope. The compile-time constraint
 * `ProjectCaps extends ReadonlyArray<OrgCaps[number]>` enforces that every
 * project-tier capability is a member of the parent org-tier capability
 * tuple. Granting a capability the org does not hold is a TYPE ERROR at
 * the call site.
 */
export const issueProjectMandate = <
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
}, audit: MandateAuditService): MandateScope<
  ProjectCaps,
  "project",
  MandateScope<OrgCaps, "organization", null>
> => {
  // Every caller-supplied field is read exactly once (the 2026-10-13 mandate audit).
  const { grantor, grantorScope, rationale } = args
  const capabilities = captureCapabilities(args.capabilities)
  const capabilityIds = resolveCapabilityIds(capabilities)
  const limits = captureLimits(args.limits, capabilityIds)
  capabilityIds.forEach(assertCapabilityIdentifierClean)
  const triggerSource: TriggerSource = args.triggerSource ?? "code"

  const rationaleCheck = constitutionalPreCheck(rationale)
  if (rationaleCheck) {
    failMandate({
      _tag: "MaliciousMandateMetadata",
      inputKind: "rationale",
      matchedPatternId: rationaleCheck.patternId,
      evidence: rationaleCheck.evidence,
    })
  }

  // Issue-time grantor-revoked check (closes the revoke-vs-issue race).
  checkGrantorNotRevoked(audit, grantorScope)

  // Runtime fallback subset check (belt-and-suspenders for any-cast escapes)
  const grantorCapIds = new Set(
    grantorScope.capabilities.map((c) => capabilityKey(c)),
  )
  for (const capId of capabilityIds) {
    if (!grantorCapIds.has(capId)) {
      failMandate({
        _tag: "CapabilityNotInGrantorScope",
        capability: capId,
      })
    }
  }

  // DAN-639: the check above trusts the forgeable in-memory grantorScope
  // capabilities; re-check every requested capability against the grantor's
  // RECORDED grant event so a forged scope cannot mint a capability the
  // grantor was never actually granted (audit-log-is-truth at issue time).
  assertRequestedCapsBackedByGrantorGrant(audit, grantorScope.id, capabilityIds)
  assertLimitsWithinGrantor(audit, grantorScope.id, capabilityIds, limits)

  // DAN-1157: an issued grantor, and the runtime half of the tier ladder.
  assertIssued(grantorScope, grantorScope.id, capabilityIds[0] ?? "")
  assertBoundTo(audit, grantorScope, grantorScope.id)
  assertGrantorTier(grantorScope, "organization", "project")

  const newId = freshMandateId(audit)
  const grantTimestamp = nowISO()

  const scope = mint<MandateScope<
    ProjectCaps,
    "project",
    MandateScope<OrgCaps, "organization", null>
  >>({
    _tag: "MandateScope",
    tier: "project",
    id: newId,
    capabilities,
    limits,
    grantor,
    grantTimestamp,
    grantRationale: rationale,
    parentMandateId: grantorScope.id,
    parentScope: detach(grantorScope),
  })

  bindTo(audit, scope)

  audit.record(Object.freeze({
    type: "grant",
    mandateId: newId,
    grantor,
    capabilities: capabilityIds,
    rationale,
    parentMandateId: grantorScope.id,
    timestamp: grantTimestamp,
    triggerSource,
    ...(Object.keys(limits).length === 0 ? {} : { limits }),
  }))

  return scope
}

/**
 * issueAgentMandate — derive an agent-tier mandate from a project-tier
 * grantor scope. The compile-time constraint
 * `AgentCaps extends ReadonlyArray<ProjectCaps[number]>` enforces project-
 * tier subset; the function signature requires a project-tier grantorScope
 * (NOT agent-tier), structurally refusing upward delegation from agent.
 */
export const issueAgentMandate = <
  OrgCaps extends ReadonlyArray<Capability>,
  ProjectCaps extends ReadonlyArray<OrgCaps[number]>,
  AgentCaps extends ReadonlyArray<ProjectCaps[number]>,
>(args: {
  readonly grantor: GrantorId
  readonly grantorScope: MandateScope<
    ProjectCaps,
    "project",
    MandateScope<OrgCaps, "organization", null>
  >
  readonly capabilities: AgentCaps
  readonly rationale: string
  readonly triggerSource?: TriggerSource
  /** Per-capability caps; at least as tight as the grantor's on every capped capability carried (DAN-1319). */
  readonly limits?: CapabilityLimits
}, audit: MandateAuditService): MandateScope<
  AgentCaps,
  "agent",
  MandateScope<ProjectCaps, "project", MandateScope<OrgCaps, "organization", null>>
> => {
  // Every caller-supplied field is read exactly once (the 2026-10-13 mandate audit).
  const { grantor, grantorScope, rationale } = args
  const capabilities = captureCapabilities(args.capabilities)
  const capabilityIds = resolveCapabilityIds(capabilities)
  const limits = captureLimits(args.limits, capabilityIds)
  capabilityIds.forEach(assertCapabilityIdentifierClean)
  const triggerSource: TriggerSource = args.triggerSource ?? "code"

  const rationaleCheck = constitutionalPreCheck(rationale)
  if (rationaleCheck) {
    failMandate({
      _tag: "MaliciousMandateMetadata",
      inputKind: "rationale",
      matchedPatternId: rationaleCheck.patternId,
      evidence: rationaleCheck.evidence,
    })
  }

  // Issue-time grantor-revoked check (closes the revoke-vs-issue race).
  checkGrantorNotRevoked(audit, grantorScope)

  // Runtime fallback subset check (belt-and-suspenders for any-cast escapes)
  const grantorCapIds = new Set(
    grantorScope.capabilities.map((c) => capabilityKey(c)),
  )
  for (const capId of capabilityIds) {
    if (!grantorCapIds.has(capId)) {
      failMandate({
        _tag: "CapabilityNotInGrantorScope",
        capability: capId,
      })
    }
  }

  // DAN-639: the check above trusts the forgeable in-memory grantorScope
  // capabilities; re-check every requested capability against the grantor's
  // RECORDED grant event so a forged scope cannot mint a capability the
  // grantor was never actually granted (audit-log-is-truth at issue time).
  assertRequestedCapsBackedByGrantorGrant(audit, grantorScope.id, capabilityIds)
  assertLimitsWithinGrantor(audit, grantorScope.id, capabilityIds, limits)

  // DAN-1157: an issued grantor, and the runtime half of the tier ladder. This
  // is what makes agents leaves for a JavaScript caller too: an agent-tier
  // grantor (agent → agent) and an org-tier one (org → agent) both stop here.
  assertIssued(grantorScope, grantorScope.id, capabilityIds[0] ?? "")
  assertBoundTo(audit, grantorScope, grantorScope.id)
  assertGrantorTier(grantorScope, "project", "agent")

  const newId = freshMandateId(audit)
  const grantTimestamp = nowISO()

  const scope = mint<MandateScope<
    AgentCaps,
    "agent",
    MandateScope<ProjectCaps, "project", MandateScope<OrgCaps, "organization", null>>
  >>({
    _tag: "MandateScope",
    tier: "agent",
    id: newId,
    capabilities,
    limits,
    grantor,
    grantTimestamp,
    grantRationale: rationale,
    parentMandateId: grantorScope.id,
    parentScope: detach(grantorScope),
  })

  bindTo(audit, scope)

  audit.record(Object.freeze({
    type: "grant",
    mandateId: newId,
    grantor,
    capabilities: capabilityIds,
    rationale,
    parentMandateId: grantorScope.id,
    timestamp: grantTimestamp,
    triggerSource,
    ...(Object.keys(limits).length === 0 ? {} : { limits }),
  }))

  return scope
}

/**
 * resumeMandate — pick an issued mandate back up from the log (DAN-1320).
 *
 * Until now a restart re-minted: a fresh id, a fresh grant line and, with
 * limits counted per id, a fresh budget. Resume returns a genuine scope for
 * the mandate the log already holds, if and only if the same walk
 * `useCapability` runs says it is live. The caller declares the capability
 * set it expects (so the returned scope is typed) and may declare the tier;
 * both are checked against the record and refused on mismatch. Tier is not
 * recorded on the grant event; it is the depth of the chain.
 *
 * Who may call this: whoever holds the client, and so the store, which ADR
 * 0004 names as the root credential of the domain. Say the consequence
 * plainly: a client holder can resume ANY mandate in the log, so it can act
 * as any holder and revoke any subtree, which a fresh org mandate of its own
 * could not do inside an existing tree. Before resume the client was root
 * over new trees; now it is root over this one too. Hand an agent its scope,
 * never the client (SECURITY.md). A `resume` event naming `resumedBy` is
 * recorded. Resuming twice yields two genuine objects over one recorded
 * authority; possession is per object, the log is the truth.
 */
export const resumeMandate = <
  Caps extends ReadonlyArray<Capability>,
  Tier extends MandateTier = MandateTier,
>(args: {
  readonly mandateId: MandateId
  readonly capabilities: Caps
  /** Who is picking the mandate up; recorded on the resume event. */
  readonly resumedBy: GrantorId
  readonly tier?: Tier
  readonly triggerSource?: TriggerSource
}, audit: MandateAuditService): ResumedScope<Caps, Tier> => {
  // Every caller-supplied field is read exactly once (the intake rule).
  const { mandateId, resumedBy } = args
  const capabilities = captureCapabilities(args.capabilities)
  const declaredIds = resolveCapabilityIds(capabilities)
  const declaredTier: unknown = args.tier
  const triggerSource: TriggerSource = args.triggerSource ?? "code"

  // The leaf's grant first, so the walk's fallback `revokedBy` is the real
  // grantor, as it is on the use path (blind review 2026-11-01, finding 4).
  const leafGrant = audit.query(mandateId).find((e) => e.type === "grant") as MandateGrantEvent | undefined
  if (leafGrant === undefined) {
    return failMandate({ _tag: "MandateNotIssued", mandateId })
  }
  const { chain, cyclic } = walkChain(audit, mandateId, leafGrant.grantor)
  const leaf = chain[0]
  if (leaf === undefined) {
    return failMandate({ _tag: "MandateNotIssued", mandateId })
  }
  if (cyclic) {
    failMandate({ _tag: "DelegationChainBroken", mandateId, brokenAncestorId: chain[chain.length - 1]!.mandateId })
  }

  // A grant line is a claim until the issuers' checks are re-run on it. The
  // issuers checked subset and tightness once, at issue, and the scope object
  // carried the result; a line appended to an unsigned log skipped them. So
  // every link of the rebuilt chain is checked again here, child against
  // parent, before anything is minted (blind review 2026-11-01, finding 2).
  for (let k = 0; k + 1 < chain.length; k++) {
    const child = chain[k]!
    const parent = chain[k + 1]!
    const parentCaps = new Set(parent.capabilities)
    for (const capId of child.capabilities) {
      if (!parentCaps.has(capId)) {
        failMandate({ _tag: "MandateScopeForged", mandateId: child.mandateId, capability: capId })
      }
    }
    assertLimitsTighterThan(parent.mandateId, parent.limits, child.capabilities, child.limits ?? EMPTY_LIMITS)
  }

  const recorded = Object.freeze([...leaf.capabilities].sort())
  const declared = Object.freeze([...declaredIds].sort())
  if (recorded.length !== declared.length || recorded.some((k, i) => k !== declared[i])) {
    failMandate({ _tag: "ResumeMismatch", mandateId, field: "capabilities", declared, recorded })
  }

  const TIERS: ReadonlyArray<MandateTier> = ["organization", "project", "agent"]
  if (chain.length > TIERS.length) {
    // Deeper than the ladder allows: no issuer can have written this, so the
    // log is not a record this module can stand on.
    failMandate({ _tag: "DelegationChainBroken", mandateId, brokenAncestorId: chain[TIERS.length]!.mandateId })
  }
  const tierAt = (depthFromLeaf: number): MandateTier => TIERS[chain.length - 1 - depthFromLeaf]!
  const tier = tierAt(0)
  if (declaredTier !== undefined && declaredTier !== tier) {
    failMandate({ _tag: "ResumeMismatch", mandateId, field: "tier", declared: [String(declaredTier)], recorded: [tier] })
  }

  // Detached, frozen copies of the ancestors, root first, carrying no
  // authority of their own (they are not minted; `detach` on an issuer does
  // the same). The capability objects are rebuilt from the recorded keys.
  let parent: MandateScope<any, any, any> | null = null
  for (let k = chain.length - 1; k >= 1; k--) {
    const g = chain[k]!
    parent = Object.freeze({
      _tag: "MandateScope",
      tier: tierAt(k),
      id: g.mandateId,
      capabilities: Object.freeze(g.capabilities.map((key) => Object.freeze({ key }))),
      limits: freezeLimits(g.limits),
      grantor: g.grantor,
      grantTimestamp: g.timestamp,
      grantRationale: g.rationale,
      parentMandateId: g.parentMandateId,
      parentScope: parent,
    }) as MandateScope<any, any, any>
  }

  const scope = mint<MandateScope<Caps, MandateTier, MandateScope<any, any, any> | null>>({
    _tag: "MandateScope",
    tier,
    id: mandateId,
    capabilities,
    limits: freezeLimits(leaf.limits),
    grantor: leaf.grantor,
    grantTimestamp: leaf.timestamp,
    grantRationale: leaf.rationale,
    parentMandateId: leaf.parentMandateId,
    parentScope: parent,
  })

  bindTo(audit, scope)

  audit.record(Object.freeze({
    type: "resume",
    mandateId,
    resumedBy,
    timestamp: nowISO(),
    triggerSource,
  }))

  return scope as unknown as ResumedScope<Caps, Tier>
}
