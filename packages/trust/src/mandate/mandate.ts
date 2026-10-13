/**
 * @sweetrust/mandate — issuance, invocation, revocation flows
 *
 * Per the mandate capability-declaration specification v0.0.
 *
 * Inheritance: per spec I9, this module imports the constitutional pre-check
 * primitive from ./security.ts (formerly a standalone package, folded back into mandate 2026-07-19). Mandate metadata (rationale strings) is exactly the attack
 * surface the pre-check exists to defend.
 */
import { randomBytes } from "node:crypto"
import { constitutionalPreCheck } from "./security.ts"
import { MandateFailure } from "./errors.ts"
import type {
  Capability,
  GrantorId,
  ISO8601,
  MandateAuditService,
  MandateError,
  MandateGrantEvent,
  MandateId,
  MandateScope,
  MandateTier,
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
 * Replaces the former `Context.Tag(...)` capability declaration (which
 * required Effect). A capability is just an identity with a name.
 */
export const defineCapability = <const Id extends string>(key: Id): Capability<Id> => ({ key })

/**
 * Extract the canonical string key for a `Capability`.
 *
 * A capability carries a stable `key`. This helper centralizes the lookup
 * (and tolerates any-cast escape hatches where a bare string sneaks in),
 * mirroring the branded-object-or-string fallback that previously appeared
 * across mandate.ts and the linear.ts adapter.
 */
export const capabilityKey = (cap: Capability): string => {
  const branded = cap as unknown as { key?: string }
  return branded.key ?? String(cap)
}

/**
 * Generate a sortable identifier with crypto-strong randomness.
 *
 * Format: MAN_<base36-ms-timestamp>_<10-hex-chars-from-crypto.randomBytes>.
 * The timestamp prefix preserves ULID-like ordering for forensic readability;
 * the randomness suffix uses node:crypto so an attacker cannot predict the
 * next mandate ID and pre-compute hash-chain or audit-log forgeries.
 */
const generateMandateId = (): MandateId => {
  const ts = Date.now().toString(36).padStart(10, "0")
  const rand = randomBytes(8).toString("hex").slice(0, 10)
  return (`MAN_${ts}_${rand}`.toUpperCase()) as MandateId
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
// and cannot invoke. Cross-process authority belongs to the Move kernel; the
// named upgrade path, if a TS consumer ever needs it, is a per-mandate secret
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
 * issueMandate — grant a child agent a subset of the grantor's capabilities.
 *
 * Per spec I4 + I5: the type system enforces that every requested capability
 * is a member of the grantor's scope. RequestedCaps extends ReadonlyArray<GrantorCaps[number]>
 * structurally proves the subset relationship at compile time.
 *
 * Per spec I9: rationale strings pass through constitutionalPreCheck before
 * any persistence. Malicious metadata throws immediately with no audit
 * pollution.
 *
 * @deprecated Use the tiered API: `issueOrgMandate` → `issueProjectMandate` →
 * `issueAgentMandate`. This v0.0 entry point stamps tier `"organization"` on
 * every scope it mints, so an organization's child claims to be an
 * organization; the tiered functions record the tier the ladder actually
 * grants. Kept only for v0.0 callers, and it may be removed before the first
 * stable release (DAN-1159 item 4d).
 */
export const issueMandate = <
  GrantorCaps extends ReadonlyArray<Capability>,
  RequestedCaps extends ReadonlyArray<GrantorCaps[number]>,
>(args: {
  readonly grantor: GrantorId
  readonly grantorScope: MandateScope<GrantorCaps>
  readonly capabilities: RequestedCaps
  readonly rationale: string
  readonly triggerSource?: TriggerSource
}, audit: MandateAuditService): MandateScope<RequestedCaps> => {
  // Every caller-supplied field is read exactly once (the 2026-10-13 mandate audit).
  const { grantor, grantorScope, rationale } = args
  const capabilities = captureCapabilities(args.capabilities)
  const capabilityIds = resolveCapabilityIds(capabilities)
  const triggerSource: TriggerSource = args.triggerSource ?? "code"

  // I9: pre-check rationale before persistence
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

  // Type-level subset check is the load-bearing guarantee. The compiler
  // refuses to satisfy `RequestedCaps extends ReadonlyArray<GrantorCaps[number]>`
  // when a requested capability is not in the grantor's scope. This runtime
  // check is a belt-and-suspenders for cases where types are erased
  // (any-cast escape hatches; dynamic capability lists from external sources).
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

  // DAN-1157: the grantor must be a scope this module issued (not a copy that
  // names a real id), and it must be organization-tier. This function stamps
  // "organization" on what it mints, so a project or agent grantor here would
  // ascend the ladder in one call.
  assertIssued(grantorScope, grantorScope.id, capabilityIds[0] ?? "")
  assertGrantorTier(grantorScope, "organization", "organization")

  const newId = generateMandateId()
  const grantTimestamp = nowISO()

  const newScope = mint<MandateScope<RequestedCaps>>({
    _tag: "MandateScope",
    tier: "organization",
    id: newId,
    capabilities,
    grantor,
    grantTimestamp,
    grantRationale: rationale,
    parentMandateId: grantorScope.id,
    parentScope: null,
  })

  audit.record({
    type: "grant",
    mandateId: newId,
    grantor,
    capabilities: capabilityIds,
    rationale,
    parentMandateId: grantorScope.id,
    timestamp: grantTimestamp,
    triggerSource,
  })

  return newScope
}

/**
 * issueRootMandate — bootstrap the root of the delegation DAG. Used once per
 * agent system to create the seed mandate from which all others derive.
 *
 * The grantor here is the human-in-the-loop (Arthur) — there is no parent
 * mandate, so parentMandateId is null. Subsequent issuances chain via
 * issueMandate.
 *
 * @deprecated Use `issueOrgMandate`, the root of the tiered API, and derive
 * from it with `issueProjectMandate` and `issueAgentMandate`. Kept only for
 * v0.0 callers, and it may be removed before the first stable release
 * (DAN-1159 item 4d).
 */
export const issueRootMandate = <Caps extends ReadonlyArray<Capability>>(args: {
  readonly grantor: GrantorId
  readonly capabilities: Caps
  readonly rationale: string
  readonly triggerSource?: TriggerSource
}, audit: MandateAuditService): MandateScope<Caps> => {
  // Every caller-supplied field is read exactly once (the 2026-10-13 mandate audit).
  const { grantor, rationale } = args
  const capabilities = captureCapabilities(args.capabilities)
  const capabilityIds = resolveCapabilityIds(capabilities)
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

  const newId = generateMandateId()
  const grantTimestamp = nowISO()

  const scope = mint<MandateScope<Caps>>({
    _tag: "MandateScope",
    tier: "organization",
    id: newId,
    capabilities,
    grantor,
    grantTimestamp,
    grantRationale: rationale,
    parentMandateId: null,
    parentScope: null,
  })

  audit.record({
    type: "grant",
    mandateId: newId,
    grantor,
    capabilities: capabilityIds,
    rationale,
    parentMandateId: null,
    timestamp: grantTimestamp,
    triggerSource,
  })

  return scope
}

/**
 * useCapability — invoke a capability under a mandate.
 *
 * Per spec I6: the type system enforces this at the call site via the
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
}, audit: MandateAuditService): void => {
  // Every caller-supplied field is read exactly once, here, and only these
  // locals are used below (the 2026-10-13 mandate audit; the note above
  // `ISSUED` has the shape of the hole). `mandate` is the one object the
  // walk, the log checks, the possession check and the record all name.
  const { mandate, capability } = args
  const triggerSource: TriggerSource = args.triggerSource ?? "code"
  const mandateId: MandateId = mandate.id

  // Per I8 + multi-tier-spec I4: a mandate is invocable iff the leaf AND every
  // ancestor in the delegation chain is unrevoked. Revoking the org-tier
  // mandate must structurally disable every descendant; otherwise the
  // org-tier "kill switch" is silently inert (the substrate's load-bearing
  // termination-protocol claim).
  //
  // The chain is reconstructed from the AUDIT LOG via each grant event's
  // parentMandateId — NOT from the in-memory `parentScope` pointer — exactly
  // as revokeMandate does below. The pointer is not load-bearing for this
  // decision: issueMandate records the real parentMandateId while setting
  // parentScope: null, deserialized mandates (JSONL, cross-process handoff)
  // lose the object graph entirely, and a forged {...realScope, parentScope:
  // null} severs the pointer on purpose. All three defeat a pointer walk; none
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
            revokeEvent?.type === "revoke" ? revokeEvent.revokedBy : mandate.grantor,
          rationale:
            revokeEvent?.type === "revoke" ? revokeEvent.rationale : "unknown",
        })
      }
      failMandate({
        _tag: "AncestorMandateRevoked",
        mandateId: mandateId,
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
    cursorId = grantEvent.parentMandateId
  }

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
        mandateId: mandateId,
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

  // Compile-time check: this function's signature requires the mandate to
  // include the capability. The runtime check is for any-cast escape hatches.
  const mandateCapIds = new Set(claimedCapIds)
  if (!mandateCapIds.has(capId)) {
    failMandate({
      _tag: "CapabilityNotInGrantorScope",
      capability: capId,
    })
  }

  audit.record({
    type: "invoke",
    mandateId,
    capability: capId,
    timestamp: nowISO(),
    triggerSource,
  })
}

/**
 * revokeMandate — remove a mandate from the active pool.
 *
 * Per spec I8: the revoker must be in the delegation chain. Since the authority
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

  // I9: rationale pre-check
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

  // Idempotent: if already revoked, do not double-record.
  const alreadyRevoked = events.some((e) => e.type === "revoke")
  if (alreadyRevoked) {
    return
  }

  audit.record({
    type: "revoke",
    mandateId,
    revokedBy: revoker,
    rationale,
    timestamp: nowISO(),
    triggerSource,
  })
}

// ============================================================================
// v1.0 multi-tier issue functions (per spec mandate-v0-2-multi-tier-and-signing)
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
// Each function preserves the v0.0 + v0.1 + v0.1.1 invariants:
//   - I9 constitutional pre-check on rationale strings BEFORE persistence
//   - Audit recording with triggerSource discriminator
//   - Branded ULID-shaped MandateId
//   - Immutable scope; re-grant via new function call
//
// And adds:
//   - Per-tier subset gate at compile time via Cap extends ParentCaps[number]
//   - Typed parent-scope chain via the ParentScope generic parameter

/**
 * issueOrgMandate — bootstrap an organization-tier mandate (the root tier
 * per spec I2 + I4). The grantor is the human-in-the-loop or any root
 * authority; there is no parent scope (this IS the root).
 */
export const issueOrgMandate = <Caps extends ReadonlyArray<Capability>>(args: {
  readonly grantor: GrantorId
  readonly capabilities: Caps
  readonly rationale: string
  readonly triggerSource?: TriggerSource
}, audit: MandateAuditService): MandateScope<Caps, "organization", null> => {
  // Every caller-supplied field is read exactly once (the 2026-10-13 mandate audit).
  const { grantor, rationale } = args
  const capabilities = captureCapabilities(args.capabilities)
  const capabilityIds = resolveCapabilityIds(capabilities)
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

  const newId = generateMandateId()
  const grantTimestamp = nowISO()

  const scope = mint<MandateScope<Caps, "organization", null>>({
    _tag: "MandateScope",
    tier: "organization",
    id: newId,
    capabilities,
    grantor,
    grantTimestamp,
    grantRationale: rationale,
    parentMandateId: null,
    parentScope: null,
  })

  audit.record({
    type: "grant",
    mandateId: newId,
    grantor,
    capabilities: capabilityIds,
    rationale,
    parentMandateId: null,
    timestamp: grantTimestamp,
    triggerSource,
  })

  return scope
}

/**
 * issueProjectMandate — derive a project-tier mandate from an
 * organization-tier grantor scope. Per spec I3, the compile-time constraint
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
}, audit: MandateAuditService): MandateScope<
  ProjectCaps,
  "project",
  MandateScope<OrgCaps, "organization", null>
> => {
  // Every caller-supplied field is read exactly once (the 2026-10-13 mandate audit).
  const { grantor, grantorScope, rationale } = args
  const capabilities = captureCapabilities(args.capabilities)
  const capabilityIds = resolveCapabilityIds(capabilities)
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

  // DAN-1157: an issued grantor, and the runtime half of the tier ladder.
  assertIssued(grantorScope, grantorScope.id, capabilityIds[0] ?? "")
  assertGrantorTier(grantorScope, "organization", "project")

  const newId = generateMandateId()
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
    grantor,
    grantTimestamp,
    grantRationale: rationale,
    parentMandateId: grantorScope.id,
    parentScope: detach(grantorScope),
  })

  audit.record({
    type: "grant",
    mandateId: newId,
    grantor,
    capabilities: capabilityIds,
    rationale,
    parentMandateId: grantorScope.id,
    timestamp: grantTimestamp,
    triggerSource,
  })

  return scope
}

/**
 * issueAgentMandate — derive an agent-tier mandate from a project-tier
 * grantor scope. Per spec I3 + I4, the compile-time constraint
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
}, audit: MandateAuditService): MandateScope<
  AgentCaps,
  "agent",
  MandateScope<ProjectCaps, "project", MandateScope<OrgCaps, "organization", null>>
> => {
  // Every caller-supplied field is read exactly once (the 2026-10-13 mandate audit).
  const { grantor, grantorScope, rationale } = args
  const capabilities = captureCapabilities(args.capabilities)
  const capabilityIds = resolveCapabilityIds(capabilities)
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

  // DAN-1157: an issued grantor, and the runtime half of the tier ladder. This
  // is what makes agents leaves for a JavaScript caller too: an agent-tier
  // grantor (agent → agent) and an org-tier one (org → agent) both stop here.
  assertIssued(grantorScope, grantorScope.id, capabilityIds[0] ?? "")
  assertGrantorTier(grantorScope, "project", "agent")

  const newId = generateMandateId()
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
    grantor,
    grantTimestamp,
    grantRationale: rationale,
    parentMandateId: grantorScope.id,
    parentScope: detach(grantorScope),
  })

  audit.record({
    type: "grant",
    mandateId: newId,
    grantor,
    capabilities: capabilityIds,
    rationale,
    parentMandateId: grantorScope.id,
    timestamp: grantTimestamp,
    triggerSource,
  })

  return scope
}
