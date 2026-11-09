/**
 * sweetrust/mandate — issuance, invocation, revocation flows
 *
 * This module imports the constitutional pre-check
 * primitive from ./security.ts (formerly a standalone package, folded back into mandate 2026-07-19). Mandate metadata (rationale strings and, since the
 * 2026-10-13 mandate audit, capability identifiers) is exactly the attack
 * surface the pre-check exists to defend.
 */
import { randomBytes } from "node:crypto"
import { canonicalJSON, sha256Hex } from "../canon.ts"
import type { GrantedPurpose, Purpose } from "../purpose.ts"
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
 * The caller's `triggerSource`, read once by the caller of this function and
 * held to the two values the type names (the 2026-11-08 audit, K2). Absent means
 * "code". Anything else is a programmer error, a `TypeError`, before any
 * authority decision.
 *
 * It used to reach the event unchecked, so an object carrying a `toJSON` went
 * into the signed payload. A stateful `toJSON` made the signed bytes differ from
 * the file bytes, and every owner operation on that store, revoke included,
 * then threw `AuditLogCorrupt` until someone edited the file by hand. A
 * re-entrant `toJSON` spent twice between the chain-head read and the append.
 * Refusing it here means no live object ever reaches a record.
 */
const captureTriggerSource = (raw: unknown): TriggerSource => {
  if (raw === undefined) return "code"
  if (raw !== "code" && raw !== "external") {
    throw new TypeError('triggerSource must be "code" or "external"')
  }
  return raw
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
 *
 * Always returns a primitive string, and only for a bare string or an object
 * with a string `key` (the 2026-11-08 audit, K1). A `key` that is an object would
 * otherwise reach the Sets, the grant event and the signed bytes as a live value,
 * and a key-less object stringified to one shared "[object Object]". Anything
 * else is a programmer error, a `TypeError`. The use path has its own form that
 * refuses instead (`presentedKey`).
 */
export const capabilityKey = (cap: Capability): string => {
  if (typeof cap === "string") return cap
  const key: unknown = (cap as unknown as { readonly key?: unknown } | null | undefined)?.key
  if (typeof key !== "string") throw new TypeError("capabilityKey: expected a capability with a string key")
  return key
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
 * Screen one authored name before it is persisted (AGENTS.md; the 2026-11-08
 * audit, K8: `grantor`, `unit` and `resumedBy` reached the log unscreened). A
 * non-string is a `TypeError` from the screen itself.
 */
const assertAuthoredNameClean = (value: string, inputKind: "grantor" | "unit" | "resumedBy"): void => {
  const match = constitutionalPreCheck(value)
  if (match) {
    failMandate({
      _tag: "MaliciousMandateMetadata",
      inputKind,
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
//
// Read-once was not enough (the 2026-11-08 audit, K1). A `key` getter read once
// still runs caller code, and it used to run AFTER `useCapability` had taken
// its snapshot of the log. The getter called `useCapability` again, the inner
// call recorded a spend, and the outer call then judged the cap against a
// snapshot that did not contain it: 150 spent against a cap of 30, on a signed
// chain that verified. So every caller-supplied value is reduced to a primitive
// before the first log read, and an issued scope's keys are kept here, in
// `ISSUED`, where the holder cannot reach them.

const ISSUED = new WeakMap<object, ReadonlyArray<string>>()

/**
 * The elements a scope hands out: one fresh object per key per scope, so no
 * caller's capability object is retained and no two scopes share an element.
 * The kernel never reads them back (`claimedCapabilityIds`), so a holder who
 * edits an element has edited its own view and nothing else.
 */
const rebuildCapabilities = (capabilityIds: ReadonlyArray<string>): ReadonlyArray<Capability> =>
  Object.freeze(capabilityIds.map((key) => ({ key })))

/**
 * Freeze a freshly built scope and record it as issued, under the keys the
 * issuer resolved once. `capabilityIds` is that frozen list, and the scope's
 * capability list is rebuilt from it.
 */
const mint = <S extends MandateScope<any, any, any>>(scope: S, capabilityIds: ReadonlyArray<string>): S => {
  const frozen = Object.freeze({
    ...scope,
    capabilities: rebuildCapabilities(capabilityIds),
  }) as unknown as S
  ISSUED.set(frozen, capabilityIds)
  return frozen
}

/**
 * A read-only view of a grantor scope for a child's `parentScope`: the same
 * fields, so the typed parent chain still reads correctly, but a different
 * object that was never issued, so it carries no authority. Its capability
 * elements are rebuilt too: a shared element let a child's holder rewrite what
 * its grantor's holder saw. Call only after `assertIssued`.
 */
const detach = <S extends MandateScope<any, any, any>>(scope: S): S =>
  Object.freeze({ ...scope, capabilities: rebuildCapabilities(ISSUED.get(scope) ?? []) }) as unknown as S

const isIssued = (scope: unknown): scope is MandateScope<any, any, any> =>
  typeof scope === "object" && scope !== null && ISSUED.has(scope)

/** Stands in for a key that is not a string; such a value is refused before anything records it. */
const UNRESOLVED_KEY = "<no string key>"

/**
 * A presented capability's key at use, or null when it has none: `capabilityKey`
 * without the throw, because a bad value at use is a refusal, never a `TypeError`.
 * Reads `key` once.
 */
const presentedKey = (cap: unknown): string | null => {
  if (typeof cap === "string") return cap
  if (typeof cap !== "object" || cap === null) return null
  const key: unknown = (cap as { readonly key?: unknown }).key
  return typeof key === "string" ? key : null
}

/**
 * The capability keys a presented scope claims, as primitives, with no caller
 * code left to run afterward. An issued scope answers from `ISSUED`, so nothing
 * planted on its elements ever executes. Anything else is a forgery on its way
 * to a refusal, and is read once here so its refusal stays the specific one: a
 * malformed element becomes `UNRESOLVED_KEY`, never a throw. Call before the
 * first log read.
 */
const claimedCapabilityIds = (scope: unknown): ReadonlyArray<string> => {
  if (isIssued(scope)) return ISSUED.get(scope) ?? []
  const raw: unknown = (scope as { readonly capabilities?: unknown }).capabilities
  if (!Array.isArray(raw)) return []
  return Object.freeze([...raw].map((c) => presentedKey(c) ?? UNRESOLVED_KEY))
}

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
  const out: Record<string, CapabilityLimit> = Object.create(null)
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
  // Null prototype: a capability named `__proto__` must be as visible to
  // enforcement as one named `amount` (ARCHITECTURE.md invariant; the
  // 2026-11-01 land review showed `out["__proto__"] = …` set the prototype
  // and recorded a grant with no limits at all).
  const out: Record<string, CapabilityLimit> = Object.create(null)
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
    if (unit !== undefined) assertAuthoredNameClean(unit, "unit")
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
    // Own keys only: a recorded map is a plain object off JSONL, so a
    // capability named `constructor` must not read Object.prototype.
    const parent = Object.hasOwn(parentLimits, capId) ? parentLimits[capId] : undefined
    if (parent === undefined) continue
    const child = Object.hasOwn(childLimits, capId) ? childLimits[capId] : undefined
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

// ============================================================================
// The purpose on a grant (DAN-1384)
// ============================================================================
//
// The owner's sentence and its deterministic fields are written into the grant
// event and signed with it. The event is the only record anything reads: the
// narrowing check takes the parent's purpose from the parent's grant event, and
// a scope has no purpose field at all, so a holder has nothing to alter.
//
// The rules mirror limits (ADR 0005): a malformed purpose at issue is a
// programmer error (a `TypeError`); a child that would widen its parent is a
// refusal (`PurposeNotNarrowing`). The same parser reads a purpose back from
// the log, where malformed means no issuer can have written the line, so the
// verdict there is `DelegationChainBroken`.

const MAX_STATEMENT_LENGTH = 280

/** Decimal base units, one spelling per value: no sign, no fraction, no leading zero. */
const DECIMAL_INTEGER = /^(?:0|[1-9][0-9]*)$/

const isObjectBag = (x: unknown): x is object =>
  typeof x === "object" && x !== null && !Array.isArray(x)

/**
 * Each own key of `raw` read exactly once, into a bag with no prototype (the
 * intake rule). An unknown key is refused rather than dropped: a misspelled
 * `payee` silently dropped would be an owner who believes the payee is bound
 * and a grant that does not bind it. An own `__proto__` (JSON.parse makes one)
 * is an unknown key like any other.
 */
const readOwnFields = (
  raw: object,
  allowed: ReadonlyArray<string>,
  where: string,
): Record<string, unknown> => {
  const out: Record<string, unknown> = Object.create(null)
  for (const key of Object.keys(raw)) {
    if (!allowed.includes(key)) throw new TypeError(`${where} has an unknown key "${key}"`)
    out[key] = (raw as Record<string, unknown>)[key]
  }
  return out
}

/** A frozen copy of a list of non-empty strings; undefined stays undefined. */
const readStringList = (raw: unknown, where: string): ReadonlyArray<string> | undefined => {
  if (raw === undefined) return undefined
  // Checked first: a bare string is iterable, and spreading "0xabc" would
  // record five one-character payees.
  if (!Array.isArray(raw)) throw new TypeError(`${where} must be an array of strings`)
  const list: ReadonlyArray<unknown> = [...raw]
  for (const entry of list) {
    if (typeof entry !== "string" || entry.length === 0) {
      throw new TypeError(`${where} must contain only non-empty strings`)
    }
  }
  return Object.freeze(list) as ReadonlyArray<string>
}

/**
 * Snapshot and validate a purpose: a deep-frozen copy built from one read of
 * each own field, sharing nothing with `raw`. Plain objects are safe here
 * because every key written is one of the fixed names below.
 */
const snapshotPurpose = (raw: unknown): Purpose => {
  if (!isObjectBag(raw)) throw new TypeError("purpose must be an object with a statement")
  const { statement, fields: rawFields } = readOwnFields(raw, ["statement", "fields"], "purpose")
  if (typeof statement !== "string" || statement.length === 0 || statement.length > MAX_STATEMENT_LENGTH) {
    throw new TypeError(`purpose.statement must be a string of 1 to ${MAX_STATEMENT_LENGTH} characters`)
  }
  if (rawFields === undefined) return Object.freeze({ statement })
  if (!isObjectBag(rawFields)) throw new TypeError("purpose.fields must be an object")
  const { payees: rawPayees, maxPerAction, actions: rawActions } = readOwnFields(
    rawFields,
    ["payees", "maxPerAction", "actions"],
    "purpose.fields",
  )
  const payees = readStringList(rawPayees, "purpose.fields.payees")
  const actions = readStringList(rawActions, "purpose.fields.actions")
  if (maxPerAction !== undefined && !(typeof maxPerAction === "string" && DECIMAL_INTEGER.test(maxPerAction))) {
    throw new TypeError("purpose.fields.maxPerAction must be a decimal integer string")
  }
  return Object.freeze({
    statement,
    fields: Object.freeze({
      ...(payees === undefined ? {} : { payees }),
      ...(maxPerAction === undefined ? {} : { maxPerAction: maxPerAction as string }),
      ...(actions === undefined ? {} : { actions }),
    }),
  })
}

/**
 * The caller's `purpose`, read once and screened: AGENTS.md, any function that
 * persists an authored string runs the constitutional pre-check first. The
 * digits of `maxPerAction` have already matched `DECIMAL_INTEGER`.
 */
const capturePurpose = (raw: unknown): Purpose | undefined => {
  if (raw === undefined) return undefined
  const purpose = snapshotPurpose(raw)
  for (const authored of [purpose.statement, ...(purpose.fields?.payees ?? []), ...(purpose.fields?.actions ?? [])]) {
    const match = constitutionalPreCheck(authored)
    if (match) {
      failMandate({
        _tag: "MaliciousMandateMetadata",
        inputKind: "purpose",
        matchedPatternId: match.patternId,
        evidence: match.evidence,
      })
    }
  }
  return purpose
}

/** A grant event's purpose, as a fresh frozen copy; a malformed line names its own id as the break. */
const recordedPurpose = (subjectId: MandateId, grant: MandateGrantEvent): Purpose | undefined => {
  const raw: unknown = grant.purpose
  if (raw === undefined) return undefined
  try {
    return snapshotPurpose(raw)
  } catch {
    return failMandate({ _tag: "DelegationChainBroken", mandateId: subjectId, brokenAncestorId: grant.mandateId })
  }
}

const isSubsetOf = (child: ReadonlyArray<string> | undefined, parent: ReadonlyArray<string>): boolean =>
  child !== undefined && child.every((entry) => parent.includes(entry))

/**
 * I9, over two validated purposes: a child may only narrow. With no parent
 * purpose there is nothing to widen. A child that omits the purpose, or a
 * field its parent set, is refused, because omission would widen. A field the
 * parent left open may be set by the child. In v1 the statement must be equal
 * byte for byte. `maxPerAction` compares as an integer, never as text or a float.
 */
const assertPurposeNarrows = (
  grantorMandateId: MandateId,
  parent: Purpose | undefined,
  child: Purpose | undefined,
): void => {
  if (parent === undefined) return
  const refuse = (field: "purpose" | "statement" | "payees" | "maxPerAction" | "actions"): never =>
    failMandate({ _tag: "PurposeNotNarrowing", grantorMandateId, field })
  if (child === undefined) return refuse("purpose")
  if (child.statement !== parent.statement) return refuse("statement")
  const p = parent.fields
  const c = child.fields
  if (p?.payees !== undefined && !isSubsetOf(c?.payees, p.payees)) return refuse("payees")
  if (
    p?.maxPerAction !== undefined &&
    (c?.maxPerAction === undefined || BigInt(c.maxPerAction) > BigInt(p.maxPerAction))
  ) {
    return refuse("maxPerAction")
  }
  if (p?.actions !== undefined && !isSubsetOf(c?.actions, p.actions)) return refuse("actions")
}

/** The issue-time half of I9: the parent's purpose comes from its grant event, never from the scope. */
const assertPurposeWithinGrantor = (
  audit: MandateAuditService,
  grantorMandateId: MandateId,
  childPurpose: Purpose | undefined,
): void => {
  const grantEvent = audit.query(grantorMandateId).find((e) => e.type === "grant") as
    | MandateGrantEvent
    | undefined
  const parentPurpose = grantEvent === undefined ? undefined : recordedPurpose(grantorMandateId, grantEvent)
  assertPurposeNarrows(grantorMandateId, parentPurpose, childPurpose)
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
  const limits = grantEvent.limits
  const limit = limits !== undefined && Object.hasOwn(limits, capId) ? limits[capId] : undefined
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
 * issue-time check stops the orphan from ever entering the audit log. It runs
 * the same walk as use, so a revoked grandparent stops it too (the 2026-11-08
 * audit, K8: the child used to be minted and refused only at use).
 */
const checkGrantorNotRevoked = (
  audit: MandateAuditService,
  grantorScope: { readonly id: MandateId; readonly grantor: GrantorId },
): void => {
  void walkChain(audit, grantorScope.id, grantorScope.grantor)
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

const VERDICT_DIGEST = /^[0-9a-f]{64}$/

/**
 * The caller's `verdictDigest`: own key only, read once, undefined when absent
 * (DAN-1385). This is the host's statement of which verdict approved the use;
 * the mandate module cannot import the gate, so it checks the format and
 * records the value and never recomputes it. The `typeof` comes first because
 * a regex test would coerce an array or a `String` object into a pass.
 */
const captureVerdictDigest = (args: object): string | undefined => {
  if (!Object.hasOwn(args, "verdictDigest")) return undefined
  const raw: unknown = (args as { readonly verdictDigest?: unknown }).verdictDigest
  if (raw === undefined) return undefined
  if (typeof raw !== "string" || !VERDICT_DIGEST.test(raw)) {
    throw new TypeError("useCapability: verdictDigest must be 64 lowercase hex characters")
  }
  return raw
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
  /** The digest of the verdict that approved this use: 64 lowercase hex, else a TypeError (DAN-1385). */
  readonly verdictDigest?: string
}, audit: MandateAuditService): void => {
  // Every caller-supplied field is read exactly once, here, and only these
  // locals are used below (the 2026-10-13 mandate audit; the note above
  // `ISSUED` has the shape of the hole). `mandate` is the one object the
  // walk, the log checks, the possession check and the record all name.
  const { mandate, capability } = args
  const triggerSource = captureTriggerSource(args.triggerSource)
  const amountRaw: unknown = args.amount
  // A malformed digest is a programmer error, so it fails here, before any
  // authority decision, as a malformed purpose does at issue.
  const verdictDigest = captureVerdictDigest(args)
  const rawMandateId: unknown = mandate.id
  if (typeof rawMandateId !== "string") {
    return failMandate({ _tag: "MandateNotIssued", mandateId: "<non-string id>" as MandateId })
  }
  const mandateId = rawMandateId as MandateId
  // Everything a caller's object can answer is answered HERE, before the first
  // log read (K1; the note above `ISSUED`). From the walk down to the record
  // this function touches only primitives, frozen log records and the store,
  // so no caller code can run between the limit check and its record.
  const claimedCapIds = claimedCapabilityIds(mandate)
  const presented = presentedKey(capability)
  const capId = presented ?? UNRESOLVED_KEY

  // The revocation walk, shared with `resume`: see `walkChain` above for why
  // it reads the audit log and never the in-memory parent pointer (DAN-637,
  // DAN-640) and how a cyclic log is handled.
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
  for (const claimed of claimedCapIds) {
    if (!grantedCapIds.has(claimed)) {
      failMandate({
        _tag: "MandateScopeForged",
        mandateId,
        capability: claimed,
      })
    }
  }

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
  if (presented === null || !mandateCapIds.has(capId)) {
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
    ...(verdictDigest === undefined ? {} : { verdictDigest }),
  }))
}

/**
 * What a revoke records in place of a rationale that tripped the screen: the
 * pattern and a hash, so the record still names the text a host kept elsewhere
 * and the log never persists the injection. `rationale` stays a string, so the
 * record's shape does not change. The replacement is itself clean: the hash is
 * 64 hex characters, far under the MIP-4 blob threshold.
 */
const withheldRationale = (rationale: string, patternId: string): string =>
  `[rationale withheld: matched ${patternId}; sha256 ${sha256Hex(rationale)}]`

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
  const triggerSource = captureTriggerSource(args.triggerSource)

  // A revoke always lands (the 2026-11-08 audit, K5). The rationale is screened
  // before persistence as every authored string is, but a match changes what is
  // written, never whether it is written: an owner quoting the injection that
  // made them pull the plug used to be refused, and the mandate stayed live.
  const rationaleCheck = constitutionalPreCheck(rationale)
  const recordedRationale =
    rationaleCheck === null ? rationale : withheldRationale(rationale, rationaleCheck.patternId)

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
    rationale: recordedRationale,
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
  /** What this grant is for, signed into it (DAN-1384). */
  readonly purpose?: Purpose
}, audit: MandateAuditService): MandateScope<Caps, "organization", null> => {
  // Every caller-supplied field is read exactly once (the 2026-10-13 mandate audit).
  const { grantor, rationale } = args
  const capabilities = captureCapabilities(args.capabilities)
  const capabilityIds = resolveCapabilityIds(capabilities)
  const limits = captureLimits(args.limits, capabilityIds)
  capabilityIds.forEach(assertCapabilityIdentifierClean)
  const purpose = capturePurpose(args.purpose)
  const triggerSource = captureTriggerSource(args.triggerSource)

  const rationaleCheck = constitutionalPreCheck(rationale)
  if (rationaleCheck) {
    failMandate({
      _tag: "MaliciousMandateMetadata",
      inputKind: "rationale",
      matchedPatternId: rationaleCheck.patternId,
      evidence: rationaleCheck.evidence,
    })
  }

  assertAuthoredNameClean(grantor, "grantor")

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
  }, capabilityIds)

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
    ...(purpose === undefined ? {} : { purpose }),
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
  /** What this grant is for; may only narrow the grantor's recorded purpose (DAN-1384). */
  readonly purpose?: Purpose
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
  const purpose = capturePurpose(args.purpose)
  const triggerSource = captureTriggerSource(args.triggerSource)

  const rationaleCheck = constitutionalPreCheck(rationale)
  if (rationaleCheck) {
    failMandate({
      _tag: "MaliciousMandateMetadata",
      inputKind: "rationale",
      matchedPatternId: rationaleCheck.patternId,
      evidence: rationaleCheck.evidence,
    })
  }

  assertAuthoredNameClean(grantor, "grantor")

  // Resolved before the first log read, as in `useCapability` (K1).
  const grantorCapIds = new Set(claimedCapabilityIds(grantorScope))

  // Issue-time grantor-revoked check (closes the revoke-vs-issue race).
  checkGrantorNotRevoked(audit, grantorScope)

  // Runtime fallback subset check (belt-and-suspenders for any-cast escapes)
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
  assertPurposeWithinGrantor(audit, grantorScope.id, purpose)

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
  }, capabilityIds)

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
    ...(purpose === undefined ? {} : { purpose }),
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
  /** What this grant is for; may only narrow the grantor's recorded purpose (DAN-1384). */
  readonly purpose?: Purpose
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
  const purpose = capturePurpose(args.purpose)
  const triggerSource = captureTriggerSource(args.triggerSource)

  const rationaleCheck = constitutionalPreCheck(rationale)
  if (rationaleCheck) {
    failMandate({
      _tag: "MaliciousMandateMetadata",
      inputKind: "rationale",
      matchedPatternId: rationaleCheck.patternId,
      evidence: rationaleCheck.evidence,
    })
  }

  assertAuthoredNameClean(grantor, "grantor")

  // Resolved before the first log read, as in `useCapability` (K1).
  const grantorCapIds = new Set(claimedCapabilityIds(grantorScope))

  // Issue-time grantor-revoked check (closes the revoke-vs-issue race).
  checkGrantorNotRevoked(audit, grantorScope)

  // Runtime fallback subset check (belt-and-suspenders for any-cast escapes)
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
  assertPurposeWithinGrantor(audit, grantorScope.id, purpose)

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
  }, capabilityIds)

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
    ...(purpose === undefined ? {} : { purpose }),
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
  const { mandateId } = args
  const resumedBy: GrantorId = grantorId(args.resumedBy as string)
  assertAuthoredNameClean(resumedBy, "resumedBy")
  const capabilities = captureCapabilities(args.capabilities)
  const declaredIds = resolveCapabilityIds(capabilities)
  const declaredTier: unknown = args.tier
  const triggerSource = captureTriggerSource(args.triggerSource)

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
  const purposes = chain.map((g) => recordedPurpose(mandateId, g))
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
    assertPurposeNarrows(parent.mandateId, purposes[k + 1], purposes[k])
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
  }, declaredIds)

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

/**
 * grantedPurpose — the purpose a mandate's grant event records, with the hash
 * that names that grant, for the host to hand a judged sink (DAN-1384).
 *
 * The log answers, never the scope. Possession and binding are checked first,
 * so a copy of a scope is refused as forged and a scope minted against another
 * store as foreign; a resumed scope is issued and bound like any other. The
 * purpose returned is a frozen copy, because a JSONL store parses a fresh
 * object and an in-memory store hands back the one it holds.
 *
 * Refused with `MandateRevoked` or `AncestorMandateRevoked` once the mandate
 * or any ancestor is revoked. It answers at the moment it is called: a sink
 * built before the revoke holds its copy, and stopping that one is the
 * action-lifecycle work, not this function's.
 *
 * A grant with no purpose is a `TypeError`, not a null: a judged sink cannot
 * be built without one, and a host that asks has made a programmer error
 * where it builds the sink (spec § 5), before any authority decision.
 */
export const grantedPurpose = (
  scope: MandateScope<any, any, any>,
  audit: MandateAuditService,
): GrantedPurpose => {
  const presented: unknown = scope
  // Read once, and only reported until `assertIssued` has passed.
  const mandateId = (presented as { readonly id?: unknown } | null | undefined)?.id as MandateId
  assertIssued(presented, mandateId, "")
  assertBoundTo(audit, presented as object, mandateId)

  // Revocation first, by the walk `useCapability` runs, so a revoked mandate or
  // ancestor is refused as it would be at use (the 2026-11-08 audit, K6). A
  // judged sink built from a revoked grant used to execute, and reconcile
  // reported it clean.
  const grantEvent = walkChain(audit, mandateId, (presented as MandateScope<any, any, any>).grantor).chain[0]
  if (grantEvent === undefined) {
    return failMandate({ _tag: "MandateNotIssued", mandateId })
  }
  const purpose = recordedPurpose(mandateId, grantEvent)
  if (purpose === undefined) {
    throw new TypeError(`grantedPurpose: the grant of ${mandateId} carries no purpose`)
  }
  return Object.freeze({ purpose, grantHash: sha256Hex(canonicalJSON(grantEvent)) })
}
