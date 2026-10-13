// sweetrust/gate — the enforcement kernel (trust-types spec v1.1, §4–§5)
// ============================================================================
// Types constrain SHAPE. Nothing constrains PEDIGREE — until values carry
// their provenance. Sourced<T> tags ride values from the extraction boundary
// to the sink, tiers rise ONLY through named declassifiers, and every sink
// decision (allow or refuse) emits a receipt.
//
// SWEE AI anatomy: SweeMandate signs (@sweetrust/mandate, authority) · the
// firewall ENFORCES (this package in-process + the Move SpendCage on-chain) ·
// SweeVerify proves (@sweetrust/verify, evidence).
//
// Dependency-free by design (node builtins only) — this package IS the kernel
// of the standalone lib; Effect/BAML/cage integrations wrap it, never fork it.
// Adding a dependency here is an architecture decision requiring an ADR.
//
// Spec rules implemented:
//   Rule 1  — taint is sticky (combining takes the minimum tier)
//   Rule 2  — inference is not evidence (LLM output is Untrusted, always)
//   Rule 3  — ascent only through explicit declassifiers (each ascent recorded in provenance)
//   Rule 3a — accumulation never reaches Verified (authority acts only)
//   Rule 3b — corroboration requires INDEPENDENT sources (disjoint ancestry)
//   Rule 4  — sinks declare their appetite (@requires), fail closed
//   Rule 5  — adoption ladder: observe → warn → enforce
// ============================================================================

import { createHash } from "node:crypto"

// ── Tiers (§3, the lattice) ─────────────────────────────────────────────────

export const TIERS = ["untrusted", "asserted", "corroborated", "verified"] as const
export type Tier = (typeof TIERS)[number]

const RANK: Record<Tier, number> = { untrusted: 0, asserted: 1, corroborated: 2, verified: 3 }

/**
 * Own-key membership in the lattice. `RANK[t]` alone is not a membership test:
 * `RANK["bogus"]` is undefined and `RANK["constructor"]` is a function, and
 * both compare as false against every number — which made minTier keep its
 * "verified" seed for any string outside the lattice (the 2026-10-13 gate
 * audit). Tier strings that arrive from JSON are exactly the ones that miss.
 */
const isTier = (t: unknown): t is Tier => typeof t === "string" && Object.hasOwn(RANK, t)

export const meetsTier = (actual: Tier, required: Tier): boolean =>
  isTier(actual) && isTier(required) && RANK[actual] >= RANK[required]

/**
 * Rule 1 — taint is sticky: any combination takes the minimum tier.
 *
 * FAIL-CLOSED ON EMPTY (adversarial pass A2, 2026-07-25). The reduce seeds with
 * "verified", so combining *nothing* used to yield the MAXIMUM tier. The call
 * site that finds this is not exotic — `minTier(...inputs.map(i => i.tier))`
 * where `inputs` is empty is the obvious way to write it, and it silently
 * minted Verified. Combining zero sources is the absence of evidence, so it
 * floors instead.
 *
 * FAIL-CLOSED ON AN UNKNOWN TIER (the 2026-10-13 gate audit). The same reduce
 * returned the maximum for any string outside the lattice, because `RANK[t]`
 * is then undefined (or, for `"constructor"`, a function) and never compares
 * below the seed. A tier that is not one of TIERS is not a tier; any
 * combination containing one is untrusted.
 */
export const minTier = (...tiers: Tier[]): Tier =>
  tiers.length === 0 || !tiers.every(isTier)
    ? "untrusted"
    : tiers.reduce((lo, t) => (RANK[t] < RANK[lo] ? t : lo), "verified" as Tier)

// ── Sourced<T> (§4) ─────────────────────────────────────────────────────────

export interface UpgradeEvent {
  readonly declassifier: string
  readonly from: Tier
  readonly to: Tier
  readonly evidence: string
  readonly at: string // ISO timestamp
}

export interface Provenance {
  /** Where the value was born, e.g. "channel:email-inbound", "llm:ExtractInvoice". */
  readonly origin: string
  /** Every root source in this value's ancestry — Rule 3b independence checks use this. */
  readonly ancestors: ReadonlySet<string>
  /** The audit surface: each tier ascent, in order. Append-only. */
  readonly chain: ReadonlyArray<UpgradeEvent>
  /**
   * Rule 5 — confidence rides along. Optional [0,1] score, ORTHOGONAL to tier:
   * tier answers "how did this value earn its trust?" (structural); confidence
   * answers "how sure is the source it's right?" (epistemic). An LLM extraction
   * is Untrusted (tier) yet may be 0.97-confident (extractor's self-report); a
   * judgment provider (§ JudgmentProvider) emits confidence a sink can floor on.
   * `undefined` = not applicable / not measured (channels, authorities). It never
   * substitutes for tier — a high-confidence Untrusted value is still Untrusted.
   */
  readonly confidence?: number | undefined
}

/** Module-private constructor handle — assigned once by the static block below;
 * never exported. This is what makes Rule 3 structural: no importer can build
 * or re-tier a Sourced except through the factories and declassifiers here. */
let construct: <T>(value: T, tier: Tier, provenance: Provenance) => Sourced<T>

/**
 * The construction token. `private constructor` is a compile-time wall only:
 * TypeScript erases it, so from JavaScript `new Sourced(v, "verified", prov)`
 * and `class Evil extends Sourced` both minted branded values that cleared an
 * `enforce` sink (the 2026-10-13 gate audit). The constructor now demands this
 * symbol as its first argument and throws without it. It never leaves this
 * module, and the shipped `.d.mts` emits `private constructor();` with no
 * parameters, so nothing about it is visible to an importer.
 */
const CONSTRUCT = Symbol("sweetrust/gate: Sourced may only be constructed inside trust.ts")

/**
 * Seal a Set so the mutators throw while reads stay ordinary.
 *
 * Why this exists (adversarial pass A1, 2026-07-25). The constructor used to
 * note that `ancestors` was a mutable Set but argue it was safe because
 * "mutating it only ADDS overlap (fails closed for independence)". That
 * enumerated only `add`. A Set also has `delete` and `clear`, which REMOVE
 * overlap — so any code holding a Sourced could strip a shared ancestor and
 * corroborate a poisoned value against something derived from itself, which is
 * the exact attack Rule 3b exists to stop. Freezing the object does not seal
 * Set contents; this does.
 */
function sealAncestors(source: Iterable<string>): ReadonlySet<string> {
  const inner = new Set(source) // copy: the caller's Set is never our Set
  const sealed = new Proxy(inner, {
    get(target, prop) {
      if (prop === "add" || prop === "delete" || prop === "clear") {
        return () => {
          throw new TypeError(`Sourced.provenance.ancestors is immutable (attempted ${String(prop)})`)
        }
      }
      // forEach is the one Set read that hands its RECEIVER to caller code: the
      // callback's third argument is the Set being iterated. Bound to `target`
      // like every other method, that was the raw inner Set, and
      // `ancestors.forEach((_v, _k, set) => set.delete(…))` walked straight
      // past the three traps above (the 2026-10-13 gate audit). The callback
      // now receives the sealed view, so the mutators throw there too. Every
      // other method is safe to bind to the raw Set: `has`/`size` return
      // scalars and the iterators yield strings, never the Set.
      if (prop === "forEach") {
        return (cb: (value: string, key: string, set: ReadonlySet<string>) => void, thisArg?: unknown) => {
          target.forEach((v, k) => cb.call(thisArg, v, k, sealed))
        }
      }
      const v = Reflect.get(target, prop, target)
      return typeof v === "function" ? v.bind(target) : v
    },
    set: () => false,
    deleteProperty: () => false,
  }) as ReadonlySet<string>
  return sealed
}

export class Sourced<T> {
  /**
   * The nominal brand (DAN-904). Load-bearing at BOTH compile time and runtime,
   * and the only member of this class that is neither data nor behaviour.
   *
   * WHY IT EXISTS. `private constructor` below reads as nominal typing and is
   * not. A private *constructor* seals CONSTRUCTION — it blocks `new Sourced(…)`
   * and `class X extends Sourced` — but adds no private member to the INSTANCE
   * type. Every other field here is public `readonly`, so the instance type was
   * fully structural, and this five-line object literal was assignable to
   * `Sourced<T>` under `strict: true` against the SHIPPED `.d.mts`:
   *
   *     { value: "attacker@evil.test", tier: "verified",
   *       provenance: { origin: "forged", ancestors: new Set(), chain: [] },
   *       describe: () => "verified via payee-registry" }
   *
   * `tsc --strict` exited 0. It cleared the tier wall, executed the privileged
   * operation, and landed on the signed receipt AS VERIFIED — the evidence
   * chain certifying the forgery rather than catching it. TypeScript's
   * nominality comes from a private or `#`-private PROPERTY, which this class
   * did not have. `ReceiptLog`, one screen below in this same file, has always
   * been nominal — because it happens to hold a `private events`. The class
   * that got it by accident was not the security-critical one.
   *
   * 🛑 DO NOT "CLEAN THIS UP". It is never read by name and every linter will
   * call it dead. It is not. The compile-time half IS the fix (a foreign object
   * cannot satisfy a member it cannot name), and the runtime half backs
   * `Sourced.is()`. The initializer is deliberate rather than `#brand!: void`:
   * a definite-assignment field is not guaranteed to be EMITTED, and an
   * unemitted brand degrades `Sourced.is()` into a check that passes for
   * everything — a green check measuring something else, which is the failure
   * this package keeps auditing out of itself.
   */
  #brand = true

  readonly provenance: Provenance

  /**
   * Runtime nominality — the brand check `makeSink` uses on the declared path.
   *
   * 🛑 DELIBERATELY NOT `instanceof` (DAN-904). The obvious runtime guard,
   * `arg instanceof Sourced`, is defeated by `Object.create(Sourced.prototype)`
   * — measured against this build, not reasoned — because `instanceof` asserts
   * "has our prototype", NOT "came through our constructor", which is what it
   * reads as. `#brand in x` asserts what the other one only appears to.
   *
   * The generalizable rule is worth more than this line: A RUNTIME GUARD MUST
   * NOT BE BUILT ON A MARKER THE RUNTIME ERASES. The originally-proposed fix
   * for this brand (DAN-904) was `instanceof`, which leans on `private` — and `private`
   * being erased at runtime is the very defect the brand exists to close. The fix
   * had inherited the bug's blind spot. The tell: the guard and the
   * vulnerability cite the same language feature.
   *
   * 🛑 HONEST LIMIT, stated because it is easy to over-read. This separates
   * VALUES THAT CAME THROUGH THIS CLASS'S DOORS from DATA THAT DID NOT — a JSON
   * body, an LLM reply, a webhook payload, a deserialized record. That is the
   * threat model, and this closes it. It does NOT defend against in-process
   * code that can import this module: such code calls
   * `Sourced.fromAuthority(x, "anything")` and mints a genuine `verified`
   * through the front door. Claiming otherwise would be false coverage — see
   * the TCB HONESTY block on `fromAuthority`.
   */
  static is(x: unknown): x is Sourced<unknown> {
    return typeof x === "object" && x !== null && #brand in x
  }

  readonly value: T
  readonly tier: Tier

  private constructor(token: typeof CONSTRUCT, value: T, tier: Tier, provenance: Provenance) {
    // The runtime half of "module-private" — see CONSTRUCT. Checked before any
    // field is assigned, so a caller without the token gets a TypeError and no
    // object.
    if (token !== CONSTRUCT) {
      throw new TypeError(
        "Sourced cannot be constructed directly — use Sourced.fromChannel, Sourced.fromLLM, Sourced.fromAuthority, or a declassifier",
      )
    }
    this.value = value
    this.tier = tier
    // Runtime immutability, not just compile-time `readonly` (Session-003 C6):
    // in strict mode, reassigning tier/provenance on a frozen instance throws.
    // `ancestors` is sealed rather than merely frozen — see sealAncestors.
    // The chain array was frozen; the event OBJECTS in it were not, so
    // `chain[0].declassifier = "humanConfirm"` rewrote what describe() renders
    // onto every later receipt (the 2026-10-13 gate audit). Each event is
    // copied and frozen here, which covers both birth and every ascent — a
    // Sourced cannot exist without passing through this constructor.
    this.provenance = Object.freeze({
      ...provenance,
      ancestors: sealAncestors(provenance.ancestors),
      chain: Object.freeze(provenance.chain.map((event) => Object.freeze({ ...event }))),
    })
    Object.freeze(this)
  }

  static {
    construct = (value, tier, provenance) => new Sourced(CONSTRUCT, value, tier, provenance)
  }

  /** External channel input (email body, webhook, scraped page): Untrusted. */
  static fromChannel<T>(value: T, channel: string): Sourced<T> {
    return new Sourced(CONSTRUCT, value, "untrusted", {
      origin: `channel:${channel}`,
      ancestors: new Set([`channel:${channel}`]),
      chain: [],
    })
  }

  /**
   * Rule 2 — inference is not evidence. Output of an LLM function is
   * Untrusted REGARDLESS of the extractor's quality or its inputs' tiers.
   * Ancestry is inherited so downstream independence checks stay honest.
   */
  static fromLLM<T>(
    value: T,
    fn: string,
    inputs: ReadonlyArray<Sourced<unknown>>,
    confidence?: number,
  ): Sourced<T> {
    const ancestors = new Set<string>([`llm:${fn}`])
    for (const input of inputs) for (const a of input.provenance.ancestors) ancestors.add(a)
    // confidence is the extractor's self-report; it rides along but does NOT
    // affect tier (Rule 2 — the value is Untrusted no matter how sure the model).
    return new Sourced(CONSTRUCT, value, "untrusted", { origin: `llm:${fn}`, ancestors, chain: [], confidence })
  }

  /**
   * A value read from an authority the deployment itself governs (own
   * registry, own reference plane): Verified at birth. The `authority` name is
   * the provenance label, NOT a checked credential — nothing here validates it.
   * (§5: the reference-plane write path is the attack surface; its mutation
   * ceremony lives with the registry, not here.)
   *
   * TCB HONESTY (read before trusting a `verified` from this door — see the C8
   * block below the class): this is the trust computing base. Any code that can
   * import this module and call `fromAuthority("anything")` mints a `verified`
   * value — the string is never checked against a registry, signature, or
   * on-chain object. So a Gate `verified` is IN-PROCESS observe/warn/dev-time
   * authority, NOT unforgeable enforcement. Unforgeable enforcement is the Move
   * SpendCage's job (testnet 0x5c1588…fdfa), where capabilities cannot be minted
   * by convention. Never treat a Gate `verified` receipt as proof that real
   * authority was present; that is the four-property discriminator, in code.
   */
  static fromAuthority<T>(value: T, authority: string): Sourced<T> {
    return new Sourced(CONSTRUCT, value, "verified", {
      origin: `authority:${authority}`,
      ancestors: new Set([`authority:${authority}`]),
      chain: [],
    })
  }

  /** One-line provenance rendering — what the human sees at a refusal. */
  describe(): string {
    const hops = this.provenance.chain.map((u) => `${u.declassifier}→${u.to}`).join(", ")
    // `typeof === "number"`, not `!== undefined`: a value rehydrated from JSON
    // carries `null`, and `null.toFixed` threw here — inside the enforce sink's
    // declared loop, before any receipt (the 2026-10-13 gate audit). Anything
    // that is not a number renders as "not measured".
    const confidence = this.provenance.confidence
    const conf = typeof confidence === "number" ? `; conf ${confidence.toFixed(2)}` : ""
    return `${this.tier.toUpperCase()} (origin: ${this.provenance.origin}${hops ? `; upgrades: ${hops}` : ""}${conf})`
  }
}

// The class object and its prototype are frozen so that `Sourced.is` and
// `describe` cannot be swapped by anything holding the class (the 2026-10-13
// gate audit). Private fields are not properties, so `#brand` is unaffected.
Object.freeze(Sourced)
Object.freeze(Sourced.prototype)

// ── Tier ascent (module-private — Rule 3 made structural) ───────────────────
// Session-003 C6 (Adversary): ascent MUST NOT be reachable from outside this
// module, or the declassifiers are audited doors in a wall with a hole next
// to them. Only the three declassifiers below may call this.
//
// TCB honesty (C8): within this process, `fromAuthority` and this module are
// the trust computing base — any code that can import trust.ts and lie about
// an authority name can mint Verified values. The TS runtime is therefore an
// OBSERVE/WARN/dev-time authority; UNFORGEABLE enforcement is the Move cage's
// job (SpendCage, testnet 0x5c1588…fdfa), where capabilities cannot be minted
// by convention. This is the spec's four-property discriminator, in code.

function ascend<T>(prev: Sourced<T>, event: UpgradeEvent, mergedAncestors?: ReadonlySet<string>): Sourced<T> {
  return construct(prev.value, event.to, {
    origin: prev.provenance.origin,
    ancestors: mergedAncestors ?? prev.provenance.ancestors,
    chain: [...prev.provenance.chain, event],
    confidence: prev.provenance.confidence, // rides along through ascent
  })
}

const now = () => new Date().toISOString()

// ── Declassifiers (§5 — the three doors) ────────────────────────────────────

export type DeclassifyResult<T> =
  | { readonly ok: true; readonly value: Sourced<T> }
  | { readonly ok: false; readonly reason: string }

/**
 * Registry membership → Verified. An authority act: the value matches an
 * entry in a registry THIS deployment governs.
 */
export function allowlisted<T>(
  candidate: Sourced<T>,
  registry: ReadonlyMap<string, Sourced<T>>,
  key: string,
  registryName: string,
): DeclassifyResult<T> {
  const entry = registry.get(key)
  if (entry === undefined) {
    return { ok: false, reason: `'${key}' not in ${registryName}; candidate is ${candidate.describe()}` }
  }

  // The comparison runs on the CANDIDATE, so it executes candidate-controlled
  // code (`toJSON`, getters) and can throw on a circular value. A declassifier
  // that throws is a declassifier that returned no verdict, which every caller
  // reads as an exception rather than a refusal. Refuse instead.
  let sameShape: boolean
  try {
    sameShape = JSON.stringify(entry.value) === JSON.stringify(candidate.value)
  } catch {
    return {
      ok: false,
      reason: `'${key}' IS in ${registryName} but the candidate could not be serialized for comparison — refusing rather than guessing`,
    }
  }
  if (!sameShape) {
    return {
      ok: false,
      reason: `'${key}' IS in ${registryName} but the ${registryName} record does NOT match — candidate is ${candidate.describe()}`,
    }
  }

  // ── Ascend the REGISTRY RECORD, never the candidate (2026-08-31) ───────
  // This used to `ascend(candidate, …)`. The comparison above was therefore a
  // string ORACLE whose answer was thrown away: it asked "does the candidate
  // serialize like the record?" and then promoted the candidate itself. Any
  // value whose serialization differs from its substance defeats it — a
  // `toJSON()` returning the good record, a getter returning GOOD once then
  // EVIL, a non-enumerable or symbol-keyed or prototype-inherited field that
  // `JSON.stringify` never visits. The promoted object reached `verified`,
  // cleared an `enforce` sink, and the Ed25519 chain faithfully recorded the
  // GOOD value while the EVIL one was the one that got used. The evidence
  // certified the forgery.
  //
  // The registry is the authority this function exists to consult, so the
  // registry's record is what carries the authority forward. On an honest call
  // the two are indistinguishable — they just compared equal. On a hostile one
  // the caller gets the governed value, which is the whole point of an
  // allowlist. The candidate's identity stays in `evidence` so the receipt
  // still records what was presented.
  //
  // 🔑 The rule this file keeps relearning: THE OBJECT YOU CHECKED MUST BE THE
  // OBJECT YOU PROMOTE. Checking A and shipping B is not a weaker check, it is
  // no check at all.
  return {
    ok: true,
    value: ascend(entry, {
      declassifier: "allowlisted",
      from: entry.tier,
      to: "verified",
      evidence: `matched ${registryName}[${key}] — candidate presented was ${candidate.describe()}`,
      at: now(),
    }),
  }
}

/**
 * Agreement of two INDEPENDENT sources → Corroborated — never Verified
 * (Rule 3a: accumulation is not authority). Independence = disjoint
 * ancestry (Rule 3b): a value corroborated against something derived from
 * itself has learned nothing.
 */
export function corroborate<T>(
  claim: Sourced<T>,
  reference: Sourced<T>,
  equals: (a: T, b: T) => boolean = (a, b) => JSON.stringify(a) === JSON.stringify(b),
): DeclassifyResult<T> {
  for (const a of claim.provenance.ancestors) {
    if (reference.provenance.ancestors.has(a)) {
      return { ok: false, reason: `sources are NOT independent (shared ancestor: ${a})` }
    }
  }
  if (!equals(claim.value, reference.value)) {
    return {
      ok: false,
      reason: `values disagree — claim ${JSON.stringify(claim.value)} (${claim.describe()}) vs reference ${JSON.stringify(reference.value)} (${reference.describe()})`,
    }
  }
  const merged = new Set([...claim.provenance.ancestors, ...reference.provenance.ancestors])
  return {
    ok: true,
    value: ascend(
      claim,
      {
        declassifier: "corroborate",
        from: claim.tier,
        to: "corroborated",
        evidence: `agrees with independent source ${reference.provenance.origin}`,
        at: now(),
      },
      merged,
    ),
  }
}

/**
 * Human confirmation → Verified. The provenance is RENDERED to the human
 * (§5: confirmation fatigue is an attack vector — the human must see what
 * they are actually vouching for, not "Confirm? y/n").
 */
export function humanConfirm<T>(
  candidate: Sourced<T>,
  render: (question: string) => boolean,
): DeclassifyResult<T> {
  const question = `Confirm ${JSON.stringify(candidate.value)} — provenance: ${candidate.describe()}?`
  if (!render(question)) {
    return { ok: false, reason: `human declined: ${question}` }
  }
  return {
    ok: true,
    value: ascend(candidate, {
      declassifier: "humanConfirm",
      from: candidate.tier,
      to: "verified",
      evidence: "human confirmed with provenance rendered",
      at: now(),
    }),
  }
}

// ── Receipts (SweeVerify's lowercase artifact) ──────────────────────────────
// Hash-chained decision log: every sink invocation — allowed OR refused —
// appends an event whose hash covers the previous hash. Tamper-evident by
// construction; Ed25519 signing is the next layer up (@sweetrust/verify's
// SignedReceiptLog wraps this class — wrap, never fork).

export interface Receipt {
  readonly seq: number
  readonly at: string
  readonly sink: string
  /**
   * `errored` (added 2026-07-25) records an operation that PASSED the walls and
   * then threw. Without it the log has a hole shaped like "everything that went
   * wrong" — see makeSink. The action may or may not have taken effect; that
   * uncertainty is the point of recording it.
   *
   * `declassify-refused` is RESERVED, not yet produced (DAN-1159 item 4b). It
   * is the evidence a declassifier's refusal should leave. Today the
   * declassifiers take no log, so a refused ascent records nothing (SECURITY.md,
   * "A declassifier's refusal leaves no receipt"). The member exists before the
   * first publish because adding one later breaks every exhaustive switch;
   * emitting it through an optional log is additive and can follow.
   */
  readonly decision:
    | "executed" | "refused" | "observed" | "warned"
    | "judgment-blocked" | "judgment-flagged" | "errored"
    | "declassify-refused"
  readonly args: Record<string, { value: unknown; tier: Tier; provenance: string }>
  readonly reason?: string
  readonly prevHash: string
  readonly hash: string
}

/**
 * The exact bytes ReceiptLog hashes for a receipt — the single definition of the
 * interior-hash serialization. Exported so verifiers (@sweetrust/verify) recompute
 * hashes from this function instead of hand-mirroring key order across packages.
 * Field order is fixed here regardless of caller object-literal order.
 */
export function receiptBody(e: Omit<Receipt, "hash">): string {
  return JSON.stringify({
    seq: e.seq,
    prevHash: e.prevHash,
    at: e.at,
    sink: e.sink,
    decision: e.decision,
    args: e.args,
    ...(e.reason !== undefined ? { reason: e.reason } : {}),
  })
}

export class ReceiptLog {
  private events: Receipt[] = []
  /**
   * Appends ever made, independent of the array. A hash chain detects a link
   * being ALTERED; it cannot detect links being REMOVED from the end, because
   * the surviving prefix is itself a valid chain — and dropping the refusals is
   * the interesting tamper (adversarial pass A5, 2026-07-25). This counter is
   * what makes truncation detectable in-process.
   */
  private appended = 0

  /**
   * Compute the next receipt WITHOUT committing it. Pure.
   *
   * Split out of append() 2026-07-25 so a subclass that must do fallible work
   * per record — @sweetrust/verify signs each one — can do that work before
   * anything lands. The old shape committed first and let the subclass sign
   * second, so a signing failure left the interior chain one ahead of the
   * signed chain, permanently, with every later wrapper link built on a stale
   * predecessor and the exported artifact silently short a receipt.
   */
  protected nextReceipt(entry: Omit<Receipt, "seq" | "prevHash" | "hash">): Receipt {
    const prevHash = this.events.at(-1)?.hash ?? "genesis"
    const seq = this.events.length
    const body = receiptBody({ seq, prevHash, ...entry })
    const hash = createHash("sha256").update(body).digest("hex")
    return { seq, prevHash, hash, ...entry }
  }

  /** Commit a receipt from nextReceipt(). The only mutation point. */
  protected commit(receipt: Receipt): Receipt {
    this.events.push(receipt)
    this.appended++
    return receipt
  }

  append(entry: Omit<Receipt, "seq" | "prevHash" | "hash">): Receipt {
    return this.commit(this.nextReceipt(entry))
  }

  /** A copy. Handing out the live array let any caller push, splice, or truncate. */
  all(): ReadonlyArray<Receipt> {
    return [...this.events]
  }

  /** The head hash — what an external anchor (@sweetrust/verify) commits to. */
  head(): string {
    return this.events.at(-1)?.hash ?? "genesis"
  }

  /**
   * Recompute the chain. Detects any alteration of a past event, AND detects
   * truncation via the append counter.
   *
   * BOUNDARY, stated because it is easy to over-read: this is *in-process*
   * tamper evidence. A hash chain reconstructed from bytes alone cannot prove
   * it is complete — only that it is internally consistent. Proving a log has
   * not been truncated across a process or a machine requires an external
   * commitment to the head; that is @sweetrust/verify's job, not this class's.
   */
  verifyChain(): boolean {
    if (this.events.length !== this.appended) return false
    let prevHash = "genesis"
    for (const [i, e] of this.events.entries()) {
      if (e.seq !== i) return false
      if (e.prevHash !== prevHash) return false
      const rebuilt = createHash("sha256").update(receiptBody(e)).digest("hex")
      if (rebuilt !== e.hash) return false
      prevHash = e.hash
    }
    return true
  }
}

// ── Judgment seam (complement, never compete) ────────────────────────────────
// Trust tiers + the cage catch bad PEDIGREE and out-of-bounds actions. Neither
// catches "in-bounds but WRONG": a payment in-budget, to an allowlisted payee,
// that still isn't what the principal meant. That gap is judgment's job — a
// calibrated model scoring the action against declared intent. Two rules govern
// it: (1) judgment is FALLIBLE (it can be fooled), so it must
// never be the only wall; (2) judgment is SELF-AWARE (it reports calibrated
// confidence and, crucially, says "unsure") — an unsure verdict defers to a
// human, it does not confidently block. We CONSUME judgment via this seam; this
// package does not ship a judgment model.

export interface JudgmentVerdict {
  readonly assessment: "match" | "mismatch" | "unsure"
  readonly confidence: number // [0,1] — calibrated: high when right, low when wrong
  readonly rationale: string
}

export interface JudgmentProvider {
  /** Score a proposed action against the principal's declared intent. */
  readonly name: string
  assess(action: string, args: Record<string, { value: unknown; tier: Tier }>): JudgmentVerdict
}

/**
 * A stand-in provider for demos and tests. Real integration = an external
 * calibrated scorer behind the same interface, swapped in with zero call-site
 * changes. Matches a declared allowlist of intended
 * payees/amounts; anything outside it is "mismatch" (or "unsure" near the edge).
 */
export function mockJudgmentProvider(intent: {
  readonly intendedPayees: ReadonlySet<string>
  readonly maxAmount: number
}): JudgmentProvider {
  return {
    name: "mock-judgment",
    assess(action, args) {
      const to = String(args.to?.value ?? "")
      const amount = Number(args.amount?.value ?? NaN)
      if (intent.intendedPayees.has(to) && amount <= intent.maxAmount) {
        return { assessment: "match", confidence: 0.9, rationale: `${action} matches declared intent` }
      }
      // Near-edge amounts read as "unsure" — the honest, defer-to-human band.
      if (intent.intendedPayees.has(to) && amount <= intent.maxAmount * 1.1) {
        return { assessment: "unsure", confidence: 0.35, rationale: `${to} is intended but amount ${amount} slightly over cap ${intent.maxAmount}` }
      }
      return { assessment: "mismatch", confidence: 0.82, rationale: `${to}/${amount} not in declared intent (payee unintended or amount over cap)` }
    },
  }
}

// ── Sinks (§4 Rule 4 + §6.5 adoption ladder) ────────────────────────────────

export type EnforcementMode = "observe" | "warn" | "enforce"

export type SinkResult<R> =
  | { readonly ok: true; readonly result: R; readonly receipt: Receipt }
  | { readonly ok: false; readonly refusal: string; readonly receipt: Receipt }

/**
 * The JSON a receipt records for a value. Identical to `JSON.stringify` except
 * that a BigInt, which it refuses, is written as its digits plus "n", the way
 * JavaScript writes the literal. Every Sui amount in MIST is a bigint.
 *
 * This lives HERE, in gate's receipt rendering, and deliberately not in
 * mandate's `canonicalJSON`: that function defines signed bytes for the whole
 * rail, and changing it would move every mandate signature (AGENTS.md, "One
 * canonicalization across the rail"). By the time a receipt reaches a signer,
 * its arguments are already plain JSON.
 */
const receiptJSON = (value: unknown): string | undefined =>
  JSON.stringify(value, (_key, v: unknown) => (typeof v === "bigint" ? `${v}n` : v))

/**
 * See makeSink's `redact` option — applied to receipt rendering only.
 *
 * Returns a SNAPSHOT, the JSON form of the value at the moment of the call.
 * It used to return the caller's object itself (DAN-1159 item 2), so a caller
 * who edited that object after a successful call rewrote the receipt, and
 * `verifyChain()` then reported the log as tampered. What the receipt holds is
 * now exactly what its hash covers. For every value that serialized before,
 * the hashed bytes are unchanged.
 *
 * Throws when the value cannot be serialized at all (a cycle, a throwing getter
 * or `toJSON`). makeSink turns that into a violation BEFORE `execute()`.
 */
function renderForReceipt(value: unknown, policy: "raw" | "hash" | "truncate"): unknown {
  const json = receiptJSON(value)
  if (policy === "hash") {
    return "sha256:" + createHash("sha256").update(json ?? "undefined").digest("hex")
  }
  if (policy === "truncate") {
    const s = typeof value === "string" ? value : typeof value === "bigint" ? `${value}n` : (json ?? "undefined")
    return s.length > 64 ? s.slice(0, 64) + "…" : s
  }
  return json === undefined ? undefined : JSON.parse(json)
}

/**
 * A privileged operation that declares its appetite: each argument's minimum
 * tier. In `enforce` mode an under-tier argument refuses the call with the
 * provenance rendered — the human sees exactly the right question. Every
 * decision, either way, lands in the receipt log.
 *
 * Declare `Args` (`makeSink<{ to: Sourced<string> }, string>(…)`) or type
 * `execute`'s parameter. `requires` names the keys but not their types, so
 * without one of those each argument's `value` is `unknown` until narrowed. It
 * used to be `any`, which let a sink compile against a shape nobody declared
 * (DAN-1159 item 4a).
 */
export function makeSink<Args extends Record<string, Sourced<unknown>>, R>(spec: {
  readonly name: string
  readonly requires: { readonly [K in keyof Args]: Tier }
  readonly mode: EnforcementMode
  readonly log: ReceiptLog
  readonly execute: (args: Args) => R
  /**
   * Optional judgment wall (the judgment seam). Runs AFTER tier checks pass —
   * it exists to catch the in-bounds-but-wrong action the tiers structurally
   * cannot. `floor` is the confidence a "mismatch" must clear to block; below
   * it, or on "unsure", the action is FLAGGED (allowed, but the doubt is on the
   * receipt) rather than blocked — judgment defers to a human when unsure.
   */
  readonly judgment?: { readonly provider: JudgmentProvider; readonly floor: number }
  /**
   * Per-arg receipt-rendering policy. Receipts are signed and potentially
   * anchored on-chain — they can never be redacted after the fact, so the
   * policy applies BEFORE the hash:
   *   raw      — record the value as-is (default)
   *   hash     — record `sha256:<hex>` of the value's JSON (provable-if-known,
   *              unreadable otherwise)
   *   truncate — record the value's string form cut to 64 chars
   * Enforcement AND judgment always see the RAW value; only what lands on the
   * durable receipt changes.
   */
  readonly redact?: { readonly [K in keyof Args]?: "raw" | "hash" | "truncate" }
}) {
  return (args: Args): SinkResult<R> => {
    // `Object.create(null)` rather than `{}`: `rendered` is keyed by ATTACKER-
    // SUPPLIED argument names and then handed to the receipt. A plain object
    // literal inherits `Object.prototype`, so an argument named `__proto__`
    // does not become a key at all — it mutates the prototype — and the
    // receipt silently loses the record of an argument that reached the sink.
    const rendered: Receipt["args"] = Object.create(null)
    const violations: string[] = []

    // Own-key redaction lookup. `spec.redact?.[key]` walks the prototype, so a
    // key like `constructor` or `toString` returns an inherited FUNCTION where
    // a `"raw" | "hash" | "truncate"` was expected, and that value decides what
    // lands on a receipt that may be anchored on-chain and can never be
    // amended. Anything not declared as an own key redacts as "raw".
    const redactFor = (k: string): "raw" | "hash" | "truncate" =>
      spec.redact !== undefined && Object.hasOwn(spec.redact, k)
        ? ((spec.redact as Record<string, "raw" | "hash" | "truncate" | undefined>)[k] ?? "raw")
        : "raw"

    // No action without its receipt (DAN-1159 item 2). Every argument is
    // rendered HERE, before any decision, so the receipt can always be
    // written. The order used to be execute() first and serialize second, so an
    // argument JSON.stringify refuses (a cycle; a BigInt before `receiptJSON`)
    // threw inside log.append AFTER the side effect: the action ran and left no
    // receipt, and the chain still verified. An argument that cannot be
    // rendered is recorded as a placeholder and raised as a violation, and the
    // adoption ladder decides as it does for any other: `enforce` refuses before
    // execute(), `observe` and `warn` run it with the gap written down.
    const record = (key: string, value: unknown): unknown => {
      try {
        return renderForReceipt(value, redactFor(key))
      } catch (err) {
        const why = (err instanceof Error ? err.message : String(err)).split("\n")[0]
        violations.push(`${key} cannot be written to a receipt (${why}), so an action it feeds could not be evidenced`)
        return `[unrecordable: ${why}]`
      }
    }
    for (const key of Object.keys(spec.requires) as Array<keyof Args & string>) {
      const arg = args[key]
      if (arg === undefined) {
        violations.push(`${key} requires ${spec.requires[key]} but was not provided`)
        continue
      }
      // ── Nominal brand check — the DECLARED path (DAN-904) ──────────────
      // Everything below this point reads `arg.tier` and calls `arg.describe()`
      // and then writes both onto a signed, hash-chained, possibly on-chain
      // receipt. All three are attacker-controlled if `arg` is not really a
      // `Sourced`, so identity has to be settled BEFORE any of them is touched
      // — including before `describe()` is CALLED, which on a forgery is
      // invoking an attacker's function and putting its return value in
      // evidence.
      //
      // The `as unknown` is deliberate and is the point rather than a wart:
      // `arg`'s static type is `Sourced<unknown>`, and that static type IS THE
      // CLAIM UNDER TEST. Narrowing through the cast also keeps `arg`'s
      // declared type intact for the honest path below, instead of collapsing
      // its negative branch to `never`.
      //
      // Fails closed the way the A3 undeclared-argument fix does, and for the
      // same reason: RECORD it (a silent unrecorded argument is the whole
      // guarantee leaking) but record it as `untrusted` with a provenance
      // string WE authored, and raise a violation. `spec.mode` still governs
      // whether a violation refuses — the adoption ladder is unchanged.
      if (!Sourced.is(arg as unknown)) {
        rendered[key] = {
          value: record(key, arg as unknown),
          tier: "untrusted",
          provenance: "FORGED — failed the Sourced brand check; not a value this rail issued",
        }
        violations.push(
          `${key} requires ${spec.requires[key]} but is not a Sourced value — it carries the shape but not the brand, so its tier is a claim this rail never made`,
        )
        continue
      }

      rendered[key] = { value: record(key, arg.value), tier: arg.tier, provenance: arg.describe() }
      if (!meetsTier(arg.tier, spec.requires[key])) {
        violations.push(`${key} requires ${spec.requires[key]} but is ${arg.describe()}`)
      }
    }

    // Undeclared arguments (adversarial pass A3, 2026-07-25).
    // `rendered` used to cover only the keys in `requires`, while execute()
    // received the FULL args object. An argument the spec never declared was
    // therefore never tier-checked AND never recorded — it reached the
    // privileged operation invisibly, and the receipt said nothing. For a
    // system whose claim is verifiable evidence of what the agent did, a silent
    // unrecorded argument is the whole guarantee leaking.
    //
    // Both halves are fixed: it is always RECORDED, and in enforce mode it is a
    // violation. A sink receiving an argument it did not declare is a spec/call
    // mismatch, and fail-closed means refuse rather than guess an appetite.
    for (const key of Object.keys(args) as Array<keyof Args & string>) {
      // ── Own-key test, not `in` (2026-08-31) ─────────────────────────────
      // This was `if (key in spec.requires) continue`. `in` walks the
      // prototype chain, and `spec.requires` is a plain object literal, so
      // `"constructor" in { to: "verified" }` is TRUE. An argument named
      // `constructor`, `__proto__`, `toString`, `valueOf`, `hasOwnProperty`,
      // `isPrototypeOf` or `propertyIsEnumerable` was therefore treated as
      // DECLARED-AND-HANDLED by this loop, while the declared loop above —
      // which iterates `Object.keys(spec.requires)` — never saw it either.
      // It fell through both: no tier check, no receipt entry, no violation,
      // in `enforce` mode. It reached `execute()` and left zero trace on a
      // chain that verifies clean.
      //
      // This is directly reachable wherever sink arguments come from model
      // tool-calls, which is this package's stated target: the argument names
      // are chosen by whatever wrote the tool schema.
      if (Object.hasOwn(spec.requires, key)) continue
      const arg = args[key]
      // Was `arg instanceof Sourced` until DAN-904. Same reasoning as the
      // declared path above: `instanceof` asserts "has our prototype", which is
      // weaker than what it reads as. Both paths now use one brand check, so
      // they cannot drift apart — the carry-back failure this file keeps
      // finding in itself.
      const isSourced = Sourced.is(arg as unknown)
      rendered[key] = isSourced
        ? { value: record(key, arg.value), tier: arg.tier, provenance: `UNDECLARED — ${arg.describe()}` }
        : { value: record(key, arg), tier: "untrusted", provenance: "UNDECLARED — not a Sourced value" }
      violations.push(`${key} was passed but is not declared in requires — the sink has no stated appetite for it`)
    }

    // Tier wall — hard structural gate (Rule 4).
    if (violations.length > 0 && spec.mode === "enforce") {
      const refusal = `⚠ ${spec.name} refused: ${violations.join(" · ")}`
      const receipt = spec.log.append({ at: now(), sink: spec.name, decision: "refused", args: rendered, reason: refusal })
      return { ok: false, refusal, receipt }
    }

    // Judgment wall — probabilistic, self-aware. Only runs once tiers are satisfied.
    // Judgment sees RAW values (redaction shapes the durable receipt, never the judge's view).
    if (spec.judgment && violations.length === 0) {
      const tierArgs: Record<string, { value: unknown; tier: Tier }> = {}
      for (const k of Object.keys(rendered)) tierArgs[k] = { value: args[k]!.value, tier: args[k]!.tier }
      const v = spec.judgment.provider.assess(spec.name, tierArgs)

      // Rationale is FREE TEXT from a provider that just saw the raw values
      // (adversarial pass A4, 2026-07-25). `redact` governed `args` and stopped
      // there, so a judge that echoed what it judged — the natural way to write
      // a rationale — republished the redacted value in `reason`, on the same
      // receipt that gets signed and anchored and can never be redacted after
      // the fact. Structured fields (assessment, confidence, provider name) are
      // safe because the provider does not author them; the prose is not.
      const anyRedacted = Object.values(spec.redact ?? {}).some((p) => p !== undefined && p !== "raw")
      const rationale = anyRedacted
        ? `[rationale withheld — this sink redacts arguments; sha256:${createHash("sha256").update(v.rationale).digest("hex").slice(0, 16)}]`
        : v.rationale

      const blocks = v.assessment === "mismatch" && v.confidence >= spec.judgment.floor
      if (blocks && spec.mode === "enforce") {
        const refusal = `⚖ ${spec.name} judgment-blocked (${spec.judgment.provider.name}, conf ${v.confidence.toFixed(2)}): ${rationale}`
        const receipt = spec.log.append({ at: now(), sink: spec.name, decision: "judgment-blocked", args: rendered, reason: refusal })
        // The caller is in-process and already holds the raw values — it gets
        // the real rationale. Only the durable receipt is redacted.
        return { ok: false, refusal: `⚖ ${spec.name} judgment-blocked (${spec.judgment.provider.name}, conf ${v.confidence.toFixed(2)}): ${v.rationale}`, receipt }
      }
      if (v.assessment !== "match") {
        // Flagged, not blocked — the honest "unsure defers to human" band.
        const note = `⚖ ${spec.name} judgment-flagged (${v.assessment}, conf ${v.confidence.toFixed(2)}): ${rationale}`
        let result: R
        try {
          result = spec.execute(args)
        } catch (err) {
          // Same hole as the main path (V5) — a flagged action that throws must
          // not vanish, and this one is MORE important: it was already doubtful.
          spec.log.append({
            at: now(), sink: spec.name, decision: "errored", args: rendered,
            reason: `${note} — then threw; the action may or may not have taken effect: ${err instanceof Error ? err.message : String(err)}`,
          })
          throw err
        }
        const receipt = spec.log.append({ at: now(), sink: spec.name, decision: "judgment-flagged", args: rendered, reason: note })
        return { ok: true, result, receipt }
      }
    }

    const decision = violations.length > 0 ? "warned" : spec.mode === "observe" ? "observed" : "executed"

    // The operation runs before the receipt can describe its outcome, so a
    // throw used to leave NO record at all (adversarial pass V5, 2026-07-25):
    // the gateway returned 500 on a request that may well have settled, and the
    // evidence log — the whole product — was silent about it. A log whose only
    // gap is "everything that went wrong" is worse than no log, because it
    // reads as complete. The attempt is now always recorded before the error
    // propagates; the caller still gets its exception.
    let result: R
    try {
      result = spec.execute(args)
    } catch (err) {
      spec.log.append({
        at: now(),
        sink: spec.name,
        decision: "errored",
        args: rendered,
        reason: `${spec.name} passed the walls and then threw — the action may or may not have taken effect: ${err instanceof Error ? err.message : String(err)}`,
      })
      throw err
    }

    const receipt = spec.log.append({
      at: now(),
      sink: spec.name,
      decision,
      args: rendered,
      ...(violations.length > 0 ? { reason: `mode=${spec.mode}, violations: ${violations.join(" · ")}` } : {}),
    })
    return { ok: true, result, receipt }
  }
}
