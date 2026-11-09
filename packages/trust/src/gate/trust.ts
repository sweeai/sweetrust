// sweetrust/gate — the enforcement kernel
// ============================================================================
// Types constrain SHAPE. Nothing constrains PEDIGREE — until values carry
// their provenance. Sourced<T> tags ride values from the extraction boundary
// to the sink, tiers rise ONLY through named declassifiers, and every sink
// decision (allow or refuse) emits a receipt.
//
// The rail: SweeMandate signs (sweetrust/mandate, authority) · SweeGate
// ENFORCES (this module, in-process) · SweeVerify proves (sweetrust/verify,
// evidence). Money limits are the chain's own job, never this module's.
//
// Dependency-free by design (node builtins only) — this module IS the kernel;
// integrations wrap it, never fork it.
// Adding a dependency here is an architecture decision requiring an ADR.
//
// The rules:
//   Rule 1  — taint is sticky (combining takes the minimum tier)
//   Rule 2  — inference is not evidence (LLM output is Untrusted, always)
//   Rule 3  — ascent only through explicit declassifiers (each ascent recorded in provenance)
//   Rule 3a — accumulation never reaches Verified (authority acts only)
//   Rule 3b — corroboration requires INDEPENDENT sources (disjoint ancestry)
//   Rule 4  — sinks declare their appetite (@requires), fail closed
//   Rule 5  — adoption ladder: observe → warn → enforce
// ============================================================================

import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto"
// The rail's one canonicalization, from a leaf that imports only node:crypto.
// This is NOT an import of mandate: the gate still stands alone (src/index.ts).
import { canonicalJSON, sha256Hex } from "../canon.ts"
// Types only: the purpose leaf has no runtime content, so the gate still stands alone.
import type { GrantedPurpose, Purpose } from "../purpose.ts"

// ── Tiers (the lattice) ─────────────────────────────────────────────────────
// Three rungs. The spec drew a fourth, `asserted`, between untrusted and
// corroborated; no factory and no declassifier in this package ever produced
// it, so SECURITY.md told readers to treat the ladder as three until the code
// caught up. The 2026-10-13 rail audit removed the rung rather than keep a
// tier a sink could require and nothing could ever satisfy.

export const TIERS = ["untrusted", "corroborated", "verified"] as const
export type Tier = (typeof TIERS)[number]

const RANK: Record<Tier, number> = { untrusted: 0, corroborated: 1, verified: 2 }

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

// ── Sourced<T> ──────────────────────────────────────────────────────────────

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
   * judgment provider (JudgmentProvider) emits confidence a sink can floor on.
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
    // Runtime immutability, not just compile-time `readonly`:
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
   * (The reference-plane write path is the attack surface; its mutation
   * ceremony lives with the registry, not here.)
   *
   * TCB HONESTY (read before trusting a `verified` from this door — see the
   * honest-limits block below the class): this is the trust computing base. Any
   * code that can import this module and call `fromAuthority("anything")` mints
   * a `verified` value — the string is never checked against a registry,
   * signature, or on-chain object. So a Gate `verified` is IN-PROCESS
   * observe/warn/dev-time authority, NOT unforgeable enforcement. In-process
   * TypeScript cannot be unforgeable; money limits belong to the chain's own
   * primitives (on Sui, native `sui::allowance`). Never treat a Gate `verified`
   * receipt as proof that real authority was present.
   */
  static fromAuthority<T>(value: T, authority: string): Sourced<T> {
    // An object value is frozen IN PLACE, shallowly. `allowlisted` hands its
    // caller the registry's own record (the object you checked is the object
    // you promote — 2026-08-31), so until this line a caller could write
    // `result.value.value.iban = "DE99-EVIL"` and rewrite the registry (the
    // 2026-10-13 gate audit). An authority's record is immutable from the
    // moment it is one. ArrayBuffer views are skipped: Object.freeze throws on
    // a typed array with elements, and a key handed in as bytes is still an
    // authority value. SECURITY.md § Honest limits states the consequence.
    if (typeof value === "object" && value !== null && !ArrayBuffer.isView(value)) Object.freeze(value)
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
// Ascent MUST NOT be reachable from outside this module, or the declassifiers
// are audited doors in a wall with a hole next to them. Only the three
// declassifiers below may call this.
//
// TCB honesty: within this process, `fromAuthority` and this module are the
// trust computing base — any code that can import trust.ts and lie about an
// authority name can mint Verified values. The TS runtime is therefore an
// OBSERVE/WARN/dev-time authority. In-process TypeScript cannot be
// unforgeable; money limits belong to the chain's own primitives (on Sui,
// native `sui::allowance`).

//
// `prev` is the declassifier's own SNAPSHOT of the value it checked — its
// `value` and `provenance` read once at the top of the declassifier — never
// the Sourced argument itself. Each declassifier used to hand its argument
// straight in, so the value that was compared and the value that was promoted
// were separate reads of the caller's object (the 2026-10-13 rail audit,
// test/intake-poison.test.ts). A Sourced is frozen and cannot carry a getter,
// so no caller could exploit that; the intake rule in AGENTS.md holds for
// every export without an exception because of this.
function ascend<T>(prev: { readonly value: T; readonly provenance: Provenance }, event: UpgradeEvent, mergedAncestors?: ReadonlySet<string>): Sourced<T> {
  return construct(prev.value, event.to, {
    origin: prev.provenance.origin,
    ancestors: mergedAncestors ?? prev.provenance.ancestors,
    chain: [...prev.provenance.chain, event],
    confidence: prev.provenance.confidence, // rides along through ascent
  })
}

/**
 * The JSON the gate renders for a value — on receipts, and in the strings the
 * declassifiers build. Identical to `JSON.stringify` for everything it accepts;
 * the two values it refuses or flattens are given a shape of their own:
 *
 *   5n          → {"$bigint":"5"}        (JSON.stringify throws on a BigInt)
 *   NaN         → {"$number":"NaN"}      (JSON.stringify writes null)
 *   ±Infinity   → {"$number":"Infinity"} / {"$number":"-Infinity"}
 *
 * Until the 2026-10-13 gate audit a BigInt was written as its digits plus "n",
 * which is byte-identical to the STRING "5n", and a non-finite number became
 * `null`, byte-identical to a literal null. A receipt is evidence of what
 * reached the sink; two different values must not leave identical evidence.
 * On-chain amounts are bigints, so this is the common case, not an edge.
 * Everything else renders exactly as before.
 *
 * This lives HERE, in gate, and deliberately not in the rail's `canonicalJSON`
 * (src/canon.ts): that function defines signed and hashed bytes for the whole
 * rail, and changing it would move every mandate signature (AGENTS.md, "One
 * canonicalization across the rail"). By the time a receipt reaches
 * `receiptBody` or a signer, its arguments are already plain JSON.
 */
const receiptJSON = (value: unknown): string | undefined =>
  JSON.stringify(value, (_key, v: unknown) =>
    typeof v === "bigint"
      ? { $bigint: `${v}` }
      : typeof v === "number" && !Number.isFinite(v)
        ? { $number: `${v}` }
        : v,
  )

const now = () => new Date().toISOString()

/** First line of an error's message — what a refusal reason quotes. */
const firstLine = (err: unknown): string => (err instanceof Error ? err.message : String(err)).split("\n")[0]!

/** receiptJSON that cannot throw — for the strings a REFUSAL carries, where a
 * value that will not serialize must be named rather than escalated. */
const show = (value: unknown): string => {
  try {
    return receiptJSON(value) ?? "undefined"
  } catch (err) {
    return `[unserializable: ${firstLine(err)}]`
  }
}

// ── Declassifiers (the three doors) ─────────────────────────────────────────

export type DeclassifyResult<T> =
  | { readonly ok: true; readonly value: Sourced<T> }
  | { readonly ok: false; readonly reason: string }

/**
 * Registry membership → Verified. An authority act: the value matches an
 * entry in a registry THIS deployment governs.
 *
 * The key is `Sourced` because it steers the ascent: it picks which record the
 * candidate is compared against, so a key the attacker wrote can pick the
 * attacker's own record. It must be `verified`, not merely corroborated:
 * accumulation never raises a value past `corroborated` (Rule 3a), and a
 * corroborated key that yielded a `verified` value would launder past that.
 * The registry row is held to the same bar, and it and the candidate must be
 * the gate's own values.
 */
export function allowlisted<T>(
  candidate: Sourced<T>,
  registry: ReadonlyMap<string, Sourced<T>>,
  key: Sourced<string>,
  registryName: string,
): DeclassifyResult<T> {
  // The brand comes first. Parsed JSON can say `tier: "verified"`, and a Proxy
  // could answer differently on a second read; neither carries the brand.
  if (!Sourced.is(key)) {
    throw new TypeError("allowlisted: key must be a Sourced<string> so the gate knows where it came from. Take it from a record your host holds, never from the message: wrapping a message-derived key in Sourced.fromAuthority defeats this check (SECURITY.md)")
  }
  // The key is read here and nowhere after. Its rendering is quoted because an
  // origin is a host-chosen string that can carry message text, and the evidence
  // is what an auditor reads.
  const { value: keyValue, tier: keyTier } = key
  const keyShown = show(key.describe())
  // Neither refusal echoes the key or its origin: either may be the attacker's text.
  if (!meetsTier(keyTier, "verified")) {
    return { ok: false, reason: `the key for ${registryName} is ${keyTier}; a key picks the record to compare against, so it must be verified` }
  }
  if (typeof keyValue !== "string") {
    return { ok: false, reason: `the key for ${registryName} is not a string` }
  }
  // A candidate or a row the gate did not mint is data arriving with a claim, so
  // it is refused rather than thrown on. No method on a forged candidate runs: its
  // `describe()` would write its own words into the evidence (DAN-1448).
  if (!Sourced.is(candidate)) {
    return { ok: false, reason: `the candidate for ${registryName} was not minted by the gate` }
  }
  const entry = registry.get(keyValue)
  if (entry === undefined) {
    return { ok: false, reason: `'${keyValue}' not in ${registryName}; candidate is ${candidate.describe()}` }
  }
  if (!Sourced.is(entry)) {
    return { ok: false, reason: `the ${registryName} record for this key was not minted by the gate` }
  }
  // Each Sourced is read once, here (AGENTS.md, "Intake"). The comparison
  // below and the ascent at the bottom both use these locals.
  const { value: entryValue, tier: entryTier, provenance: entryProvenance } = entry
  const { value: candidateValue } = candidate
  // The same rule as the key: a row below `verified` coming out `verified` would
  // launder past Rule 3a. Neither refusal echoes the record.
  if (!meetsTier(entryTier, "verified")) {
    return { ok: false, reason: `the ${registryName} record for this key is ${entryTier}; only a verified record can be promoted` }
  }

  // The comparison runs on the CANDIDATE, so it executes candidate-controlled
  // code (`toJSON`, getters) and can throw on a circular value. A declassifier
  // that throws is a declassifier that returned no verdict, which every caller
  // reads as an exception rather than a refusal. Refuse instead.
  //
  // The two sides are serialized SEPARATELY, through the gate's own
  // receiptJSON (the 2026-10-13 gate audit). One shared try blamed "the
  // candidate" whichever side threw, and JSON.stringify threw on every BigInt
  // — so a bigint registry record refused every candidate, honest or not, with
  // the wrong reason. receiptJSON renders a bigint as {"$bigint":"…"}; the
  // comparison is still an oracle whose answer decides nothing but
  // match/mismatch — what comes back is the registry's record, below.
  let entryJSON: string | undefined
  try {
    entryJSON = receiptJSON(entryValue)
  } catch (err) {
    return {
      ok: false,
      reason: `'${keyValue}' IS in ${registryName} but the ${registryName} record could not be serialized for comparison (${firstLine(err)}) — refusing rather than guessing; candidate is ${candidate.describe()}`,
    }
  }
  let candidateJSON: string | undefined
  try {
    candidateJSON = receiptJSON(candidateValue)
  } catch (err) {
    return {
      ok: false,
      reason: `'${keyValue}' IS in ${registryName} but the candidate could not be serialized for comparison (${firstLine(err)}) — refusing rather than guessing`,
    }
  }
  if (entryJSON !== candidateJSON) {
    return {
      ok: false,
      reason: `'${keyValue}' IS in ${registryName} but the ${registryName} record does NOT match — candidate is ${candidate.describe()}`,
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
    value: ascend({ value: entryValue, provenance: entryProvenance }, {
      declassifier: "allowlisted",
      from: entryTier,
      to: "verified",
      evidence: `matched ${registryName}[${show(keyValue)}] by key ${keyShown} — candidate presented was ${candidate.describe()}`,
      at: now(),
    }),
  }
}

/**
 * Agreement of two INDEPENDENT sources → Corroborated — never Verified
 * (Rule 3a: accumulation is not authority). Independence = disjoint
 * ancestry (Rule 3b): a value corroborated against something derived from
 * itself has learned nothing. A claim already at or above corroborated is
 * returned unchanged: accumulation never lowers a tier either.
 */
export function corroborate<T>(
  claim: Sourced<T>,
  reference: Sourced<T>,
  // The default compares the gate's own JSON (so a BigInt compares instead of
  // throwing — the 2026-10-13 gate audit) and requires the same `typeof` first,
  // so the bigint 5n never agrees with an object that merely renders as
  // {"$bigint":"5"}, and `undefined` never agrees with a function.
  equals: (a: T, b: T) => boolean = (a, b) => typeof a === typeof b && receiptJSON(a) === receiptJSON(b),
): DeclassifyResult<T> {
  // Each Sourced is read once, here (AGENTS.md, "Intake"): the independence
  // check, the comparison, the ceiling check and the ascent all use these.
  const { value: liveClaim, tier: claimTier, provenance: claimProvenance } = claim
  const { value: liveReference, provenance: referenceProvenance } = reference
  for (const a of claimProvenance.ancestors) {
    if (referenceProvenance.ancestors.has(a)) {
      return { ok: false, reason: `sources are NOT independent (shared ancestor: ${a})` }
    }
  }
  // The judged path's rule (the 2026-11-08 audit, G2). A value with a `toJSON`
  // or a getter compared as one thing and was promoted as another, and the
  // receipt recorded the good one. Plain JSON has no code in it, so what is
  // compared is what it is, and the frozen copy compared is the copy promoted.
  // The reasons are fixed strings: what was refused is caller-shaped.
  let claimValue: T
  let referenceValue: T
  try {
    claimValue = pinPlainJSON(liveClaim)
  } catch {
    return { ok: false, reason: `could not compare — the claim is not plain JSON; claim ${claim.describe()}` }
  }
  try {
    referenceValue = pinPlainJSON(liveReference)
  } catch {
    return { ok: false, reason: `could not compare — the reference is not plain JSON; reference ${reference.describe()}` }
  }
  // `equals` is caller code over caller values; if it throws it has given no
  // verdict, and no verdict is a refusal, never an exception.
  let agree: boolean
  try {
    agree = equals(claimValue, referenceValue)
  } catch (err) {
    return {
      ok: false,
      reason: `could not compare — equals threw (${firstLine(err)}); claim ${claim.describe()} vs reference ${reference.describe()}`,
    }
  }
  if (!agree) {
    return {
      ok: false,
      reason: `values disagree — claim ${show(claimValue)} (${claim.describe()}) vs reference ${show(referenceValue)} (${reference.describe()})`,
    }
  }
  // Rule 3a cuts both ways: accumulation never raises a value PAST
  // corroborated, and it never LOWERS one. This used to ascend unconditionally,
  // so a verified claim checked against an agreeing untrusted reference came
  // back "corroborated" with a from:verified→to:corroborated event on its
  // chain — an email demoting an authority's record, recorded as an ascent
  // (the 2026-10-13 gate audit). A claim already at or above corroborated has
  // nothing to gain here and comes back as itself. The two checks above still
  // ran: `ok` means the sources agree and are independent, whatever the tier.
  if (meetsTier(claimTier, "corroborated")) {
    return { ok: true, value: claim }
  }
  const merged = new Set([...claimProvenance.ancestors, ...referenceProvenance.ancestors])
  return {
    ok: true,
    value: ascend(
      { value: claimValue, provenance: claimProvenance },
      {
        declassifier: "corroborate",
        from: claimTier,
        to: "corroborated",
        evidence: `agrees with independent source ${referenceProvenance.origin}`,
        at: now(),
      },
      merged,
    ),
  }
}

/** How much of a candidate's JSON humanConfirm puts in front of the human. */
const HUMAN_CONFIRM_VALUE_CHARS = 256

/**
 * Human confirmation → Verified. The provenance is RENDERED to the human
 * (Confirmation fatigue is an attack vector — the human must see what
 * they are actually vouching for, not "Confirm? y/n"). It is rendered FIRST,
 * before the value, and the value is bounded — see the body.
 *
 * ASYNC SINCE 0.5.0. A human who answers over a network (a phone, a voice
 * call, a chat approval) answers later, so `render` may return a boolean or a
 * Promise of one, and the verdict is always a Promise. Three properties ride
 * on that shape; do not trade them for convenience:
 *
 * - The candidate's value is COPIED (`structuredClone`) and the question is
 *   built from the copy SYNCHRONOUSLY, at the call, before the first `await`.
 *   The copy is what ascends, so the value the human is asked about is the
 *   value that ascends, however long the human takes and whatever the caller
 *   does to its own object meanwhile. A value that cannot be cloned (a
 *   function, a symbol, a proxy) is refused. A class instance does NOT
 *   throw: it ascends as a plain object of its own enumerable fields, and
 *   its methods and `#private` fields are dropped silently.
 * - The return is a Promise even for a synchronous `render`. A caller who
 *   forgets `await` holds a Promise, whose `.ok` is `undefined`, so the
 *   forgotten await reads as a refusal. Overloads that hand a sync renderer a
 *   sync result would make the same mistake silent in one shape and loud in
 *   the other; one shape keeps it fail-closed in both.
 * - A `render` that throws or rejects has given no answer, and no answer is a
 *   refusal, never an exception (as `corroborate`'s throwing `equals` is).
 *
 * The caller owns the wait. A render that never settles never confirms;
 * reject it from your own timeout to turn silence into a refusal.
 */
export async function humanConfirm<T>(
  candidate: Sourced<T>,
  render: (question: string) => boolean | Promise<boolean>,
): Promise<DeclassifyResult<T>> {
  // The PROVENANCE leads and the VALUE trails, cut to 256 characters with its
  // full length declared. The question used to open with the value — attacker-
  // controlled, any length — so a value beginning "… — provenance: VERIFIED
  // (origin: authority:payee-registry)?" followed by 4,000 spaces put a forged
  // provenance where a one-line renderer shows it and the real one off-screen
  // (the 2026-10-13 gate audit). The provenance string is ours; it goes first.
  // Through receiptJSON, in a try: JSON.stringify threw on a bigint candidate
  // and the human never saw a question (the 2026-10-13 gate audit). A value
  // that cannot be rendered cannot be confirmed — refuse, naming why.
  // The candidate is read once, here (AGENTS.md, "Intake"): the question and
  // the ascent both use these locals.
  const { value: liveValue, tier: candidateTier, provenance: candidateProvenance } = candidate
  // SNAPSHOT, not a reference. A Sourced is frozen, but the object it carries
  // is not (only `fromAuthority` freezes its value), and whoever handed it in
  // still holds that object. Once a human answers over a network, the await
  // below can last minutes, and a reference would let the holder rewrite the
  // value after the human saw it: shown "GB00-ALICE", promoted "DE99-EVIL"
  // (found in the 0.5.0 review, test/gate/human-confirm-async.test.ts). The
  // question and the ascent both read this private copy, so the value the
  // human is asked about is the value that ascends. A value structuredClone
  // cannot copy (a function, a symbol, a proxy) cannot be pinned, so it
  // cannot be confirmed: refuse, naming why. A class instance is not refused:
  // structuredClone copies its own enumerable fields into a plain object and
  // drops its methods and `#private` fields silently. The question is built
  // from that same copy, so the human sees what ascends; a class whose meaning
  // lives in private state should be confirmed as an explicit data object.
  let candidateValue: T
  try {
    candidateValue = structuredClone(liveValue)
  } catch (err) {
    return {
      ok: false,
      reason: `human confirmation refused: the candidate (${candidate.describe()}) could not be copied for confirmation (${firstLine(err)})`,
    }
  }
  let json: string
  try {
    json = receiptJSON(candidateValue) ?? "undefined"
  } catch (err) {
    return {
      ok: false,
      reason: `human confirmation refused: the candidate (${candidate.describe()}) could not be rendered for the question (${firstLine(err)})`,
    }
  }
  const shown =
    json.length > HUMAN_CONFIRM_VALUE_CHARS
      ? `${json.slice(0, HUMAN_CONFIRM_VALUE_CHARS)}… [${json.length} chars total; first ${HUMAN_CONFIRM_VALUE_CHARS} shown]`
      : json
  const question = `Confirm the value with provenance ${candidate.describe()} — value: ${shown}?`
  // Everything above ran synchronously, at the call. The await below is the
  // first point at which time passes; nothing after it reads `candidate`.
  //
  // A throw and a rejection land in the same catch: either way the renderer
  // returned no answer, and no answer is a refusal (fail closed), never an
  // exception the caller might read as an outage and retry around.
  let answer: unknown
  try {
    answer = await render(question)
  } catch (err) {
    // The rejection reason is caller-controlled too: `String()` of a
    // null-prototype object throws, and a throw from here would turn the
    // refusal back into the exception this catch exists to prevent.
    let why: string
    try {
      why = firstLine(err)
    } catch {
      why = "a reason that could not be rendered"
    }
    return {
      ok: false,
      reason: `human confirmation refused: render() threw or rejected before an answer (${why}): ${question}`,
    }
  }
  // `!== true`, not `!`: only the literal true is a confirmation. The string
  // "no" is truthy, and so was an unawaited Promise when this function was
  // synchronous; either used to mint verified before the human had answered
  // (the 2026-10-13 gate audit). The Promise is now awaited, so what is tested
  // here is the human's settled answer, and it must still be exactly `true`.
  if (answer !== true) {
    return { ok: false, reason: `human declined (render() must return or resolve to exactly true): ${question}` }
  }
  return {
    ok: true,
    value: ascend({ value: candidateValue, provenance: candidateProvenance }, {
      declassifier: "humanConfirm",
      from: candidateTier,
      to: "verified",
      evidence: "human confirmed with provenance rendered",
      at: now(),
    }),
  }
}

// ── Receipts (SweeVerify's lowercase artifact) ──────────────────────────────
// Hash-chained decision log: every sink invocation — allowed OR refused —
// appends an event whose hash covers the previous hash. Tamper-evident by
// construction; Ed25519 signing is the next layer up (sweetrust/verify's
// SignedReceiptLog wraps this class — wrap, never fork).

export interface Receipt {
  readonly seq: number
  readonly at: string
  readonly sink: string
  /**
   * `errored` (added 2026-07-25) records an operation that PASSED the walls and
   * then threw. Without it the log has a hole shaped like "everything that went
   * wrong" — see makeSink. The action may or may not have taken effect; that
   * uncertainty is the point of recording it. For an ASYNC action it follows
   * the `executed` (or `judgment-flagged`) receipt rather than replacing it:
   * the first receipt precedes the outcome, the `errored` one trails it.
   *
   * `declassify-refused` is RESERVED, not yet produced (DAN-1159 item 4b). It
   * is the evidence a declassifier's refusal should leave. Today the
   * declassifiers take no log, so a refused ascent records nothing (SECURITY.md,
   * "A declassifier's refusal leaves no receipt"). The member exists before the
   * first publish because adding one later breaks every exhaustive switch;
   * emitting it through an optional log is additive and can follow.
   *
   * `judgment-held` (0.6.0) is doubt in enforce mode: nothing ran, and the
   * action waits for an owner. `judgment-flagged` is the same doubt in observe
   * or warn, where the action runs anyway; enforce never writes it.
   *
   * `attempted` (0.6.0, ADR 0010) is a judged enforce action's intent record,
   * written with the verdict BEFORE `execute`. Its presence means the action
   * may have run, so a log write that fails afterward cannot make the action,
   * or the approval that released it, reusable.
   */
  readonly decision:
    | "attempted" | "executed" | "refused" | "observed" | "warned"
    | "judgment-blocked" | "judgment-flagged" | "judgment-held" | "errored"
    | "declassify-refused"
  readonly args: Record<string, { value: unknown; tier: Tier; provenance: string }>
  readonly reason?: string
  /**
   * The verdict exactly as digested, so a verifier can recompute
   * `verdictDigest` from the receipt alone (ADR 0009). Present on every receipt
   * a judge's answer, or its failure to answer, decided. Absent, never null, on
   * every other receipt, which is what keeps those hashing as in 0.5.0.
   */
  readonly verdict?: Verdict
  /**
   * The owner's approval, on the receipt of the execution it released: the
   * `executed` one, and an `errored` one too when that attempt failed. Absent
   * otherwise.
   */
  readonly approval?: Approval
  readonly prevHash: string
  readonly hash: string
}

/**
 * The exact bytes ReceiptLog hashes for a receipt — the single definition of the
 * interior-hash serialization. Exported so verifiers (sweetrust/verify) recompute
 * hashes from this function instead of hand-mirroring it across packages.
 *
 * Canonical JSON (src/canon.ts): keys sorted at EVERY depth, no whitespace,
 * the same bytes the signature and the wrapper link are computed over. Until
 * the 2026-10-13 rail audit this was `JSON.stringify` of a hand-ordered
 * literal, which pinned its top-level keys and nothing beneath them: `args` is a
 * tree of caller-shaped objects, so its bytes followed insertion order, and an
 * honest exportJSONL artifact run through `jq -S` came back `hash-mismatch`.
 * Every receipt hash changed with this; a 0.3.0 log does not verify under
 * 0.4.0 (CHANGELOG, docs/adr/0002). A `reason` of undefined is dropped by
 * canonicalJSON exactly as the old conditional spread dropped it, and each
 * field is read from `e` once.
 *
 * `verdict` and `approval` are the two optional keys added in 0.6.0 (ADR 0009).
 * canonicalJSON drops an undefined key and keeps a null one, so a receipt that
 * omits them hashes byte for byte as in 0.5.0, and a sink must omit them,
 * never write null.
 */
export function receiptBody(e: Omit<Receipt, "hash">): string {
  return canonicalJSON({
    seq: e.seq,
    prevHash: e.prevHash,
    at: e.at,
    sink: e.sink,
    decision: e.decision,
    args: e.args,
    reason: e.reason,
    verdict: e.verdict,
    approval: e.approval,
  })
}

/** Freeze an object graph in place. `seen` guards against a cyclic graph handed
 * straight to append(): receiptBody() rejects one before commit() runs, but
 * a `toJSON` can hide a cycle from JSON.stringify and not from a walk. */
function deepFreeze<T>(root: T, seen = new WeakSet<object>()): T {
  if (typeof root !== "object" || root === null || seen.has(root)) return root
  seen.add(root)
  Object.freeze(root)
  for (const v of Object.values(root)) deepFreeze(v, seen)
  return root
}

/** Everything a receipt may hold: `receiptBody`'s nine fields and the hash. A tenth key would sit outside the hash. */
const RECEIPT_KEYS: ReadonlyArray<string> = ["seq", "prevHash", "at", "sink", "decision", "args", "reason", "verdict", "approval", "hash"]

/** Each row read once and deep-copied, so a loaded log shares nothing with its caller. */
export function snapshotRows<T>(rows: ReadonlyArray<T>): T[] {
  return rows.map((row, i) => {
    if (typeof row !== "object" || row === null || Array.isArray(row)) throw new TypeError(`row ${i} is not a record`)
    try {
      return structuredClone({ ...row })
    } catch {
      throw new TypeError(`row ${i} is not plain data`)
    }
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
   * per record — sweetrust/verify signs each one — can do that work before
   * anything lands. The old shape committed first and let the subclass sign
   * second, so a signing failure left the interior chain one ahead of the
   * signed chain, permanently, with every later wrapper link built on a stale
   * predecessor and the exported artifact silently short a receipt.
   */
  protected nextReceipt(entry: Omit<Receipt, "seq" | "prevHash" | "hash">): Receipt {
    const prevHash = this.events.at(-1)?.hash ?? "genesis"
    const seq = this.events.length
    // The entry is spread FIRST and the log's three fields are set after it.
    // The other order let an entry that carried `seq`, `prevHash` or `hash`
    // replace the log's own (the 2026-10-13 gate audit): `Omit<>` hides those
    // fields from TypeScript, not from JavaScript.
    //
    // Spread ONCE. This used to spread the entry into the hashed body and then
    // spread it AGAIN into the committed receipt, so a getter on the entry
    // could answer the hash with one value and the record with another, and
    // the log then held a receipt whose own hash did not cover it (the
    // 2026-10-13 rail audit, caught by test/intake-poison.test.ts). The
    // snapshot that is hashed is the snapshot that is committed.
    const snapshot = { ...entry, seq, prevHash }
    const hash = createHash("sha256").update(receiptBody(snapshot)).digest("hex")
    return { ...snapshot, hash }
  }

  /**
   * Commit a receipt from nextReceipt(). The only mutation point.
   *
   * The receipt is deep-frozen here (the 2026-10-13 gate audit). all() has
   * returned a COPY of the array since A5, but the elements were the log's own
   * objects, so anyone holding one could edit it in place — and the sharp
   * version, `receipt.args = { toJSON: () => original }`, hid an argument from
   * the in-memory receipt while receiptBody() still serialized the original and
   * verifyChain() stayed green. What append() returns and what all() hands out
   * is now one frozen object, and nothing holding it can change what the log
   * says. A receipt's args are plain JSON trees by the time they get here.
   */
  protected commit(receipt: Receipt): Receipt {
    this.events.push(deepFreeze(receipt))
    this.appended++
    return receipt
  }

  append(entry: Omit<Receipt, "seq" | "prevHash" | "hash">): Receipt {
    return this.commit(this.nextReceipt(entry))
  }

  /**
   * Load prior receipts into this empty log, after checking them as one chain
   * from genesis. The rows must already be this log's own snapshots.
   */
  protected load(rows: ReadonlyArray<Receipt>): void {
    if (this.events.length !== 0) throw new TypeError("a log can only be seeded while it is empty")
    let prevHash = "genesis"
    rows.forEach((row, i) => {
      const stray = Object.keys(row).filter((k) => !RECEIPT_KEYS.includes(k))
      if (stray.length > 0) throw new TypeError(`receipt ${i} carries a key outside its hash`)
      if (row.seq !== i || row.prevHash !== prevHash || sha256Hex(receiptBody(row)) !== row.hash) {
        throw new TypeError(`receipt ${i} does not continue the chain`)
      }
      prevHash = row.hash
    })
    for (const row of rows) this.commit(row)
  }

  /**
   * A log that continues from `receipts`, for a process that restarts: without
   * it a new log is empty, and every block, hold and attempt it held is gone
   * (ADR 0010). The chain is checked first and any break is a TypeError. Each
   * row is read once and copied. It proves only that the rows are internally
   * consistent: a list missing its newest rows loads as a valid shorter chain.
   * For a signed log use `SignedReceiptLog.fromSigned`.
   */
  static fromReceipts<T extends ReceiptLog>(this: new () => T, receipts: ReadonlyArray<Receipt>): T {
    if (!Array.isArray(receipts)) throw new TypeError("fromReceipts: receipts must be an array")
    const log = new this()
    log.load(snapshotRows(receipts))
    return log
  }

  /** A copy. Handing out the live array let any caller push, splice, or truncate. */
  all(): ReadonlyArray<Receipt> {
    return [...this.events]
  }

  /** The head hash — what an external anchor (sweetrust/verify) commits to. */
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
   * commitment to the head; that is sweetrust/verify's job, not this class's.
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

// ── The intent digests (spec § 3.2) ──────────────────────────────────────────
// Three hashes link a judged action across the gate, the mandate log and the
// chain. Each must name ONE value, and canonicalJSON is built to match
// JSON.stringify, which quietly maps several values onto one output: NaN and
// null, -0 and 0, a Map and {}, a Date and its ISO string, a hole and null, a
// toJSON carrier and whatever it returns. Two different actions under one
// digest is an approval that travels. So the copy below accepts only what
// survives canonicalJSON and JSON.parse unchanged, and throws on the rest,
// rather than extending canonicalJSON (one canonicalization across the rail).
//
// Messages are fixed strings: a key or a value here is caller-controlled, and
// a refusal string ends up in receipts and in front of models.

export interface Action {
  readonly sink: string
  readonly args: Readonly<Record<string, unknown>>
  /**
   * Set by the host, never by the agent (ADR 0010): what makes a repeat of this
   * action a new payment rather than a duplicate. Absent, the digest is the
   * digest of `{ sink, args }` alone.
   */
  readonly idempotencyKey?: string
}

export interface Payment {
  readonly network: string
  readonly asset: string
  readonly recipient: string
  readonly amount: bigint | string
}

export interface Verdict {
  readonly assessment: "match" | "mismatch" | "unsure"
  readonly confidence: number
  readonly rationaleHash: string
  readonly provider: string
  readonly model: string
  /** The action this verdict names and an approval releases, its idempotency key included. */
  readonly actionDigest: string
  /** The same action as if it carried no key: what a block or a hold sticks to (ADR 0010). */
  readonly unkeyedActionDigest: string
  /** False when the judge gave no answer: the `unsure` here is the gate's, and it does not stick (ADR 0010). */
  readonly scored: boolean
  readonly paymentDigest: string | null
  readonly grantHash: string
  /** `purposeHash` of the purpose the judge scored: the text, where `grantHash` names the grant (ADR 0010). */
  readonly purposeHash: string
  readonly judgedAt: string
  readonly attestation: null
}

/**
 * An owner's signed answer to a held action, as recorded on the receipt of the
 * execution it released (spec § 3.3, I11). `signature` is 128 lowercase hex,
 * Ed25519 by the sink's `approvalKey`, over `canonicalJSON` of the other four
 * fields plus `domain: "sweetrust/approval@1"`. `expiresAt` is exactly
 * `Date.prototype.toISOString` output.
 */
export interface Approval {
  readonly verdictDigest: string
  readonly actionDigest: string
  readonly grantHash: string
  readonly expiresAt: string
  readonly signature: string
}

/** What a held result hands back: the three digests an owner's approval must name. */
export interface HeldAction {
  /** Set when this hold was made under a different idempotency key; resume under that key. */
  readonly underAnotherKey?: true
  readonly verdictDigest: string
  readonly actionDigest: string
  readonly grantHash: string
}

/** How a payment names the verdict it ran under. `paymentDigest` is null when the sink names no `purposeArgs`. */
export interface AuthorizedBy {
  readonly verdictDigest: string
  readonly paymentDigest: string | null
}

// ── Spend authorization (ADR 0010) ───────────────────────────────────────────

/** The result of `SpendAuthorization.consume`. A failure names why, never a value. */
export type SpendAuthorizationResult =
  | { readonly ok: true; readonly authorizedBy: AuthorizedBy }
  | { readonly ok: false; readonly reason: "not-issued" | "already-consumed" | "wrong-payment" }

const ISSUE_AUTHORIZATION = Symbol("sweetrust/gate: a SpendAuthorization is issued only by a sink")
let issueAuthorization: (authorizedBy: AuthorizedBy) => SpendAuthorization

/**
 * One execution's authority to pay, handed to `execute` by the sink and spent
 * once by whatever moves the money (`spend` in sweetrust-sui). A digest typed
 * by a caller is not one: a value that did not come through this class's
 * constructor is refused, the same brand check `Sourced` uses, and a genuine
 * one works once.
 *
 * Issued only to an action that a confident match or an owner's approval let
 * through, never to a flagged one in warn or observe.
 *
 * In-process only, like every other kernel guarantee (SECURITY.md): code that
 * can import this module and holds an execute context holds the token.
 */
export class SpendAuthorization {
  #spent = false
  readonly authorizedBy: AuthorizedBy

  private constructor(token: typeof ISSUE_AUTHORIZATION, authorizedBy: AuthorizedBy) {
    if (token !== ISSUE_AUTHORIZATION) throw new TypeError("a SpendAuthorization is issued by a sink, never constructed")
    this.authorizedBy = authorizedBy
    Object.freeze(this)
  }

  static {
    issueAuthorization = (authorizedBy) => new SpendAuthorization(ISSUE_AUTHORIZATION, authorizedBy)
  }

  static is(x: unknown): x is SpendAuthorization {
    return typeof x === "object" && x !== null && #spent in x
  }

  /**
   * Spend the token on the payment named by `paymentDigest`. Exactly one call
   * for a genuine token and its own payment returns ok; a token presented for
   * a different payment, or with no payment named, is not spent.
   */
  static consume(token: unknown, paymentDigest: string): SpendAuthorizationResult {
    if (!SpendAuthorization.is(token)) return { ok: false, reason: "not-issued" }
    if (typeof paymentDigest !== "string" || token.authorizedBy.paymentDigest !== paymentDigest) return { ok: false, reason: "wrong-payment" }
    if (token.#spent) return { ok: false, reason: "already-consumed" }
    token.#spent = true
    return { ok: true, authorizedBy: token.authorizedBy }
  }
}

Object.freeze(SpendAuthorization)
Object.freeze(SpendAuthorization.prototype)

interface Walk {
  /** Encode bigints as {"$bigint":"<decimal>"} (and so refuse that key raw), or refuse them. */
  readonly bigints: boolean
  /** The containers currently being walked: a repeat is a cycle, a shared reference is not. */
  readonly path: Set<object>
}

function assertRecord(value: unknown, what: string): asserts value is object {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${what} must be a plain object`)
  }
  const proto: unknown = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) throw new TypeError(`${what} must be a plain object`)
}

/** The one read of an own, enumerable data property. An accessor is refused without being run. */
const ownValue = (owner: object, key: string): unknown => {
  const d = Reflect.getOwnPropertyDescriptor(owner, key)
  if (d === undefined || !("value" in d) || !d.enumerable) {
    throw new TypeError("not plain JSON: a missing, accessor or non-enumerable property")
  }
  return d.value
}

const copyJSON = (value: unknown, walk: Walk): unknown => {
  switch (typeof value) {
    case "string":
    case "boolean":
      return value
    case "number":
      if (!Number.isFinite(value) || Object.is(value, -0)) throw new TypeError("not plain JSON: a non-finite number or -0")
      return value
    case "bigint":
      if (!walk.bigints) throw new TypeError("not plain JSON: a bigint")
      // String(), not .toString(): it does not go through BigInt.prototype.
      return { $bigint: String(value) }
    case "object": {
      if (value === null) return null
      if (walk.path.has(value)) throw new TypeError("not plain JSON: a cycle")
      walk.path.add(value)
      const copy = Array.isArray(value) ? copyArray(value, walk) : copyRecord(value, walk)
      walk.path.delete(value)
      return copy
    }
    default:
      throw new TypeError("not plain JSON: undefined, a function or a symbol")
  }
}

const copyArray = (value: readonly unknown[], walk: Walk): unknown[] => {
  if (Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError("not plain JSON: an array subclass")
  const length = value.length
  // Own keys are the indices plus `length`, so this refuses a hole and an extra
  // key alike, and refuses new Array(2 ** 32 - 1) without walking it.
  if (Reflect.ownKeys(value).length !== length + 1) throw new TypeError("not plain JSON: a sparse array or an array with extra keys")
  const out: unknown[] = []
  for (let i = 0; i < length; i++) out.push(copyJSON(ownValue(value, String(i)), walk))
  return out
}

const copyRecord = (value: object, walk: Walk): Record<string, unknown> => {
  assertRecord(value, "not plain JSON: a value")
  const entries: Array<[string, unknown]> = []
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === "symbol") throw new TypeError("not plain JSON: a symbol key")
    if (walk.bigints && key === "$bigint") throw new TypeError("a raw $bigint key collides with the bigint encoding")
    entries.push([key, copyJSON(ownValue(value, key), walk)])
  }
  // fromEntries defines own properties, so a "__proto__" key stays data. An
  // assignment here would set the copy's prototype.
  return Object.fromEntries(entries)
}

/** Nesting deeper than the stack is one more malformed input: a TypeError like the rest. */
const refusingOverflow = <T>(run: () => T): T => {
  try {
    return run()
  } catch (e) {
    if (e instanceof RangeError) throw new TypeError("not plain JSON: nested too deeply or too large")
    throw e
  }
}

const copyExact = (value: unknown, bigints: boolean): unknown =>
  refusingOverflow(() => copyJSON(value, { bigints, path: new Set() }))

/**
 * A deep-frozen copy of a value that must be plain JSON, bigints allowed; throws
 * on anything else. The check reads the ORIGINAL first, because structuredClone
 * hides what it must refuse: it runs a getter and keeps the answer, and it
 * flattens a class instance into a plain object. Only a value that is already
 * plain JSON gets cloned, and structuredClone then throws on a Proxy.
 */
function pinPlainJSON<T>(value: T): T {
  copyExact(value, true)
  return deepFreeze(structuredClone(value))
}

/** A decimal-integer amount, as `paymentDigest` and the purpose check both accept it. */
const DECIMAL_INTEGER = /^[0-9]+$/
/** What the agent is told by default: a block and a hold read alike (ADR 0010). */
const STOPPED_BY_JUDGMENT = "stopped by judgment"
/** The one spelling a sink accepts for a string amount. */
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/

const digestOf = (value: unknown): string => refusingOverflow(() => sha256Hex(canonicalJSON(value)))

/**
 * Replace each bigint in an action, at any depth, with {"$bigint":"<decimal>"},
 * so that canonicalJSON can take it. Returns a fresh copy sharing nothing with
 * the input. Throws a TypeError on a raw `$bigint` key (it would collide with
 * the encoding) and on anything that is not plain JSON.
 */
export function encodeAction(action: Action): Action {
  assertRecord(action, "an action")
  const keyCount = Reflect.ownKeys(action).length
  if (keyCount !== 2 && keyCount !== 3) throw new TypeError("an action is exactly { sink, args }, with an optional idempotencyKey")
  const sink = ownValue(action, "sink")
  const args = ownValue(action, "args")
  if (typeof sink !== "string") throw new TypeError("an action's sink must be a string")
  assertRecord(args, "an action's args")
  const encoded = copyExact(args, true) as Action["args"]
  if (keyCount === 2) return { sink, args: encoded }
  const idempotencyKey = ownValue(action, "idempotencyKey")
  if (typeof idempotencyKey !== "string" || idempotencyKey.length === 0) throw new TypeError("an action's idempotencyKey must be a non-empty string")
  return { sink, args: encoded, idempotencyKey }
}

/**
 * sha256Hex(canonicalJSON(encodeAction(action))). A sink that names `purposeArgs`
 * digests a bigint amount as its decimal string first, so this over a bigint amount
 * differs from that sink's digest.
 */
export function actionDigest(action: Action): string {
  return digestOf(encodeAction(action))
}

/**
 * The digest of a payment's four parts; any other field on the argument is
 * ignored. The kernel has no chain knowledge and normalizes nothing: the
 * strings are hashed as given, so a non-canonical address or a zero-padded
 * amount simply fails to match the adapter's own recomputation, which is the
 * fail-closed path the spec wants. A bigint amount must be non-negative, like
 * the string form.
 */
export function paymentDigest(payment: Payment): string {
  const { network, asset, recipient, amount } = payment as { [K in keyof Payment]: unknown }
  if (typeof network !== "string" || typeof asset !== "string" || typeof recipient !== "string") {
    throw new TypeError("a payment's network, asset and recipient must be strings")
  }
  if (typeof amount === "bigint" ? amount < 0n : typeof amount !== "string" || !DECIMAL_INTEGER.test(amount)) {
    throw new TypeError("a payment's amount must be a non-negative bigint or decimal-integer string")
  }
  return digestOf({ network, asset, recipient, amount: String(amount) })
}

/** sha256Hex(canonicalJSON(verdict)), over a copy that must be plain JSON. */
export function verdictDigest(verdict: Verdict): string {
  assertRecord(verdict, "a verdict")
  return digestOf(copyExact(verdict, false))
}

/** sha256Hex(canonicalJSON(purpose)), over a copy that must be plain JSON. What a verdict's `purposeHash` must equal. */
export function purposeHash(purpose: Purpose): string {
  return digestOf(copyExact(purpose, false))
}

// ── Owner approval (spec § 3.3, I11) ─────────────────────────────────────────
// The agent already holds the verdict digest from the held result, so anything
// it could produce cannot release a hold. A signature by a key it never sees can.

const APPROVAL_DOMAIN = "sweetrust/approval@1"
const APPROVAL_WINDOW_MS = 15 * 60 * 1000
/** How long a block stands unless the sink says otherwise (ADR 0010): long enough that a retry loop learns nothing. */
const DEFAULT_BLOCK_WINDOW_MS = 60 * 60 * 1000
const HEX_64 = /^[0-9a-f]{64}$/
const HEX_128 = /^[0-9a-f]{128}$/

/**
 * Pin the owner's key at construction. Every spelling but the one exact SPKI-DER
 * hex is refused, so a key that was mistyped is one line from its cause rather
 * than a sink that can never resume.
 */
function bindApprovalKey(where: string, raw: unknown, log: ReceiptLog): KeyObject | undefined {
  if (raw === undefined) return undefined
  if (typeof raw !== "string" || raw.length % 2 !== 0 || !/^[0-9a-f]+$/.test(raw)) {
    throw new TypeError(`${where}: judgment.approvalKey must be lowercase SPKI-DER hex, got ${preview(raw)}`)
  }
  let key: KeyObject
  try {
    key = createPublicKey({ key: Buffer.from(raw, "hex"), format: "der", type: "spki" })
  } catch (err) {
    throw new TypeError(`${where}: judgment.approvalKey is not an SPKI-DER public key (${firstLine(err)})`)
  }
  if (key.asymmetricKeyType !== "ed25519" || key.export({ format: "der", type: "spki" }).toString("hex") !== raw) {
    throw new TypeError(`${where}: judgment.approvalKey must be exactly one Ed25519 public key in SPKI-DER hex`)
  }
  // The held receipt is looked up in the log, so a log that cannot be read back
  // could never honor an approval. That is a misconfiguration, found here.
  if (typeof (log as { all?: unknown }).all !== "function") {
    throw new TypeError(`${where}: judgment.approvalKey needs a log with an all() method, to find the held receipt`)
  }
  return key
}

/**
 * Read an approval once, own data properties only, and refuse the shape of
 * anything that is not exactly the five fields. An accessor is refused without
 * being run, so what is verified and what lands on the receipt are the same
 * values: this fresh object. A field the signature does not cover has nowhere
 * to ride.
 */
function readApproval(raw: unknown): Approval | undefined {
  try {
    assertRecord(raw, "an approval")
    if (Reflect.ownKeys(raw).length !== 5) return undefined
    const verdictDigest = ownValue(raw, "verdictDigest")
    const actionDigest = ownValue(raw, "actionDigest")
    const grantHash = ownValue(raw, "grantHash")
    const expiresAt = ownValue(raw, "expiresAt")
    const signature = ownValue(raw, "signature")
    if (typeof verdictDigest !== "string" || !HEX_64.test(verdictDigest)) return undefined
    if (typeof actionDigest !== "string" || !HEX_64.test(actionDigest)) return undefined
    if (typeof grantHash !== "string" || !HEX_64.test(grantHash)) return undefined
    if (typeof expiresAt !== "string") return undefined
    if (typeof signature !== "string" || !HEX_128.test(signature)) return undefined
    return Object.freeze({ verdictDigest, actionDigest, grantHash, expiresAt, signature })
  } catch {
    return undefined
  }
}

/** The signature, over bytes built here from the snapshot. `domain` is ours, never the caller's. */
function approvalSigned(approval: Approval, key: KeyObject): boolean {
  const { verdictDigest, actionDigest, grantHash, expiresAt, signature } = approval
  const body = canonicalJSON({ domain: APPROVAL_DOMAIN, verdictDigest, actionDigest, grantHash, expiresAt })
  try {
    return verifySignature(null, Buffer.from(body), key, Buffer.from(signature, "hex"))
  } catch {
    return false
  }
}

/** Only the exact form `toISOString` writes. Date.parse alone also accepts "Nov 8 2026" and friends. */
const strictInstant = (s: string): number | undefined => {
  const ms = Date.parse(s)
  return Number.isFinite(ms) && new Date(ms).toISOString() === s ? ms : undefined
}

// ── Judgment seam (complement, never compete) ────────────────────────────────
// Trust tiers + the cage catch bad PEDIGREE and out-of-bounds actions. Neither
// catches "in-bounds but WRONG": a payment in-budget, to an allowlisted payee,
// that still isn't what the principal meant. That gap is judgment's job — a
// calibrated model scoring the action against declared intent. Two rules govern
// it: (1) judgment is FALLIBLE (it can be fooled), so it must
// never be the only wall; (2) judgment is SELF-AWARE (it reports calibrated
// confidence and, crucially, says "unsure") — in enforce mode an unsure verdict
// holds the action for a human; it neither runs it nor confidently blocks it.
// We CONSUME judgment via this seam; this package does not ship a judgment model.

export interface JudgmentVerdict {
  readonly assessment: "match" | "mismatch" | "unsure"
  readonly confidence: number // [0,1] — calibrated: high when right, low when wrong
  readonly rationale: string
}

/**
 * A judge. Asynchronous since 0.6.0 (ADR 0007): a judge is a model behind a
 * network call or an inference step, and its answer arrives later.
 *
 * `input` has three keys: the owner's purpose, the action as raw values, and
 * `trust`, each argument's tier and provenance. The agent's own rationale never
 * reaches a judge, but an argument can hold text an agent wrote, so a judge
 * must read `action.args` as data and weigh each one by its `trust` entry. The
 * signal fires at the sink's deadline, and an answer that arrives after it is
 * discarded, so a provider that cannot finish should stop rather than keep
 * spending.
 */
export interface JudgmentProvider {
  readonly name: string
  /** The pinned model version, for example "jev@2026-09-15". Empty is a TypeError at sink construction. */
  readonly model: string
  /** Score a proposed action against the owner's purpose. */
  assess(input: JudgmentInput, signal: AbortSignal): Promise<JudgmentVerdict>
}

/** What a judge is told about one argument: the tier and provenance its receipt records. */
export interface ArgumentTrust {
  readonly tier: Tier
  readonly provenance: string
}

/** A judge's whole view of a call. `trust` has one entry per key of `action.args`. */
export interface JudgmentInput {
  readonly purpose: Purpose
  readonly action: Action
  readonly trust: Readonly<Record<string, ArgumentTrust>>
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
    model: "mock-judgment@1",
    async assess({ action }) {
      // No wrong type is coerced: String(["a"]) is "a" and Number("") is 0, so
      // such a value used to read as an intended payee or a zero amount. Number()
      // below is a stand-in's shortcut and loses precision past 2^53.
      const { to, amount: raw } = action.args
      const amount =
        (typeof raw === "number" && Number.isFinite(raw) && raw >= 0) || (typeof raw === "bigint" && raw >= 0n) || (typeof raw === "string" && DECIMAL_INTEGER.test(raw))
          ? Number(raw)
          : undefined
      if (typeof to !== "string" || amount === undefined) {
        return { assessment: "mismatch", confidence: 0.82, rationale: `${action.sink} has no string payee, or no non-negative amount` }
      }
      if (intent.intendedPayees.has(to) && amount <= intent.maxAmount) {
        return { assessment: "match", confidence: 0.9, rationale: `${action.sink} matches declared intent` }
      }
      // Near-edge amounts read as "unsure" — the honest, defer-to-human band.
      if (intent.intendedPayees.has(to) && amount <= intent.maxAmount * 1.1) {
        return { assessment: "unsure", confidence: 0.35, rationale: `${to} is intended but amount ${amount} slightly over cap ${intent.maxAmount}` }
      }
      return { assessment: "mismatch", confidence: 0.82, rationale: `${to}/${amount} not in declared intent (payee unintended or amount over cap)` }
    },
  }
}

// ── Sinks (Rule 4 + the adoption ladder) ─────────────────────────────────────

export type EnforcementMode = "observe" | "warn" | "enforce"
const MODES: ReadonlySet<string> = new Set<EnforcementMode>(["observe", "warn", "enforce"])

/** How long a judged sink waits for its judge unless told otherwise. */
const DEFAULT_JUDGMENT_TIMEOUT_MS = 5000
/** The largest delay setTimeout honors. Past it Node fires after 1ms, so a generous deadline would become an impossible one. */
const MAX_JUDGMENT_TIMEOUT_MS = 2 ** 31 - 1
const ASSESSMENTS: ReadonlySet<unknown> = new Set(["match", "mismatch", "unsure"])

/** Name a value in a TypeError without dereferencing it. */
const preview = (v: unknown): string =>
  typeof v === "string" ? JSON.stringify(v) : typeof v === "symbol" ? v.toString() : v === null ? "null" : typeof v === "object" ? "<object>" : typeof v === "function" ? "<function>" : String(v)

/**
 * What the host passes beside the arguments. `idempotencyKey` names this call
 * as a distinct repeat of an action: with one, an action already attempted
 * under another key runs again. It comes from the HOST, for example a payment's
 * own invoice id, and must never be derived from anything an agent wrote: a
 * host that forwards an agent's value hands the agent the decision to repeat a
 * payment. A key never escapes a block or a hold (ADR 0010).
 */
export interface SinkCallOptions {
  readonly idempotencyKey?: string
}

export type SinkResult<R> =
  | { readonly ok: true; readonly result: R; readonly receipt: Receipt }
  | { readonly ok: false; readonly refusal: string; readonly receipt: Receipt; readonly held?: HeldAction }

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
    // A string is cut as itself; anything else is cut as its receipt JSON, so a
    // BigInt under `truncate` reads the same as under `raw`.
    const s = typeof value === "string" ? value : (json ?? "undefined")
    return s.length > 64 ? s.slice(0, 64) + "…" : s
  }
  return json === undefined ? undefined : JSON.parse(json)
}

/** Run a renderer over something thrown. Its `message` and `toString` are the thrower's code and can throw too. */
const safely = (render: () => string): string => {
  try {
    return render()
  } catch {
    return "a reason that could not be rendered"
  }
}

/**
 * Pin the grant at construction: each field read once, the purpose copied and
 * frozen, so neither the host nor a provider can change what later calls are
 * judged against (spec I3).
 */
function pinGranted(where: string, granted: unknown): GrantedPurpose {
  if (typeof granted !== "object" || granted === null) {
    throw new TypeError(`${where}: judgment.granted must be { purpose, grantHash } from the signed grant, got ${preview(granted)}`)
  }
  const purposeRaw = Object.hasOwn(granted, "purpose") ? (granted as GrantedPurpose).purpose : undefined
  const grantHash = Object.hasOwn(granted, "grantHash") ? (granted as GrantedPurpose).grantHash : undefined
  const isLive = Object.hasOwn(granted, "isLive") ? (granted as GrantedPurpose).isLive : undefined
  if (isLive !== undefined && typeof isLive !== "function") {
    throw new TypeError(`${where}: judgment.granted.isLive must be a function when set, got ${preview(isLive)}`)
  }
  if (typeof grantHash !== "string" || !/^[0-9a-f]{64}$/.test(grantHash)) {
    throw new TypeError(`${where}: judgment.granted.grantHash must be 64 lowercase hex, got ${preview(grantHash)}`)
  }
  let purpose: Purpose
  try {
    purpose = copyExact(purposeRaw, false) as Purpose
  } catch (err) {
    throw new TypeError(`${where}: judgment.granted.purpose must be plain JSON (${firstLine(err)})`)
  }
  if (typeof purpose !== "object" || purpose === null || typeof purpose.statement !== "string" || purpose.statement.length === 0) {
    throw new TypeError(`${where}: judgment.granted.purpose must carry a non-empty statement`)
  }
  return Object.freeze({ purpose: deepFreeze(purpose), grantHash, ...(isLive === undefined ? {} : { isLive }) })
}

/** The purpose's deterministic fields and the sink's map onto them, checked before any judge runs. */
interface BoundPurpose {
  readonly payees: ReadonlyArray<string> | undefined
  readonly maxPerAction: bigint | undefined
  readonly actions: ReadonlyArray<string> | undefined
  readonly asset: string | undefined
  readonly payment: { readonly payeeArg: string; readonly amountArg: string; readonly assetArg: string | undefined; readonly asset: string | undefined; readonly network: string } | undefined
}

const ownOf = (o: object, k: string): unknown => (Object.hasOwn(o, k) ? (o as Record<string, unknown>)[k] : undefined)
const isStringList = (v: unknown): v is ReadonlyArray<string> => Array.isArray(v) && v.every((x) => typeof x === "string")

/**
 * Read the purpose's fields and the sink's payment mapping once, as own keys,
 * and refuse anything a call could never satisfy (spec § 3.2). A purpose field
 * whose argument is not named would otherwise have nothing to be checked
 * against, which is a sink that quietly ignores its owner.
 */
function bindPurpose(
  where: string,
  purpose: Purpose,
  requires: Readonly<Record<string, Tier>>,
  config: { readonly purposeArgs: unknown; readonly network: unknown; readonly asset: unknown },
): BoundPurpose {
  const fieldsRaw = ownOf(purpose, "fields")
  if (fieldsRaw !== undefined && (typeof fieldsRaw !== "object" || fieldsRaw === null || Array.isArray(fieldsRaw))) {
    throw new TypeError(`${where}: judgment.granted.purpose.fields must be an object`)
  }
  const fields: object = fieldsRaw ?? {}
  const payees = ownOf(fields, "payees")
  const maxPerAction = ownOf(fields, "maxPerAction")
  const actions = ownOf(fields, "actions")
  const fieldAsset = ownOf(fields, "asset")
  if (fieldAsset !== undefined && (typeof fieldAsset !== "string" || fieldAsset.length === 0)) {
    throw new TypeError(`${where}: judgment.granted.purpose.fields.asset must be a non-empty string, got ${preview(fieldAsset)}`)
  }
  if (payees !== undefined && !isStringList(payees)) throw new TypeError(`${where}: judgment.granted.purpose.fields.payees must be a list of strings`)
  if (actions !== undefined && !isStringList(actions)) throw new TypeError(`${where}: judgment.granted.purpose.fields.actions must be a list of strings`)
  if (maxPerAction !== undefined && !(typeof maxPerAction === "string" && DECIMAL_INTEGER.test(maxPerAction))) {
    throw new TypeError(`${where}: judgment.granted.purpose.fields.maxPerAction must be a decimal integer string, got ${preview(maxPerAction)}`)
  }

  const { purposeArgs, network, asset } = config
  let payment: BoundPurpose["payment"]
  if (purposeArgs !== undefined) {
    if (typeof purposeArgs !== "object" || purposeArgs === null) {
      throw new TypeError(`${where}: judgment.purposeArgs must be { payee, amount, asset? }, got ${preview(purposeArgs)}`)
    }
    // Each read once, own keys only, and checked against the declared arguments.
    const declared = (role: string, name: unknown): string => {
      if (typeof name !== "string" || !Object.hasOwn(requires, name)) {
        throw new TypeError(`${where}: judgment.purposeArgs.${role} must name an argument declared in requires, got ${preview(name)}`)
      }
      return name
    }
    const payeeArg = declared("payee", ownOf(purposeArgs, "payee"))
    const amountArg = declared("amount", ownOf(purposeArgs, "amount"))
    const assetName = ownOf(purposeArgs, "asset")
    const assetArg = assetName === undefined ? undefined : declared("asset", assetName)
    if (typeof network !== "string" || network.length === 0) {
      throw new TypeError(`${where}: judgment.network (CAIP-2) is required with purposeArgs, got ${preview(network)}`)
    }
    if (assetArg === undefined && (typeof asset !== "string" || asset.length === 0)) {
      throw new TypeError(`${where}: judgment.asset is required when purposeArgs names no asset argument, got ${preview(asset)}`)
    }
    if (assetArg !== undefined && asset !== undefined) {
      throw new TypeError(`${where}: judgment.asset and judgment.purposeArgs.asset are both set, so the asset of a payment would be ambiguous`)
    }
    payment = { payeeArg, amountArg, assetArg, asset: asset as string | undefined, network }
  }
  if (payees !== undefined && payment === undefined) {
    throw new TypeError(`${where}: the purpose sets payees, so judgment.purposeArgs must name the payee argument`)
  }
  if (maxPerAction !== undefined && payment === undefined) {
    throw new TypeError(`${where}: the purpose sets maxPerAction, so judgment.purposeArgs must name the amount argument`)
  }
  if (fieldAsset !== undefined && payment === undefined) {
    throw new TypeError(`${where}: the purpose sets asset, so judgment.purposeArgs must name the payment`)
  }
  // Base units mean nothing without an asset (the 2026-11-08 audit, K7): one
  // number would cap 1000 MIST and 1000 of an eight-decimal coin alike. A sink
  // with a fixed asset settles the unit in host config; an asset argument
  // leaves it to the call, so the purpose has to name it.
  if (maxPerAction !== undefined && payment?.assetArg !== undefined && fieldAsset === undefined) {
    throw new TypeError(`${where}: this sink takes its asset as an argument and the purpose's maxPerAction names no asset; set purpose.fields.asset`)
  }
  if (fieldAsset !== undefined && payment?.assetArg === undefined && payment?.asset !== fieldAsset) {
    throw new TypeError(`${where}: judgment.asset is not the asset the purpose names, so no call could satisfy it`)
  }
  return Object.freeze({
    payees,
    maxPerAction: maxPerAction === undefined ? undefined : BigInt(maxPerAction),
    actions,
    asset: fieldAsset as string | undefined,
    payment,
  })
}

/**
 * Step 2 of the judged path (spec § 3.1): the deterministic purpose fields,
 * over the frozen snapshot, pushing into `violations` so a failure takes the
 * tier wall's path and no judge runs. Returns the payment's digest, or null
 * when the sink names no payment or the payment is one of the violations.
 *
 * Strings here name arguments and fields, never values: these land in `reason`
 * on a receipt that may redact the very arg being refused.
 */
function checkPurpose(bound: BoundPurpose, sink: string, values: Readonly<Record<string, unknown>>, violations: string[]): string | null {
  if (bound.actions !== undefined && !bound.actions.includes(sink)) {
    violations.push(`${sink} is not an action this purpose covers`)
  }
  const { payment } = bound
  if (payment === undefined) return null
  const before = violations.length
  const recipient = ownOf(values, payment.payeeArg)
  const amount = ownOf(values, payment.amountArg)
  const asset = payment.assetArg === undefined ? payment.asset : ownOf(values, payment.assetArg)
  if (typeof recipient !== "string") {
    violations.push(`${payment.payeeArg} must be a string to name a payee`)
  } else if (bound.payees !== undefined && !bound.payees.includes(recipient)) {
    violations.push(`${payment.payeeArg} is not a payee this purpose names`)
  }
  if (typeof amount === "bigint" ? amount < 0n : typeof amount !== "string" || !DECIMAL_INTEGER.test(amount)) {
    violations.push(`${payment.amountArg} must be a non-negative bigint or decimal-integer string`)
  } else if (typeof amount === "string" && !CANONICAL_DECIMAL.test(amount)) {
    // One payment has one spelling, or "0100" is a new action that escapes a
    // block on "100" (the 2026-11-08 series review). `paymentDigest` still
    // digests a string as written; this is where a sink decides what it pays.
    violations.push(`${payment.amountArg} must be a canonical decimal with no leading zeros`)
  } else if (bound.maxPerAction !== undefined) {
    let within = false
    try {
      within = BigInt(amount as bigint | string) <= bound.maxPerAction
    } catch {
      // A digit string too long for a BigInt is over any cap that can be written.
    }
    if (!within) violations.push(`${payment.amountArg} is over this purpose's maxPerAction`)
  }
  if (typeof asset !== "string") violations.push(`the payment's asset must be a string`)
  else if (bound.asset !== undefined && asset !== bound.asset) violations.push(`the payment's asset is not the asset this purpose names`)
  if (violations.length > before) return null
  return paymentDigest({ network: payment.network, asset: asset as string, recipient: recipient as string, amount: amount as bigint | string })
}

/** What the judge saw and what will run: the same frozen values, under one digest. */
interface ActionSnapshot {
  readonly values: Readonly<Record<string, unknown>>
  readonly sourced: Readonly<Record<string, Sourced<unknown>>>
  /** Names this action and its idempotency key: what runs, and what an approval releases. */
  readonly digest: string
  /** Names the action alone: what a block or a hold sticks to (ADR 0010). */
  readonly unkeyed: string
  readonly keyed: boolean
  /** Each argument's tier and provenance, for the judge. Not part of any digest. */
  readonly trust: Readonly<Record<string, ArgumentTrust>>
}

/**
 * Freeze the action before the judge runs (spec § 3.2, I2): nothing can change
 * between judging and acting, because `Sourced` freezes only its first level.
 *
 * A caller's Proxy can throw from a trap with any message it likes, and a
 * clone error quotes the function it refused, so the violation is a fixed
 * sentence that names only the argument. It can land on a redacting receipt.
 */
function snapshotAction(
  sink: string,
  checked: Readonly<Record<string, Sourced<unknown>>>,
  violations: string[],
  idempotencyKey: string | undefined,
  amountArg: string | undefined,
): ActionSnapshot | undefined {
  const values: Record<string, unknown> = Object.create(null)
  const sourced: Record<string, Sourced<unknown>> = Object.create(null)
  const trust: Record<string, ArgumentTrust> = Object.create(null)
  const before = violations.length
  for (const key of Object.keys(checked)) {
    const { value, tier, provenance } = checked[key]!
    try {
      const frozen = pinPlainJSON(value)
      values[key] = frozen
      // Not an ascent: the tier and provenance it passed the wall with, around the clone.
      const pinned = construct(frozen, tier, provenance)
      sourced[key] = pinned
      trust[key] = Object.freeze({ tier, provenance: pinned.describe() })
    } catch {
      violations.push(`${key} is not plain JSON, or holds a raw $bigint key, so the action cannot be digested and judged`)
    }
  }
  if (violations.length > before) return undefined
  try {
    // Over the snapshot, not the original: this digest names what runs. A bigint
    // amount digests as its decimal string, so 100n and "100" are one action and
    // a type change cannot escape a block or a dedupe (the 2026-11-08 review).
    const args = amountArg !== undefined && typeof values[amountArg] === "bigint"
      ? Object.assign(Object.create(null) as Record<string, unknown>, values, { [amountArg]: String(values[amountArg]) })
      : values
    const unkeyed = actionDigest({ sink, args })
    return {
      values: Object.freeze(values),
      sourced: Object.freeze(sourced),
      trust: Object.freeze(trust),
      unkeyed,
      keyed: idempotencyKey !== undefined,
      digest: idempotencyKey === undefined ? unkeyed : actionDigest({ sink, args, idempotencyKey }),
    }
  } catch {
    violations.push("the action cannot be digested and judged")
    return undefined
  }
}

interface BoundJudge {
  readonly assess: (input: Parameters<JudgmentProvider["assess"]>[0], signal: AbortSignal) => unknown
  readonly name: string
  readonly model: string
  readonly floor: number
  readonly timeoutMs: number
  readonly granted: GrantedPurpose
  /** The digest of the purpose the judge sees, on every verdict. */
  readonly purposeHash: string
  readonly purpose: BoundPurpose
  readonly blockWindowMs: number
  readonly rationaleInRefusal: boolean
}

/** Validate a sink's judgment config and read every field of it once; a misconfigured judged sink never exists. */
function bindJudge(
  where: string,
  config: {
    readonly provider: JudgmentProvider
    readonly floor: number
    readonly timeoutMs?: number | undefined
    readonly granted: GrantedPurpose
    readonly purposeArgs?: unknown
    readonly network?: unknown
    readonly asset?: unknown
    readonly blockWindowMs?: number | undefined
    readonly rationaleInRefusal?: boolean | undefined
  },
  requires: Readonly<Record<string, Tier>>,
): BoundJudge {
  // `floor: undefined` made `confidence >= floor` false forever, so a
  // mismatch at 0.99 never blocked (the 2026-10-13 gate audit).
  const { provider, floor, timeoutMs = DEFAULT_JUDGMENT_TIMEOUT_MS, granted, purposeArgs, network, asset, blockWindowMs = DEFAULT_BLOCK_WINDOW_MS, rationaleInRefusal = false } = config
  if (typeof provider !== "object" || provider === null) {
    throw new TypeError(`${where}: judgment.provider must be an object with an assess() method, got ${preview(provider)}`)
  }
  // The provider's three fields are read once, here. Every call uses these.
  const { assess, name, model } = provider
  if (typeof assess !== "function") {
    throw new TypeError(`${where}: judgment.provider must be an object with an assess() method, got ${preview(provider)}`)
  }
  if (typeof model !== "string" || model.length === 0) {
    throw new TypeError(`${where}: judgment.provider.model must be a non-empty pinned version, got ${preview(model)}`)
  }
  if (typeof floor !== "number" || !Number.isFinite(floor) || floor < 0 || floor > 1) {
    throw new TypeError(`${where}: judgment.floor must be a finite number in [0, 1], got ${preview(floor)}`)
  }
  if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_JUDGMENT_TIMEOUT_MS) {
    throw new TypeError(`${where}: judgment.timeoutMs must be a positive number of milliseconds no larger than ${MAX_JUDGMENT_TIMEOUT_MS}, got ${preview(timeoutMs)}`)
  }
  // A window below the approval window would let a block lapse while a hold on
  // the same action still could not, and a shorter block is one a retry loop outlasts.
  if (typeof blockWindowMs !== "number" || !Number.isFinite(blockWindowMs) || blockWindowMs < APPROVAL_WINDOW_MS) {
    throw new TypeError(`${where}: judgment.blockWindowMs must be a number of milliseconds of at least the ${APPROVAL_WINDOW_MS}ms approval window, got ${preview(blockWindowMs)}`)
  }
  if (typeof rationaleInRefusal !== "boolean") {
    throw new TypeError(`${where}: judgment.rationaleInRefusal must be a boolean, got ${preview(rationaleInRefusal)}`)
  }
  const pinned = pinGranted(where, granted)
  const bound: BoundJudge = {
    assess: (input, signal) => assess.call(provider, input, signal),
    name: String(name),
    model,
    floor,
    timeoutMs,
    granted: pinned,
    purposeHash: purposeHash(pinned.purpose),
    purpose: bindPurpose(where, pinned.purpose, requires, { purposeArgs, network, asset }),
    blockWindowMs,
    rationaleInRefusal,
  }
  return Object.freeze(bound)
}

type Consulted = { readonly out: unknown } | { readonly failure: string }

/** A judged action cleared to run: the frozen args the judge saw and the verdict that names them. */
interface JudgedRun {
  readonly args: Readonly<Record<string, Sourced<unknown>>>
  readonly verdict: Verdict
  /** Absent on a flagged run: doubt is not authority (ADR 0010). */
  readonly authorizedBy?: AuthorizedBy
  /** Present on a resume: the owner's approval, carried onto every receipt this run leaves. */
  readonly approval?: Approval
}

/**
 * Ask the judge, with a deadline. Whichever settles first decides, and
 * `resolve` ignores every later call, so a late verdict has nowhere to go. A
 * rejection after the deadline lands in a handler and is dropped, so it cannot
 * surface as an unhandled rejection.
 *
 * A provider that answers from its own abort listener is still late: its
 * answer reaches `settle` through a promise callback, which cannot run until
 * this timer callback has returned, and by then the failure has won.
 *
 * The timer is cleared the moment the judge answers, so a fast verdict leaves
 * nothing holding the process open. It is deliberately not `unref`ed: while a
 * judge is still out, a process with nothing else to do must wait for the
 * deadline, not exit with the call neither executed nor recorded.
 */
const consultJudge = (ask: (signal: AbortSignal) => unknown, timeoutMs: number): Promise<Consulted> =>
  new Promise((resolve) => {
    const controller = new AbortController()
    const timer = setTimeout(() => {
      const failure = `no verdict within ${timeoutMs}ms`
      resolve({ failure })
      controller.abort(new DOMException(failure, "TimeoutError"))
    }, timeoutMs)
    const settle = (answer: Consulted) => {
      clearTimeout(timer)
      resolve(answer)
    }
    const failed = (err: unknown) => settle({ failure: safely(() => firstLine(err)) })
    try {
      Promise.resolve(ask(controller.signal)).then((out) => settle({ out }), failed)
    } catch (err) {
      failed(err)
    }
  })

/**
 * Read a judge's answer, once, as own keys. Anything that is not a verdict is
 * a failure, never a verdict with blanks in it: an object with no assessment
 * used to pass as one, and that is how an unawaited Promise executed.
 */
function readVerdict(consulted: Consulted): { readonly assessment: Verdict["assessment"]; readonly confidence: number; readonly rationale: string } | { readonly failure: string } {
  if ("failure" in consulted) return consulted
  const { out } = consulted
  if (typeof out !== "object" || out === null) return { failure: `provider returned ${preview(out)} instead of a verdict` }
  try {
    const field = (k: string): unknown => (Object.hasOwn(out, k) ? (out as Record<string, unknown>)[k] : undefined)
    const assessment = field("assessment")
    const confidence = field("confidence")
    const rationale = field("rationale")
    if (!ASSESSMENTS.has(assessment)) return { failure: `provider returned an unknown assessment ${preview(assessment)}` }
    if (typeof confidence !== "number" || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
      return { failure: `provider returned confidence ${preview(confidence)}, not a number in [0, 1]` }
    }
    // A verdict with no reasons is not evidence of anything (the 2026-11-08 audit, G3).
    if (typeof rationale !== "string" || rationale.trim().length === 0) {
      return { failure: `provider returned rationale ${preview(rationale)}, not a non-empty string` }
    }
    // `+ 0` turns -0 into 0: -0 is in range, and verdictDigest refuses it.
    return { assessment: assessment as Verdict["assessment"], confidence: confidence + 0, rationale }
  } catch (err) {
    return { failure: `reading the verdict threw: ${safely(() => firstLine(err))}` }
  }
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
 *
 * `execute` receives a SNAPSHOT: a null-prototype object holding only the keys
 * `requires` declares, each read once from the caller's object at check time.
 * An argument the spec never declared is recorded on the receipt and raised as
 * a violation, and does not reach `execute` in any mode. Every value must be
 * plain JSON (bigints allowed): anything else is a violation, and only observe
 * and warn run it. A judged call runs on a deep-frozen copy, the same values
 * the judge saw.
 *
 * Every call returns a Promise, judged or not (ADR 0007), and `result` is the
 * settled value of whatever `execute` returned. A caller who forgets `await`
 * reads `.ok` as undefined on the Promise, never true.
 *
 * The returned function also has `.resume(args, approval)`, the one way a held
 * action runs: an owner-signed approval, usable once (spec § 3.3, I11). The
 * kernel never asks the owner; the broker does, and brings back the signature.
 */
export function makeSink<Args extends Record<string, Sourced<unknown>>, R>(spec: {
  readonly name: string
  readonly requires: { readonly [K in keyof Args]: Tier }
  readonly mode: EnforcementMode
  readonly log: ReceiptLog
  /**
   * The second argument names the verdict that let the action through and
   * carries the one-shot authorization for it. It is present on a confident
   * match or an owner's approval. A flagged action in warn or observe runs
   * without one (doubt is not authority), and so does an unjudged call.
   */
  readonly execute: (args: Args, context?: { readonly authorizedBy: AuthorizedBy; readonly authorization: SpendAuthorization }) => R
  /**
   * Optional judgment wall (the judgment seam). Runs AFTER tier and purpose
   * checks pass — it exists to catch the in-bounds-but-wrong action the tiers
   * structurally cannot.
   *
   * In enforce mode only a "match" at or above `floor` runs, and only a
   * "mismatch" at or above it blocks. Everything else is HELD and waits for an
   * owner: "unsure", either assessment below the floor, and a judge that timed
   * out, threw, rejected or answered with something that is not a verdict
   * (spec I4). In observe and warn nothing is held: a would-be hold or block
   * runs, flagged, with the verdict on the receipt.
   *
   * `granted` is the owner's purpose and the hash of the grant that signs it,
   * bound here and never per call (spec I3). When it carries `isLive`, as
   * `grantedPurpose` provides, the sink asks before judging and again
   * immediately before `execute`, and a grant no longer live is refused in
   * every mode: a revoke is the owner's word, not a tier the ladder can relax. `timeoutMs` (default 5000) is the
   * judge's deadline: at it the provider's signal fires, any later answer is
   * discarded, and the call has no verdict.
   *
   * `purposeArgs` names the arguments that are the payment's parts. With it the
   * sink takes `network` (CAIP-2) and, unless an asset argument is named,
   * `asset`, and its verdicts carry a payment digest. A purpose field that is
   * set needs its argument named here, or the sink does not construct.
   *
   * `approvalKey` is the owner's Ed25519 public key as SPKI-DER hex (what
   * `publicKeyHexFromPem` returns), bound here and never per call. It is what
   * lets `sink.resume` release a hold; without it every resume is refused.
   *
   * `blockWindowMs` (default one hour, never below the 15-minute approval
   * window) is how long a block stands before the judge is asked again; a
   * `match` after it is held for the owner. `rationaleInRefusal` (default false)
   * puts the judge's assessment, confidence and words back in the refusal
   * string; the receipt always has them, its `reason` redacted per `redact`, so
   * a host that wants them kept from the agent must not hand it the receipt
   * (ADR 0010).
   */
  readonly judgment?: {
    readonly provider: JudgmentProvider
    readonly floor: number
    readonly timeoutMs?: number
    readonly granted: GrantedPurpose
    readonly purposeArgs?: { readonly payee: keyof Args & string; readonly amount: keyof Args & string; readonly asset?: keyof Args & string }
    readonly network?: string
    readonly asset?: string
    readonly approvalKey?: string
    readonly blockWindowMs?: number
    readonly rationaleInRefusal?: boolean
  }
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
  // ── The spec is read ONCE, here, every field as an OWN key ───────────────
  // ARCHITECTURE § 9 claims that nothing in the sink path reads a key off a
  // prototype. The argument path honoured it; the spec path did not:
  // `spec.redact` and `spec.judgment` were plain reads, so a polluted
  // `Object.prototype.redact` hashed the receipts of a sink that declared no
  // redaction, and a polluted `Object.prototype.judgment` judged a sink that
  // declared no wall (the 2026-10-13 gate audit). Snapshotting also means a
  // caller who keeps the spec object cannot change a running sink's mode or
  // appetite from under it.
  const own = <K extends keyof typeof spec>(k: K): (typeof spec)[K] | undefined =>
    Object.hasOwn(spec, k) ? spec[k] : undefined
  const copyOwn = <V>(source: object | undefined): Readonly<Record<string, V>> | undefined => {
    if (source === undefined || source === null || typeof source !== "object") return undefined
    const out: Record<string, V> = Object.create(null)
    for (const k of Object.keys(source)) out[k] = (source as Record<string, V>)[k] as V
    return Object.freeze(out)
  }
  // Own keys, each read once. `granted` above all: an inherited one would let a
  // polluted Object.prototype supply the purpose a judge scores against (I3).
  const ownJudgment = own("judgment")
  const judgmentField = <K extends keyof NonNullable<typeof ownJudgment>>(k: K): NonNullable<typeof ownJudgment>[K] | undefined =>
    typeof ownJudgment === "object" && ownJudgment !== null && Object.hasOwn(ownJudgment, k) ? ownJudgment[k] : undefined
  const redactSpec = own("redact")
  const cfg = Object.freeze({
    name: own("name") as string,
    requires: copyOwn<Tier>(own("requires")) ?? Object.freeze(Object.create(null) as Record<string, Tier>),
    mode: own("mode") as EnforcementMode,
    log: own("log") as ReceiptLog,
    execute: own("execute") as (args: Args, context?: { readonly authorizedBy: AuthorizedBy; readonly authorization: SpendAuthorization }) => R,
    judgment:
      ownJudgment === undefined
        ? undefined
        : Object.freeze({
            provider: judgmentField("provider") as JudgmentProvider,
            floor: judgmentField("floor") as number,
            timeoutMs: judgmentField("timeoutMs"),
            granted: judgmentField("granted") as GrantedPurpose,
            purposeArgs: judgmentField("purposeArgs"),
            network: judgmentField("network"),
            asset: judgmentField("asset"),
            approvalKey: judgmentField("approvalKey"),
            blockWindowMs: judgmentField("blockWindowMs"),
            rationaleInRefusal: judgmentField("rationaleInRefusal"),
          }),
    redact: copyOwn<"raw" | "hash" | "truncate" | undefined>(redactSpec),
  })

  // ── Validate at construction: a misconfigured sink never exists ──────────
  // The call body used to test `mode === "enforce"` and `mode === "observe"`
  // and let everything else fall through to the WARN path, so "ENFORCE",
  // "strict", undefined and null all executed an under-tier argument with a
  // receipt that said "warned" (the 2026-10-13 gate audit). The deployment
  // that hits this reads its mode from an environment variable. A TypeError
  // here is the only moment the misconfiguration is one line away from its
  // cause; at call time it is a silently permissive sink.
  const where = `makeSink(${preview(cfg.name)})`
  if (typeof cfg.mode !== "string" || !MODES.has(cfg.mode)) {
    throw new TypeError(`${where}: mode must be one of "observe" | "warn" | "enforce", got ${preview(cfg.mode)}`)
  }
  if (typeof cfg.log !== "object" || cfg.log === null || typeof cfg.log.append !== "function") {
    throw new TypeError(`${where}: log must be a ReceiptLog (an object with an append() method), got ${preview(cfg.log)}`)
  }
  for (const [key, tier] of Object.entries(cfg.requires)) {
    if (!isTier(tier)) {
      throw new TypeError(`${where}: requires.${key} must be one of ${TIERS.map((t) => `"${t}"`).join(" | ")}, got ${preview(tier)}`)
    }
  }
  // An unknown policy used to record the raw value on a receipt that cannot be
  // redacted later (the 2026-11-08 audit, G4). A misspelled "hash" is a secret
  // published on the first call.
  if (redactSpec !== undefined && (typeof redactSpec !== "object" || redactSpec === null || Array.isArray(redactSpec))) {
    throw new TypeError(`${where}: redact must be an object of per-argument policies, got ${preview(redactSpec)}`)
  }
  for (const [key, policy] of Object.entries(cfg.redact ?? {})) {
    // A misspelled argument name leaves the real argument raw, the same way.
    if (!Object.hasOwn(cfg.requires, key)) throw new TypeError(`${where}: redact.${key} names an argument that is not declared in requires`)
    if (policy !== undefined && policy !== "raw" && policy !== "hash" && policy !== "truncate") {
      throw new TypeError(`${where}: redact.${key} must be one of "raw" | "hash" | "truncate", got ${preview(policy)}`)
    }
  }
  const judge = cfg.judgment === undefined ? undefined : bindJudge(where, cfg.judgment, cfg.requires)
  const ownerKey = bindApprovalKey(where, cfg.judgment?.approvalKey, cfg.log)
  // The action record's durable states live on the log and survive a restart,
  // so a judged enforce sink has to be able to read it back (ADR 0010). Refused
  // here, one line from the misconfiguration.
  if (judge !== undefined && cfg.mode === "enforce" && typeof (cfg.log as { all?: unknown }).all !== "function") {
    throw new TypeError(`${where}: a judged enforce sink needs a log with an all() method, to read back its blocks, holds and attempts`)
  }
  // Verdicts an approval has released in this process (I11). Since ADR 0010 the
  // `attempted` receipt is written before execute() and read back from the log,
  // which also stops a second sink; this set stays as the check that needs no
  // read-back, for a log whose all() lags its append. An entry is added once the
  // intent record lands and is never removed, a failed execute included: the
  // action may have taken effect, and one approval is one attempt.
  const claimed = new Set<string>()
  // Actions a judge is deciding right now, by unkeyed digest: the one state that
  // cannot be on the log yet, because no receipt exists before the answer. The
  // claim is taken before the first await and released once the decision's
  // receipt is on the log, so concurrent identical calls wait and answer from it.
  const judging = new Map<string, Promise<void>>()

  // What this action already is, read back from the log in one synchronous
  // walk (ADR 0010). A later receipt moves the state: a judgment sets a block
  // or a hold, and only the owner's approval of that doubt resolves it. Receipts under another grant or
  // purpose are skipped: they are someone else's action, or the owner has
  // changed what is being judged against. A hold with no real verdict behind it
  // (`scored: false`) is skipped too: an outage is not an answer.
  //
  // Stickiness ignores the idempotency key (`unkeyed`), so no key can escape a
  // block or a hold. Dedupe keys on it: with a key, only this key's attempt is
  // a duplicate; with none, any attempt of this action is.
  const actionState = (action: ActionSnapshot, bound: BoundJudge) => {
    let standing: { readonly verdict: Verdict; readonly label: "judgment-blocked" | "judgment-held" } | undefined
    let attempted: Verdict | undefined
    for (const receipt of cfg.log.all()) {
      const { verdict, decision } = receipt
      if (receipt.sink !== cfg.name || verdict === undefined || verdict.unkeyedActionDigest !== action.unkeyed) continue
      if (verdict.grantHash !== bound.granted.grantHash || verdict.purposeHash !== bound.purposeHash) continue
      if (decision === "judgment-blocked" || decision === "judgment-held") {
        if (verdict.scored) standing = { verdict, label: decision }
      } else if (decision === "attempted" || decision === "executed" || decision === "errored") {
        // Only the owner's approval of this doubt answers it (DAN-1443). Anything
        // else can land after the doubt without the owner having seen it: a late
        // `errored` from an earlier payment, a clean run on a warn sink over the
        // same log, or the release of an outage hold signed before the doubt.
        if (decision === "attempted" && standing !== undefined) {
          try {
            if (receipt.approval?.verdictDigest === verdictDigest(standing.verdict)) standing = undefined
          } catch {
            // A verdict that will not digest cannot be shown to be the one approved.
          }
        }
        if (!action.keyed || verdict.actionDigest === action.digest) attempted = verdict
      }
    }
    return { standing, attempted }
  }

  // Whether the grant still stands. No check means a hand-built grant, which
  // gets no revocation (SECURITY.md). A check that throws or answers anything
  // but `true` has not said the grant is live.
  const grantIsLive = (): boolean => {
    const isLive = judge?.granted.isLive
    if (isLive === undefined) return true
    try {
      return isLive() === true
    } catch {
      return false
    }
  }

  const call = async (args: Args, resuming?: { readonly approval: unknown }, options?: unknown): Promise<SinkResult<Awaited<R>>> => {
    // `Object.create(null)` rather than `{}`: `rendered` is keyed by ATTACKER-
    // SUPPLIED argument names and then handed to the receipt. A plain object
    // literal inherits `Object.prototype`, so an argument named `__proto__`
    // does not become a key at all — it mutates the prototype — and the
    // receipt silently loses the record of an argument that reached the sink.
    const rendered: Receipt["args"] = Object.create(null)
    const violations: string[] = []
    // THE snapshot an unjudged execute() receives, and the source of the frozen
    // one a judged call runs on — null-prototype, holding ONLY declared keys,
    // each from the single read in the loop below. Until
    // the 2026-10-13 gate audit execute() got the caller's own `args` object
    // and the judge re-read `args[k].value` from it, so a getter or Proxy that
    // answered GOOD on the check and EVIL on the action cleared enforce with a
    // verified receipt (the 2026-08-31 rule, "the object you checked must be
    // the object you act on", applied here at last), and a symbol-keyed,
    // non-enumerable or inherited argument reached execute untier-checked and
    // off the receipt. An undeclared argument is still recorded and still a
    // violation; it no longer reaches execute() in ANY mode.
    const checked: Record<string, Sourced<unknown>> = Object.create(null)

    // `sink(null)` used to reject on the first read, with no receipt (the
    // 2026-11-08 audit, G4). There is no action to run, so every mode refuses.
    if (typeof (args as unknown) !== "object" || (args as unknown) === null) {
      const refusal = `⚠ ${cfg.name} refused: the sink was called without an arguments object`
      const receipt = cfg.log.append({ at: now(), sink: cfg.name, decision: "refused", args: rendered, reason: refusal })
      return { ok: false, refusal, receipt }
    }

    // The one place an action runs and is recorded (ADR 0007). The flagged path
    // used to hold its own copy of this sequence, and the two had drifted
    // before ("Same hole as the main path (V5)").
    //
    // A throw used to leave NO record at all (adversarial pass V5, 2026-07-25):
    // the gateway returned 500 on a request that may well have settled, and the
    // evidence log — the whole product — was silent about it. A log whose only
    // gap is "everything that went wrong" is worse than no log, because it reads
    // as complete. The attempt is now always recorded before the error
    // propagates; the caller still gets its exception.
    //
    // ORDER, pinned in the spec (§ 3.2). The receipt is appended the moment
    // `execute` returns, BEFORE its result is awaited, so a crash during a slow
    // action still leaves a record. If the result then rejects, an `errored`
    // receipt TRAILS it, and the sink's own promise rejects with the same error,
    // so a host that forgets its catch still gets Node's crash (the 2026-10-13
    // flip, test/gate/audit-2026-10-13.test.ts).
    //
    // A judged run executes the frozen snapshot the judge saw (I2) and every
    // receipt it leaves, `errored` included, carries the verdict.
    const act = async (
      decision: Receipt["decision"],
      reason: string | undefined,
      threw: string,
      rejected: string,
      run?: JudgedRun,
    ): Promise<SinkResult<Awaited<R>>> => {
      // The second liveness check: nothing is awaited from here to execute().
      if (run !== undefined && !grantIsLive()) return refuseRevoked(run.verdict)
      const evidence = run === undefined ? {} : { verdict: run.verdict, ...(run.approval === undefined ? {} : { approval: run.approval }) }
      // The intent record, before anything can happen (ADR 0010). A log that
      // cannot take it stops the action here; once it is written the action
      // counts as attempted, whatever becomes of the outcome receipt.
      if (run !== undefined && cfg.mode === "enforce") {
        cfg.log.append({ at: now(), sink: cfg.name, decision: "attempted", args: rendered, ...evidence })
        // Only now: if the write above throws nothing ran, and the approval is unspent.
        if (run.approval !== undefined) claimed.add(run.approval.verdictDigest)
      }
      let pending: R
      try {
        // A token is issued per execution, only for a run that carries authority.
        const authorized = run?.authorizedBy
        const context = authorized === undefined ? undefined : { authorizedBy: authorized, authorization: issueAuthorization(authorized) }
        pending = run === undefined ? cfg.execute(checked as Args) : cfg.execute(run.args as Args, context)
      } catch (err) {
        cfg.log.append({ at: now(), sink: cfg.name, decision: "errored", args: rendered, reason: `${threw}: ${safely(() => (err instanceof Error ? err.message : String(err)))}`, ...evidence })
        throw err
      }
      let receipt: Receipt
      try {
        receipt = cfg.log.append({ at: now(), sink: cfg.name, decision, args: rendered, ...(reason === undefined ? {} : { reason }), ...evidence })
      } catch (err) {
        // The log's failure is what the caller gets. The action is still
        // running, and nobody can catch its rejection now that this call is
        // over, so it is observed here rather than left to crash the process.
        void (async () => {
          try {
            await pending
          } catch {
            /* the log just failed; there is nowhere left to record this */
          }
        })()
        throw err
      }
      try {
        return { ok: true, result: await pending, receipt }
      } catch (err) {
        cfg.log.append({
          at: now(),
          sink: cfg.name,
          decision: "errored",
          args: rendered,
          reason: `${rejected} — then its promise rejected; the action may or may not have taken effect: ${safely(() => firstLine(err))}`,
          ...evidence,
        })
        throw err
      }
    }

    // Own-key redaction lookup over the own-key snapshot. `spec.redact?.[key]`
    // used to walk the prototype, so a key like `constructor` or `toString`
    // returned an inherited FUNCTION where a `"raw" | "hash" | "truncate"` was
    // expected, and that value decided what landed on a receipt that may be
    // anchored on-chain and can never be amended. Anything not declared as an
    // own key redacts as "raw".
    const redactFor = (k: string): "raw" | "hash" | "truncate" =>
      cfg.redact !== undefined && Object.hasOwn(cfg.redact, k) ? (cfg.redact[k] ?? "raw") : "raw"

    // No action without its receipt (DAN-1159 item 2). Every argument is
    // rendered HERE, before any decision, so the receipt can always be
    // written. The order used to be execute() first and serialize second, so an
    // argument JSON.stringify refuses (a cycle; a BigInt before `receiptJSON`)
    // threw inside log.append AFTER the side effect: the action ran and left no
    // receipt, and the chain still verified. An argument that cannot be
    // rendered is recorded as a placeholder and raised as a violation, and the
    // adoption ladder decides as it does for any other: `enforce` refuses before
    // execute(), `observe` and `warn` run it with the gap written down.
    // The host's idempotency key, read once, own key only. It names a repeat
    // payment, so a value the sink cannot use is a violation like any other.
    let idempotencyKey: string | undefined
    if (options !== undefined) {
      const raw = typeof options === "object" && options !== null && Object.hasOwn(options, "idempotencyKey") ? (options as { idempotencyKey?: unknown }).idempotencyKey : undefined
      if (typeof raw === "string" && raw.length > 0) idempotencyKey = raw
      else if (raw !== undefined || typeof options !== "object" || options === null) violations.push("the idempotencyKey option must be a non-empty string set by the host")
    }

    const record = (key: string, value: unknown): unknown => {
      try {
        return renderForReceipt(value, redactFor(key))
      } catch (err) {
        const why = firstLine(err)
        violations.push(`${key} cannot be written to a receipt (${why}), so an action it feeds could not be evidenced`)
        return `[unrecordable: ${why}]`
      }
    }
    // Every argument is read before any is rendered (the 2026-11-08 series
    // review). Rendering inside the read loop let a getter on a later key edit
    // an earlier argument's object after its receipt entry was written.
    const read: Record<string, unknown> = Object.create(null)
    for (const key of Object.keys(cfg.requires)) read[key] = (args as Record<string, unknown>)[key]
    for (const key of Object.keys(args)) {
      if (!Object.hasOwn(cfg.requires, key)) read[key] = (args as Record<string, unknown>)[key]
    }
    for (const key of Object.keys(cfg.requires) as Array<keyof Args & string>) {
      const arg = read[key] as Args[typeof key] // the ONE read is above; everything below, and execute(), sees this binding
      if (arg === undefined) {
        violations.push(`${key} requires ${cfg.requires[key]} but was not provided`)
        continue
      }
      checked[key] = arg
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
      // string WE authored, and raise a violation. `cfg.mode` still governs
      // whether a violation refuses — the adoption ladder is unchanged.
      if (!Sourced.is(arg as unknown)) {
        rendered[key] = {
          value: record(key, arg as unknown),
          tier: "untrusted",
          provenance: "FORGED — failed the Sourced brand check; not a value this rail issued",
        }
        violations.push(
          `${key} requires ${cfg.requires[key]} but is not a Sourced value — it carries the shape but not the brand, so its tier is a claim this rail never made`,
        )
        continue
      }

      rendered[key] = { value: record(key, arg.value), tier: arg.tier, provenance: arg.describe() }
      if (!meetsTier(arg.tier, cfg.requires[key])) {
        violations.push(`${key} requires ${cfg.requires[key]} but is ${arg.describe()}`)
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
    let undeclared = 0
    for (const key of Object.keys(read) as Array<keyof Args & string>) {
      // ── Own-key test, not `in` (2026-08-31) ─────────────────────────────
      // This was `if (key in cfg.requires) continue`. `in` walks the
      // prototype chain, and `cfg.requires` is a plain object literal, so
      // `"constructor" in { to: "verified" }` is TRUE. An argument named
      // `constructor`, `__proto__`, `toString`, `valueOf`, `hasOwnProperty`,
      // `isPrototypeOf` or `propertyIsEnumerable` was therefore treated as
      // DECLARED-AND-HANDLED by this loop, while the declared loop above —
      // which iterates `Object.keys(cfg.requires)` — never saw it either.
      // It fell through both: no tier check, no receipt entry, no violation,
      // in `enforce` mode. It reached `execute()` and left zero trace on a
      // chain that verifies clean.
      //
      // This is directly reachable wherever sink arguments come from model
      // tool-calls, which is this package's stated target: the argument names
      // are chosen by whatever wrote the tool schema.
      if (Object.hasOwn(cfg.requires, key)) continue
      const arg = read[key] as Args[typeof key]
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
      undeclared += 1
    }

    // The judged path's rule, for every value snapshotAction will not reach: an
    // unjudged call, or a judged one that already has a violation (the 2026-11-08
    // audit, G2). A `toJSON` otherwise puts one value on the receipt and another
    // in execute(). Only the check: plain JSON runs no code, and nothing is
    // awaited between here and execute(), so the argument needs no copy.
    if (judge === undefined || violations.length !== undeclared) {
      for (const key of Object.keys(checked)) {
        const arg: unknown = checked[key]
        if (!Sourced.is(arg)) continue
        try {
          pinPlainJSON(arg.value)
        } catch {
          violations.push(`${key} is not plain JSON, so its receipt may not record what runs`)
        }
      }
    }

    // "Not live" covers a revoke and a check that could not confirm the grant, so
    // the receipt says that much and no more.
    const refuseRevoked = (verdict?: Verdict): SinkResult<Awaited<R>> => {
      const refusal = `⚠ ${cfg.name} refused: grant-not-live: the grant behind this sink is revoked, or could not be confirmed live`
      const receipt = cfg.log.append({ at: now(), sink: cfg.name, decision: "refused", args: rendered, reason: refusal, ...(verdict === undefined ? {} : { verdict }) })
      return { ok: false, refusal, receipt }
    }

    // The first liveness check, before a resume or a judge can do anything.
    if (!grantIsLive()) return refuseRevoked()

    const refuseViolations = (): SinkResult<Awaited<R>> => {
      const refusal = `⚠ ${cfg.name} refused: ${violations.join(" · ")}`
      const receipt = cfg.log.append({ at: now(), sink: cfg.name, decision: "refused", args: rendered, reason: refusal })
      return { ok: false, refusal, receipt }
    }

    // ── Resuming a held action (spec § 3.3, I11) ───────────────────────────
    // No `await` from here to execute(), which act() calls synchronously: the
    // replay check, the claim and the call are one uninterrupted step, so of two
    // overlapping resumes exactly one gets past the claim.
    //
    // The kernel never asks the owner. That is the broker's job; this only
    // checks what the broker brings back. Refusals name a fixed code and no value.
    if (resuming !== undefined) {
      const refuse = (code: string, detail: string): SinkResult<Awaited<R>> => {
        const refusal = `⚠ ${cfg.name} refused: ${code}: ${detail}`
        const receipt = cfg.log.append({ at: now(), sink: cfg.name, decision: "refused", args: rendered, reason: refusal })
        return { ok: false, refusal, receipt }
      }

      // 1. The owner's signature, before anything the approval says is believed.
      const approval = readApproval(resuming.approval)
      if (approval === undefined || ownerKey === undefined || judge === undefined || !approvalSigned(approval, ownerKey)) {
        return refuse("approval-unsigned", "no valid owner signature over the approval")
      }

      // 2. The hold, found by recomputing each receipt's digest from the verdict
      // it stores. A hold exists only in enforce, so an observe or warn sink
      // sharing this log (and a violation would pass there) can release nothing.
      let heldReceipt: Receipt | undefined
      let heldVerdict: Verdict | undefined
      let attempted = false
      if (cfg.mode === "enforce") {
        for (const receipt of cfg.log.all()) {
          const v = receipt.verdict
          if (receipt.sink !== cfg.name || v === undefined) continue
          if (receipt.decision !== "judgment-held" && receipt.decision !== "attempted" && receipt.decision !== "executed" && receipt.decision !== "errored") continue
          let digest: string
          try {
            digest = verdictDigest(v)
          } catch {
            continue
          }
          if (digest !== approval.verdictDigest) continue
          if (receipt.decision !== "judgment-held") attempted = true
          else if (heldReceipt === undefined) {
            heldReceipt = receipt
            heldVerdict = v
          }
        }
      }
      if (heldReceipt === undefined || heldVerdict === undefined || heldVerdict.grantHash !== judge.granted.grantHash || heldVerdict.purposeHash !== judge.purposeHash || approval.grantHash !== heldVerdict.grantHash) {
        return refuse("approval-mismatch", "this approval does not name an action held by this sink")
      }

      // 3. Expiry, against the receipt's own clock. `!(a <= b)` so that a receipt
      // whose `at` does not parse refuses instead of comparing false.
      const expiresAt = strictInstant(approval.expiresAt)
      if (expiresAt === undefined || Date.now() >= expiresAt || !(expiresAt <= Date.parse(heldReceipt.at) + APPROVAL_WINDOW_MS)) {
        return refuse("approval-expired", "this approval is expired, or expires more than 15 minutes after the hold")
      }

      // 4. The args presented now are the action that was held. Any change is a
      // new action, which goes through the judge by calling the sink again. Only
      // branded values can name it: `checked` also holds what failed the brand
      // check, and those are violations, not tiers to re-wrap.
      const resumed = Object.values(checked).every((arg) => Sourced.is(arg)) ? snapshotAction(cfg.name, checked, [], idempotencyKey, judge?.purpose.payment?.amountArg) : undefined
      if (resumed === undefined || resumed.digest !== approval.actionDigest || approval.actionDigest !== heldVerdict.actionDigest) {
        return refuse("approval-mismatch", "the resumed arguments are not the action that was held")
      }
      // The digest treats 100n and "100" as one action, but execute() must get the
      // type the judge saw. A redacted amount matches neither test and is not compared.
      const heldAmountArg = judge.purpose.payment?.amountArg
      if (heldAmountArg !== undefined) {
        const heldAmount: unknown = heldReceipt.args[heldAmountArg]?.value
        const heldBigint = typeof heldAmount === "object" && heldAmount !== null && Object.hasOwn(heldAmount, "$bigint")
        const heldString = typeof heldAmount === "string" && CANONICAL_DECIMAL.test(heldAmount)
        if (typeof resumed.values[heldAmountArg] === "bigint" ? heldString : heldBigint) {
          return refuse("approval-mismatch", "the resumed amount is not the type that was held")
        }
      }

      // 5. Replay: claimed in this process, or an attempt already on the log,
      // under this verdict (step 2) or under another one for the same action. A
      // judge failure leaves no standing hold, so a later call can run the action
      // while the failed hold's approval is still valid; that must not pay twice.
      if (claimed.has(approval.verdictDigest) || attempted || actionState(resumed, judge).attempted !== undefined) {
        return refuse("approval-replayed", "this approval has already released its one execution")
      }

      // Steps 1 and 2 of a judged call, and only the judge is skipped (I1). The
      // digest above says nothing about pedigree: the same value at a lower tier
      // digests the same. This refusal spends nothing; the claim comes after it.
      const paymentOfResume = violations.length === 0 ? checkPurpose(judge.purpose, cfg.name, resumed.values, violations) : null
      if (violations.length > 0) return refuseViolations()
      if (paymentOfResume !== heldVerdict.paymentDigest) {
        return refuse("approval-mismatch", "this sink's payment is not the payment that was held")
      }

      return act(
        "executed",
        undefined,
        `${cfg.name} was released by an owner approval and then threw — the action may or may not have taken effect`,
        `${cfg.name} was released by an owner approval and was recorded as executed`,
        {
          args: resumed.sourced,
          verdict: heldVerdict,
          authorizedBy: Object.freeze({ verdictDigest: approval.verdictDigest, paymentDigest: heldVerdict.paymentDigest }),
          approval,
        },
      )
    }

    // Snapshot and purpose fields, before the wall they feed. A judge never
    // runs on a violation (I1), with one exception that exists only outside
    // enforce: an undeclared argument never reaches execute or the judge, so it
    // no longer switches the judge off and erases the verdict (ADR 0010).
    let snapshot: ActionSnapshot | undefined
    let paymentDigestOfCall: string | null = null
    if (judge !== undefined && violations.length === undeclared) {
      snapshot = snapshotAction(cfg.name, checked, violations, idempotencyKey, judge.purpose.payment?.amountArg)
      if (snapshot !== undefined) paymentDigestOfCall = checkPurpose(judge.purpose, cfg.name, snapshot.values, violations)
    }

    // Tier wall — hard structural gate (Rule 4). A purpose-field or snapshot
    // failure is a violation too, so it refuses here and the judge never runs.
    if (violations.length > 0 && cfg.mode === "enforce") return refuseViolations()

    const standingAnswer = (action: ActionSnapshot, bound: BoundJudge): SinkResult<Awaited<R>> | undefined => {
      const { standing, attempted } = actionState(action, bound)
      if (standing !== undefined) {
        const { verdict, label } = standing
        const until = Date.parse(verdict.judgedAt) + (label === "judgment-held" ? APPROVAL_WINDOW_MS : bound.blockWindowMs)
        // `!(now >= until)` so that a verdict whose time does not parse stands.
        if (!(Date.now() >= until)) {
          // A new receipt, because every sink decision lands on the log. It
          // carries the same verdict and no judge was called: retrying is free
          // and learns nothing. The receipt's reason names the verdict; the
          // refusal, which goes to the agent, does so only on the host's opt-in.
          const detail = ` (${verdict.provider}, ${verdict.assessment}, conf ${verdict.confidence})`
          // A hold's approval resumes only under the key it was made with. The host
          // learns that from the receipt and from `held`; the refusal goes to the
          // agent, and saying it there would tell a hold from a block.
          const underAnotherKey = label === "judgment-held" && verdict.actionDigest !== action.digest
          const answered = ": this action already has this answer and was not judged again"
          const anotherKeyNote = underAnotherKey ? "; the hold was made under a different idempotency key, so approve and resume under that key" : ""
          const reason = `⚖ ${cfg.name} ${label}${detail}${answered}${anotherKeyNote}`
          const refusal = bound.rationaleInRefusal ? `⚖ ${cfg.name} ${label}${detail}${answered}` : `⚖ ${cfg.name} ${STOPPED_BY_JUDGMENT}`
          const receipt = cfg.log.append({ at: now(), sink: cfg.name, decision: label, args: rendered, reason, verdict })
          if (label === "judgment-blocked") return { ok: false, refusal, receipt }
          return {
            ok: false,
            refusal,
            receipt,
            held: Object.freeze({ verdictDigest: verdictDigest(verdict), actionDigest: verdict.actionDigest, grantHash: verdict.grantHash, ...(underAnotherKey ? { underAnotherKey: true as const } : {}) }),
          }
        }
      }
      if (attempted !== undefined) {
        const refusal = `⚠ ${cfg.name} refused: duplicate-action: this action has already been attempted, so it will not run again; a deliberate repeat needs a new idempotencyKey from the host`
        const receipt = cfg.log.append({ at: now(), sink: cfg.name, decision: "refused", args: rendered, reason: refusal, verdict: attempted })
        return { ok: false, refusal, receipt }
      }
      return undefined
    }

    // The one place a call that passed the walls runs and is recorded. The
    // decision names the MODE that let the call through. The old order
    // (`violations.length > 0 ? "warned" : …`) labelled an observe-mode call
    // WITH violations "warned", so `observed` only ever labelled a clean call
    // and a dirty one read as if the sink were in warn mode (the 2026-10-13
    // gate audit). The violations are on the receipt's reason either way.
    const passWalls = (run: JudgedRun | undefined): Promise<SinkResult<Awaited<R>>> => {
      const decision = cfg.mode === "observe" ? "observed" : violations.length > 0 ? "warned" : "executed"
      return act(
        decision,
        violations.length > 0 ? `mode=${cfg.mode}, violations: ${violations.join(" · ")}` : undefined,
        `${cfg.name} passed the walls and then threw — the action may or may not have taken effect`,
        `${cfg.name} passed the walls and was recorded as ${decision}`,
        run,
      )
    }

    // Judgment wall — probabilistic, self-aware. Every path out of this block
    // either returns or runs on a confident match: that is I4, and the only way
    // a judged enforce sink reaches execute.
    if (judge !== undefined && snapshot !== undefined && violations.length === undeclared) {
      const action = snapshot

      // ── The action's lifecycle (ADR 0010), in enforce only ─────────────────
      // Observe and warn run the action by definition, so they keep no record.
      // Up to `judging.set` nothing has been awaited on the first pass, so two
      // identical calls cannot both be the one deciding.
      let settled = (): void => {}
      if (cfg.mode === "enforce") {
        for (let wait = judging.get(action.unkeyed); wait !== undefined; wait = judging.get(action.unkeyed)) await wait
        const answer = standingAnswer(action, judge)
        if (answer !== undefined) return answer
        let release!: () => void
        judging.set(action.unkeyed, new Promise<void>((resolve) => { release = resolve }))
        settled = () => {
          judging.delete(action.unkeyed)
          release()
        }
      }

      const input = Object.freeze({
        purpose: judge.granted.purpose,
        action: Object.freeze({ sink: cfg.name, args: action.values }),
        trust: action.trust,
      })
      const providerName = judge.name

      try {
        // A provider that throws, rejects, runs out of time or answers with
        // something that is not a verdict HAS NOT SCORED. That exception used to
        // escape between the tier wall and the receipt (the 2026-10-13 gate
        // audit), and an unawaited Promise once read as a verdict and executed
        // (DAN-1382). No score is recorded as `unsure` at confidence 0, so the
        // receipt carries a digestible verdict that states the doubt, and it is
        // never mistaken for an answer: `scored` keeps a floor of 0 from admitting it.
        const answer = readVerdict(await consultJudge((signal) => judge.assess(input, signal), judge.timeoutMs))

        // Read the log again. `judging` only covers this sink object, and another
        // sink over the same log (per-request sinks are supported, ADR 0010) may
        // have decided or run this action while this judge was out. Nothing
        // between here and execute() awaits, so the first to get here wins.
        if (cfg.mode === "enforce") {
          const decidedElsewhere = standingAnswer(action, judge)
          if (decidedElsewhere !== undefined) return decidedElsewhere
        }
        const scored = !("failure" in answer)
        const rationaleText = scored ? answer.rationale : `provider ${providerName} gave no verdict: ${answer.failure}`

        const verdict: Verdict = Object.freeze({
          assessment: scored ? answer.assessment : "unsure",
          confidence: scored ? answer.confidence : 0,
          rationaleHash: sha256Hex(rationaleText),
          provider: providerName,
          model: judge.model,
          actionDigest: action.digest,
          unkeyedActionDigest: action.unkeyed,
          scored,
          paymentDigest: paymentDigestOfCall,
          grantHash: judge.granted.grantHash,
          purposeHash: judge.purposeHash,
          judgedAt: now(),
          attestation: null,
        })
        const digest = verdictDigest(verdict)
        const evidence = { at: now(), sink: cfg.name, args: rendered, verdict }
        const confText = scored ? `conf ${verdict.confidence.toFixed(2)}` : "no verdict"

        // Rationale is FREE TEXT from a provider that just saw the raw values
        // (adversarial pass A4, 2026-07-25). `redact` governed `args` and stopped
        // there, so a judge that echoed what it judged — the natural way to write
        // a rationale — republished the redacted value in `reason`, on the same
        // receipt that gets signed and anchored and can never be redacted after
        // the fact. Structured fields (assessment, confidence, provider name) are
        // safe because the provider does not author them; the prose is not.
        // A failure's text is the provider's too: an error message can echo.
        const anyRedacted = Object.values(cfg.redact ?? {}).some((p) => p !== undefined && p !== "raw")
        const rationale = anyRedacted
          ? `[rationale withheld — this sink redacts arguments; sha256:${createHash("sha256").update(rationaleText).digest("hex").slice(0, 16)}]`
          : rationaleText

        const confident = scored && verdict.confidence >= judge.floor
        // A real doubt on this action outlives its window (ADR 0010, DAN-1443). The
        // judge is still asked, because the owner needs a fresh hold to approve,
        // but only the owner can turn that doubt into a run. `standingAnswer`
        // above has already answered any doubt still inside its window, and
        // nothing has been awaited since it read the log.
        const earlier = cfg.mode === "enforce" ? actionState(action, judge).standing : undefined
        if (!(confident && verdict.assessment === "match") || earlier !== undefined) {
          if (cfg.mode === "enforce") {
            // Only a confident mismatch is a judgment. Everything else is doubt.
            const label = confident && verdict.assessment === "mismatch" ? "judgment-blocked" : "judgment-held"
            // The new sample alone would read as a clean match, so the receipt also
            // names the doubt the owner is being asked to answer.
            const earlierNote = earlier === undefined ? "" : `; an earlier ${earlier.label} (${earlier.verdict.provider}, ${earlier.verdict.assessment}, conf ${earlier.verdict.confidence}) on this action needs its owner`
            const receipt = cfg.log.append({ ...evidence, decision: label, reason: `⚖ ${cfg.name} ${label} (${providerName}, ${verdict.assessment}, ${confText}): ${rationale}${earlierNote}` })
            // The refusal goes to the agent. The judge's words, its assessment
            // and its confidence would each teach it what to change, so they come
            // back only when the host opts in (ADR 0010).
            const refusal = `⚖ ${cfg.name} ${judge.rationaleInRefusal ? label : STOPPED_BY_JUDGMENT}${judge.rationaleInRefusal ? ` (${providerName}, ${verdict.assessment}, ${confText}): ${rationaleText}${earlier === undefined ? "" : "; an earlier doubt on this action needs its owner"}` : ""}`
            if (label === "judgment-blocked") return { ok: false, refusal, receipt }
            return {
              ok: false,
              refusal,
              receipt,
              held: Object.freeze({ verdictDigest: digest, actionDigest: action.digest, grantHash: judge.granted.grantHash }),
            }
          }
          // Observe or warn: nothing is held, and the doubt is on the receipt.
          // It carries no `authorizedBy`: a flagged action is not an authorized one.
          const violationsNote = violations.length > 0 ? ` · violations: ${violations.join(" · ")}` : ""
          const note = `⚖ ${cfg.name} judgment-flagged (${verdict.assessment}, ${confText}): ${rationale}${violationsNote}`
          return act("judgment-flagged", note, `${note} — then threw; the action may or may not have taken effect`, note, {
            args: action.sourced,
            verdict,
          })
        }
        // A call the sink itself flagged carries no authority, even on a match.
        return passWalls(
          violations.length > 0
            ? { args: action.sourced, verdict }
            : { args: action.sourced, verdict, authorizedBy: Object.freeze({ verdictDigest: digest, paymentDigest: paymentDigestOfCall }) },
        )
      } finally {
        // Reached with the decision's receipt on the log and, on a run, with
        // `attempted` written and execute() already called: act() runs to its
        // first await before returning its promise. Anyone waiting answers from that.
        settled()
      }
    }

    return passWalls(undefined)
  }

  // Two wrappers, so `resuming` cannot be reached positionally: a caller who
  // passes an approval to the sink itself gets an ordinary judged call. Frozen
  // so that nothing holding the sink can swap what `resume` does.
  return Object.freeze(
    Object.assign((args: Args, options?: SinkCallOptions) => call(args, undefined, options), {
      /**
       * Release a held action with the owner's approval (spec § 3.3). Runs
       * the frozen copy of `args` and skips the judge. Refused otherwise with
       * `approval-unsigned`, `approval-expired`, `approval-mismatch` or
       * `approval-replayed` in the refusal string and a `refused` receipt.
       * A held call that named an idempotency key is resumed with the same key.
       */
      resume: (args: Args, approval: Approval, options?: SinkCallOptions) => call(args, { approval }, options),
    }),
  )
}
