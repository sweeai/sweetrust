/**
 * Property-based floor for canonicalJSON (DAN-631, item 1).
 *
 * Two example-escaping bugs in a row motivated this file: the undefined-key
 * drop (caught pre-0.9.0) and the array-hole/toJSON divergence (caught in the
 * 2026-07-21 pre-publish review, AFTER 700+ example tests passed). The
 * property below kills the whole class: canonicalJSON must agree with
 * JSON.stringify semantics on every JSON-representable value, differing only
 * in key order.
 */
import { describe, expect, it } from "vitest"
import fc from "fast-check"
import { canonicalJSON, makeEd25519SignerLive, MANDATE_AUDIT_DOMAIN } from "../../src/mandate/signer.ts"
import { generateSigningKeypair } from "../../src/verify/verify.ts"

/** Arbitrary JSON-ish values, deliberately hostile: undefined holes, toJSON
 * carriers (Date), unicode keys/strings, -0, huge and tiny numbers. */
const jsonish: fc.Arbitrary<unknown> = fc.letrec<{ value: unknown }>((tie) => ({
  value: fc.oneof(
    { maxDepth: 6, withCrossShrink: true },
    fc.constant(null),
    fc.constant(undefined),
    fc.boolean(),
    fc.double({ noNaN: false }),
    fc.integer(),
    fc.constantFrom(-0, 0, 1e21, 5e-324, Number.MAX_SAFE_INTEGER + 1),
    fc.fullUnicodeString(),
    fc.date({ noInvalidDate: true }),
    // The 2026-10-13 verify audit: boxed primitives, toJSON carriers that
    // return ANY value (so a carrier can return another carrier), and a
    // toJSON that reads its key argument. All three diverged from
    // JSON.stringify before the audit.
    fc.fullUnicodeString().map((v) => new String(v)),
    fc.double().map((v) => new Number(v)),
    fc.boolean().map((v) => new Boolean(v)),
    tie("value").map((inner) => ({ toJSON: () => inner })),
    fc.constant({ toJSON: (k: string) => `key=${k}` }),
    fc.array(tie("value"), { maxLength: 6 }),
    fc.dictionary(fc.fullUnicodeString({ maxLength: 8 }), tie("value"), { maxKeys: 6 })
  ),
})).value

const shuffleKeys = (value: unknown): unknown => {
  if (value === null || typeof value !== "object") return value
  // Leave boxed primitives and toJSON carriers (Date included) whole: their
  // own keys are not what they serialize as.
  if (value instanceof String || value instanceof Number || value instanceof Boolean) return value
  if (typeof (value as { toJSON?: unknown }).toJSON === "function") return value
  if (Array.isArray(value)) return value.map(shuffleKeys)
  const record = value as Record<string, unknown>
  const out: Record<string, unknown> = {}
  for (const k of Object.keys(record).reverse()) out[k] = shuffleKeys(record[k])
  return out
}

describe("canonicalJSON properties (differential oracle vs JSON.stringify)", () => {
  it("parses as JSON and round-trip-equals JSON.stringify semantics, for arbitrary hostile values", () => {
    fc.assert(
      fc.property(jsonish, (x: unknown) => {
        const reference = JSON.stringify(x)
        const canonical = canonicalJSON(x)
        if (reference === undefined) {
          // top-level undefined/function: stringify yields nothing; canonical must agree
          expect(canonical).toBeUndefined()
          return
        }
        // 1. canonical bytes are valid JSON (the "[1,,2]" bug dies here)
        const parsedCanonical = JSON.parse(canonical)
        // 2. identical VALUE to what a JSON round-trip of the input yields
        //    (the Date-signs-as-{} bug dies here); key order is the only
        //    permitted difference, and deep equality ignores it
        expect(parsedCanonical).toEqual(JSON.parse(reference))
      }),
      { numRuns: 2000 }
    )
  })

  it("is key-order independent: shuffled-key clones canonicalize byte-identically", () => {
    fc.assert(
      fc.property(jsonish, (x: unknown) => {
        if (JSON.stringify(x) === undefined) return
        expect(canonicalJSON(shuffleKeys(x))).toBe(canonicalJSON(x))
      }),
      { numRuns: 1000 }
    )
  })

  it("is deterministic across invocations", () => {
    fc.assert(
      fc.property(jsonish, (x: unknown) => {
        if (JSON.stringify(x) === undefined) return
        expect(canonicalJSON(x)).toBe(canonicalJSON(x))
      }),
      { numRuns: 500 }
    )
  })
})

describe("pinned regression corpus (bugs we actually shipped or nearly shipped)", () => {
  it("array holes render as null, not as invalid JSON (2026-07-21 blocker)", () => {
    expect(canonicalJSON([1, undefined, 2])).toBe("[1,null,2]")
    expect(() => JSON.parse(canonicalJSON([1, undefined, 2]))).not.toThrow()
  })

  it("TRUE elision holes (sparse arrays) render as null, not as invalid JSON (DAN-646)", () => {
    // The 2026-07-21 fix used [1, undefined, 2] — a DENSE array; Array.prototype.map
    // visits it, so the bug hid. A real hole (`[1,,2]`, `new Array(3)`) is skipped by
    // .map, so the old code emitted "[1,,2]" / "[,,]" — invalid JSON. Index iteration fixes it.
    // eslint-disable-next-line no-sparse-arrays
    expect(canonicalJSON([1, , 2])).toBe("[1,null,2]")
    expect(canonicalJSON(new Array(3))).toBe("[null,null,null]")
    // eslint-disable-next-line no-sparse-arrays
    expect(() => JSON.parse(canonicalJSON([1, , 2]))).not.toThrow()
    expect(() => JSON.parse(canonicalJSON(new Array(3)))).not.toThrow()
    // matches JSON.stringify, which also nulls holes
    // eslint-disable-next-line no-sparse-arrays
    expect(canonicalJSON([1, , 2])).toBe(JSON.stringify([1, , 2]))
  })

  it("toJSON carriers (Date) sign as their JSON form, not as {} (2026-07-21 blocker)", () => {
    const d = new Date(0)
    expect(canonicalJSON({ t: d })).toBe('{"t":"1970-01-01T00:00:00.000Z"}')
  })

  it("undefined-valued keys are dropped (the original pre-0.9.0 catch)", () => {
    expect(canonicalJSON({ a: 1, b: undefined })).toBe('{"a":1}')
  })

  it("function/symbol values behave like JSON.stringify (dropped as keys, null in arrays)", () => {
    expect(canonicalJSON({ a: 1, f: () => 1 })).toBe('{"a":1}')
    expect(canonicalJSON([() => 1, Symbol("s")])).toBe("[null,null]")
  })

  it("NaN and Infinity render as null, matching JSON.stringify", () => {
    expect(canonicalJSON([NaN, Infinity, -Infinity])).toBe("[null,null,null]")
  })
})

describe("the 2026-10-13 verify audit: the five rows where canonicalJSON diverged from JSON.stringify", () => {
  // Each row is asserted twice: the exact bytes, and the differential oracle.
  // The invariant comment above canonicalJSON claims these agree; before the
  // audit it was false for every row here.
  const row = (label: string, value: unknown, bytes: string) => {
    it(label, () => {
      expect(canonicalJSON(value)).toBe(bytes)
      expect(JSON.parse(canonicalJSON(value))).toEqual(JSON.parse(JSON.stringify(value)))
    })
  }
  row("boxed String serializes as its string", { s: new String("ab") }, '{"s":"ab"}')
  row("boxed Number serializes as its number", { n: new Number(5) }, '{"n":5}')
  row("boxed Boolean serializes as its boolean", { b: new Boolean(false) }, '{"b":false}')
  row("toJSON is applied ONCE: a carrier returned by toJSON is serialized as a plain object", { t: { toJSON: () => ({ toJSON: () => "inner" }) } }, '{"t":{}}')
  row("toJSON receives the property key", { t: { toJSON: (k: string) => `key=${k}` } }, '{"t":"key=t"}')
  row("toJSON receives the array index as a string", [{ toJSON: (k: string) => `key=${k}` }], '["key=0"]')
  row("toJSON at the top level receives the empty key", { toJSON: (k: string) => `key=[${k}]` }, '"key=[]"')
  row("a boxed primitive returned by toJSON is unwrapped (toJSON first, then unboxing)", { t: { toJSON: () => new Number(7) } }, '{"t":7}')

  it("consequence: a record signed over a boxed-String payload verifies after a JSON round trip", () => {
    // Before the audit the signer signed {"note":{"0":"a","1":"b"}} and the
    // exported record carried {"note":"ab"}, so an honest record failed to
    // verify the moment it left memory.
    const signer = makeEd25519SignerLive(generateSigningKeypair())
    for (const payload of [
      { type: "grant", note: new String("ab") },
      { type: "grant", note: { toJSON: () => ({ toJSON: () => "inner" }) } },
    ]) {
      const rec = signer.sign({ payload, previousHash: null, domain: MANDATE_AUDIT_DOMAIN })
      expect(signer.verify(rec)).toBe(true)
      expect(signer.verify(JSON.parse(JSON.stringify(rec)))).toBe(true)
    }
  })
})
