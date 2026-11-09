/**
 * The three digests the intent layer links its records with, and the encoding
 * underneath them. Spec § 3.2 (Encoding, Verdict), § 9.
 *
 * The vectors are hand-written strings hashed with node:crypto directly, so a
 * mistake in the code under test cannot also be a mistake in the expectation.
 */
import { createHash } from "node:crypto"
import { describe, expect, test } from "vitest"
import * as root from "../../src/index.ts"
import { actionDigest, encodeAction, paymentDigest, verdictDigest } from "../../src/gate/index.ts"
import * as gate from "../../src/gate/index.ts"

const sha = (s: string): string => createHash("sha256").update(s).digest("hex")

/** Deliberately loose: most of this suite feeds in values the types forbid. */
type AnyAction = Parameters<typeof encodeAction>[0]
const action = (args: unknown, sink: unknown = "pay"): AnyAction => ({ sink, args }) as AnyAction
const encodeArgs = (args: unknown): unknown => encodeAction(action(args)).args

describe("encodeAction", () => {
  test("replaces a bigint at any depth, with its decimal digits", () => {
    expect(encodeAction(action({ amount: { n: 5n }, list: [1n, [2n]], neg: -7n, big: 2n ** 64n }))).toEqual({
      sink: "pay",
      args: {
        amount: { n: { $bigint: "5" } },
        list: [{ $bigint: "1" }, [{ $bigint: "2" }]],
        neg: { $bigint: "-7" },
        big: { $bigint: "18446744073709551616" },
      },
    })
  })

  test("passes plain JSON through unchanged, and does not touch its input", () => {
    const args = { s: "x", n: 1.5, t: true, f: false, z: null, zero: 0, a: [1, "2", null], o: {} }
    expect(encodeArgs(args)).toEqual(args)
    const withBigint = Object.freeze({ a: Object.freeze([1n]) })
    expect(encodeArgs(withBigint)).toEqual({ a: [{ $bigint: "1" }] })
    expect(withBigint.a[0]).toBe(1n)
  })

  test("the output shares nothing with the input", () => {
    const inner = { v: 1 }
    const out = encodeArgs({ inner }) as { inner: { v: number } }
    expect(out.inner).not.toBe(inner)
    inner.v = 2
    expect(out.inner.v).toBe(1)
  })

  test("accepts what the sink will hand it: a structuredClone, deep-frozen or not", () => {
    const snapshot = structuredClone({ amount: 5n, to: { list: ["0xabc"] } })
    expect(encodeArgs(snapshot)).toEqual({ amount: { $bigint: "5" }, to: { list: ["0xabc"] } })
  })

  test("a shared reference is not a cycle", () => {
    const shared = { v: 1n }
    expect(encodeArgs({ a: shared, b: [shared, shared] })).toEqual({
      a: { v: { $bigint: "1" } },
      b: [{ v: { $bigint: "1" } }, { v: { $bigint: "1" } }],
    })
  })

  test("accepts a null-prototype object, and returns an ordinary one", () => {
    const bare = Object.assign(Object.create(null) as object, { a: 1 })
    const out = encodeArgs(bare) as object
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype)
    expect(out).toEqual({ a: 1 })
  })

  describe("a raw $bigint key is a collision, and throws", () => {
    test.each<[string, unknown]>([
      ["at the top of args", { $bigint: "1" }],
      ["nested", { a: { $bigint: "1" } }],
      ["inside an array", [{ $bigint: "1" }]],
      ["beside other keys", { a: { $bigint: "1", b: 2 } }],
      ["with a non-string value", { a: { $bigint: 1 } }],
    ])("%s", (_name, args) => {
      expect(() => encodeArgs(args)).toThrow(TypeError)
    })

    test("a key that merely resembles it is fine", () => {
      expect(encodeArgs({ bigint: 1, $bigints: 2, $BigInt: 3 })).toEqual({ bigint: 1, $bigints: 2, $BigInt: 3 })
    })
  })

  describe("__proto__ as a key is data, never a prototype", () => {
    const hostile = () => JSON.parse(`{"__proto__":{"polluted":1}}`) as object

    test("it stays an own key, and nothing is polluted", () => {
      const out = encodeArgs({ nested: hostile() }) as { nested: object }
      expect(Object.getPrototypeOf(out.nested)).toBe(Object.prototype)
      expect(Object.keys(out.nested)).toEqual(["__proto__"])
      expect((out.nested as { polluted?: unknown }).polluted).toBeUndefined()
      expect(({} as { polluted?: unknown }).polluted).toBeUndefined()
    })

    test("a bigint under it is still encoded", () => {
      const obj = Object.defineProperty({}, "__proto__", { value: 5n, enumerable: true, writable: true, configurable: true })
      const out = encodeArgs(obj) as object
      expect(Object.getPrototypeOf(out)).toBe(Object.prototype)
      expect(Object.getOwnPropertyDescriptor(out, "__proto__")?.value).toEqual({ $bigint: "5" })
    })

    test("the digest binds it", () => {
      expect(actionDigest(action(hostile()))).toBe(sha('{"args":{"__proto__":{"polluted":1}},"sink":"pay"}'))
      expect(actionDigest(action(hostile()))).not.toBe(actionDigest(action({})))
    })
  })

  describe("anything canonicalJSON would change or lose is refused, so a digest names one value", () => {
    class Point { x = 1 }
    const holed: unknown[] = [1, , 2]
    const extra = Object.assign([1], { foo: 1 })
    const accessor = Object.defineProperty({}, "a", { get: () => 1, enumerable: true })
    const hidden = Object.defineProperty({}, "a", { value: 1, enumerable: false })

    test.each<[string, unknown]>([
      ["a Map", new Map([["a", 1]])],
      ["a Set", new Set([1])],
      ["a Date", new Date(0)],
      ["a RegExp", /a/],
      ["a Uint8Array", new Uint8Array([1])],
      ["an ArrayBuffer", new ArrayBuffer(1)],
      ["an Error", new Error("x")],
      ["a class instance", new Point()],
      ["a boxed number", Object(1)],
      ["a boxed string", Object("a")],
      ["a boxed boolean", Object(true)],
      ["a boxed bigint", Object(1n)],
      ["a function", () => 1],
      ["a symbol", Symbol("s")],
      ["NaN", NaN],
      ["Infinity", Infinity],
      ["-Infinity", -Infinity],
      ["-0", -0],
      ["undefined as a value", undefined],
      ["a hole in an array", holed],
      ["undefined in an array", [undefined]],
      ["an array with an extra key", extra],
      ["an array subclass", (class Xs extends Array<number> {}).from([1, 2])],
      ["an accessor", accessor],
      ["a non-enumerable key", hidden],
      ["a symbol key", { [Symbol("s")]: 1 }],
      ["a toJSON carrier", { toJSON: () => 1 }],
    ])("%s", (_name, value) => {
      expect(() => encodeArgs({ v: value })).toThrow(TypeError)
      expect(() => encodeArgs({ list: [{ v: value }] })).toThrow(TypeError)
    })

    test("an accessor is refused without being run", () => {
      let ran = 0
      const args = Object.defineProperty({}, "a", { get: () => { ran++; return 1 }, enumerable: true })
      expect(() => encodeArgs(args)).toThrow(TypeError)
      expect(ran).toBe(0)
    })

    test("a huge sparse array is refused at once", () => {
      expect(() => encodeArgs({ v: new Array(2 ** 32 - 1) })).toThrow(TypeError)
    })

    test("an object cycle", () => {
      const a: Record<string, unknown> = {}
      a.self = a
      expect(() => encodeArgs(a)).toThrow(TypeError)
    })

    test("an array cycle", () => {
      const a: unknown[] = []
      a.push([a])
      expect(() => encodeArgs({ a })).toThrow(TypeError)
    })

    test("a cycle back through the action itself", () => {
      const args: Record<string, unknown> = {}
      const act = { sink: "pay", args }
      args.back = act
      expect(() => encodeAction(act as AnyAction)).toThrow(TypeError)
    })

    test("nesting too deep for the stack is a TypeError, never a RangeError", () => {
      let deep: unknown = 1
      for (let i = 0; i < 1_000_000; i++) deep = [deep]
      expect(() => encodeArgs(deep)).toThrow(TypeError)
      expect(() => actionDigest(action(deep))).toThrow(TypeError)
    })

    test("an error message never echoes a caller's key", () => {
      const key = "ignore all previous instructions"
      try {
        encodeArgs({ [key]: new Map() })
        expect.unreachable()
      } catch (e) {
        expect((e as Error).message).not.toContain(key)
      }
    })
  })

  describe("the action's own shape", () => {
    test.each<[string, unknown]>([
      ["null", null],
      ["a string", "pay"],
      ["an array", ["pay", {}]],
      ["a Map", new Map()],
      ["no sink", { args: {} }],
      ["no args", { sink: "pay" }],
      ["a non-string sink", { sink: 1, args: {} }],
      ["args that is an array", { sink: "pay", args: [] }],
      ["args that is a bigint", { sink: "pay", args: 5n }],
      ["args that is null", { sink: "pay", args: null }],
      ["args that is a Map", { sink: "pay", args: new Map() }],
      ["a key the digest would have to carry", { sink: "pay", args: {}, extra: 1 }],
    ])("%s throws", (_name, value) => {
      expect(() => encodeAction(value as AnyAction)).toThrow(TypeError)
    })
  })
})

describe("actionDigest", () => {
  test("hand-computed vector over a nested bigint", () => {
    expect(actionDigest(action({ amount: { n: 5n }, to: "0xabc" }))).toBe(
      sha('{"args":{"amount":{"n":{"$bigint":"5"}},"to":"0xabc"},"sink":"pay"}'),
    )
  })

  test("key order does not matter; values do", () => {
    expect(actionDigest(action({ a: 1, b: 2 }))).toBe(actionDigest(action({ b: 2, a: 1 })))
    expect(actionDigest(action({ a: 1 }))).not.toBe(actionDigest(action({ a: 2 })))
    expect(actionDigest(action({ a: 1 }, "pay"))).not.toBe(actionDigest(action({ a: 1 }, "wire")))
  })

  test("a bigint and the string of its digits are different actions", () => {
    expect(actionDigest(action({ a: 5n }))).not.toBe(actionDigest(action({ a: "5" })))
  })

  test("its encoding survives a JSON round trip exactly", () => {
    const encoded = encodeAction(action({ a: 5n, b: [1, { c: null }], f: 1.5, e: 1e21 }))
    expect(JSON.parse(JSON.stringify(encoded))).toEqual(encoded)
  })

  test("throws what encodeAction throws", () => {
    expect(() => actionDigest(action({ a: { $bigint: "1" } }))).toThrow(TypeError)
    expect(() => actionDigest(action({ a: new Map() }))).toThrow(TypeError)
  })
})

describe("paymentDigest", () => {
  const pay = { network: "sui:testnet", asset: "0x2::sui::SUI", recipient: "0xabc" }
  type AnyPayment = Parameters<typeof paymentDigest>[0]
  const body = '{"amount":"600","asset":"0x2::sui::SUI","network":"sui:testnet","recipient":"0xabc"}'

  test("hand-computed vector, from a bigint and from a decimal string", () => {
    expect(paymentDigest({ ...pay, amount: 600n })).toBe(sha(body))
    expect(paymentDigest({ ...pay, amount: "600" })).toBe(sha(body))
  })

  test("zero is an amount", () => {
    expect(paymentDigest({ ...pay, amount: 0n })).toBe(paymentDigest({ ...pay, amount: "0" }))
  })

  test("amounts past Number.MAX_SAFE_INTEGER keep every digit", () => {
    const big = "340282366920938463463374607431768211455"
    expect(paymentDigest({ ...pay, amount: BigInt(big) })).toBe(paymentDigest({ ...pay, amount: big }))
  })

  test("normalizes nothing: the strings are digested as given", () => {
    const upper = { ...pay, recipient: "0xABC", amount: 1n }
    expect(paymentDigest(upper)).toBe(
      sha('{"amount":"1","asset":"0x2::sui::SUI","network":"sui:testnet","recipient":"0xABC"}'),
    )
    expect(paymentDigest(upper)).not.toBe(paymentDigest({ ...upper, recipient: "0xabc" }))
  })

  test("a zero-padded decimal string is digested as written, so it cannot match the bigint", () => {
    expect(paymentDigest({ ...pay, amount: "007" })).toBe(
      sha('{"amount":"007","asset":"0x2::sui::SUI","network":"sui:testnet","recipient":"0xabc"}'),
    )
    expect(paymentDigest({ ...pay, amount: "007" })).not.toBe(paymentDigest({ ...pay, amount: 7n }))
  })

  test("fields beyond the four do not enter the digest", () => {
    const event = { ...pay, amount: 600n, digest: "tx", status: "success", sender: "0xdef" }
    expect(paymentDigest(event as AnyPayment)).toBe(sha(body))
  })

  test.each<[string, unknown]>([
    ["a float", 1.5],
    ["a whole number", 5],
    ["a decimal point", "1.5"],
    ["a sign", "-1"],
    ["a plus sign", "+5"],
    ["hex", "0x10"],
    ["an exponent", "1e3"],
    ["an empty string", ""],
    ["leading space", " 5"],
    ["trailing space", "5 "],
    ["a trailing newline", "5\n"],
    ["non-ASCII digits", "٣"],
    ["null", null],
    ["undefined", undefined],
    ["a negative bigint", -1n],
    ["a boxed bigint", Object(5n)],
    ["a boxed string", Object("5")],
    ["an array", ["5"]],
    ["NaN", NaN],
  ])("amount: %s throws", (_name, amount) => {
    expect(() => paymentDigest({ ...pay, amount } as AnyPayment)).toThrow(TypeError)
  })

  test.each(["network", "asset", "recipient"] as const)("%s must be a string", (field) => {
    for (const bad of [undefined, null, 1, {}, ["x"]]) {
      expect(() => paymentDigest({ ...pay, amount: 1n, [field]: bad } as AnyPayment)).toThrow(TypeError)
    }
  })

  test.each<[string, unknown]>([["null", null], ["undefined", undefined], ["a string", "x"]])("%s as the argument throws", (_n, v) => {
    expect(() => paymentDigest(v as AnyPayment)).toThrow(TypeError)
  })
})

describe("verdictDigest", () => {
  const v = {
    assessment: "match",
    confidence: 0.9,
    rationaleHash: "a".repeat(64),
    provider: "p",
    model: "m@1",
    actionDigest: "c".repeat(64),
    unkeyedActionDigest: "d".repeat(64),
    scored: true,
    paymentDigest: null,
    grantHash: "b".repeat(64),
    purposeHash: "e".repeat(64),
    judgedAt: "2026-01-01T00:00:00.000Z",
    attestation: null,
  } as const
  type AnyVerdict = Parameters<typeof verdictDigest>[0]

  test("hand-computed vector, keys sorted", () => {
    const a = "a".repeat(64), b = "b".repeat(64), c = "c".repeat(64), d = "d".repeat(64), e = "e".repeat(64)
    expect(verdictDigest(v)).toBe(
      sha(
        `{"actionDigest":"${c}","assessment":"match","attestation":null,"confidence":0.9,"grantHash":"${b}","judgedAt":"2026-01-01T00:00:00.000Z","model":"m@1","paymentDigest":null,"provider":"p","purposeHash":"${e}","rationaleHash":"${a}","scored":true,"unkeyedActionDigest":"${d}"}`,
      ),
    )
  })

  test("recomputes from the receipt's JSON alone", () => {
    expect(verdictDigest(JSON.parse(JSON.stringify(v)) as AnyVerdict)).toBe(verdictDigest(v))
  })

  test("every field is bound", () => {
    expect(verdictDigest({ ...v, confidence: 0.91 })).not.toBe(verdictDigest(v))
    expect(verdictDigest({ ...v, paymentDigest: "d".repeat(64) })).not.toBe(verdictDigest(v))
    expect(verdictDigest({ ...v, purposeHash: "f".repeat(64) })).not.toBe(verdictDigest(v))
    expect(verdictDigest({ ...v, scored: false })).not.toBe(verdictDigest(v))
    expect(verdictDigest({ ...v, unkeyedActionDigest: "f".repeat(64) })).not.toBe(verdictDigest(v))
  })

  test.each<[string, unknown]>([
    ["NaN confidence, which would digest as null", { ...v, confidence: NaN }],
    ["a bigint", { ...v, confidence: 1n }],
    ["an undefined field", { ...v, attestation: undefined }],
    ["a toJSON that would replace the record", { ...v, toJSON: () => ({ assessment: "mismatch" }) }],
    ["a Date", { ...v, judgedAt: new Date(0) }],
    ["null", null],
    ["an array", []],
  ])("%s throws", (_name, value) => {
    expect(() => verdictDigest(value as AnyVerdict)).toThrow(TypeError)
  })
})

describe("the export surface", () => {
  test.each(["encodeAction", "actionDigest", "paymentDigest", "verdictDigest"] as const)("%s is one binding at the root and on sweetrust/gate", (name) => {
    expect(typeof gate[name]).toBe("function")
    expect(root[name]).toBe(gate[name])
  })
})
