/**
 * Doubt never moves money (0.6.0, DAN-1386, spec §§ 3.2, 3.3, I1, I2, I4).
 *
 * In enforce mode a judged action runs only on a match at or above the floor,
 * and every judged action leaves a verdict the receipt can prove:
 *   - every doubt case is `judgment-held`, and `execute` never runs
 *   - purpose fields are checked before the judge, and refuse like the tier wall
 *   - what runs is a frozen snapshot, the same bytes the judge saw and digested
 *   - the verdict is inside the receipt hash, and an unjudged receipt is unchanged
 */
import { describe, expect, it } from "vitest"
import { sha256Hex } from "../../src/canon.ts"
import {
  SpendAuthorization,
  actionDigest,
  encodeAction,
  makeSink,
  paymentDigest,
  ReceiptLog,
  receiptBody,
  Sourced,
  verdictDigest,
  type GrantedPurpose,
  type JudgmentProvider,
  type Receipt,
  type Verdict,
} from "../../src/gate/index.ts"
import { generateSigningKeypair, makeEd25519ReceiptSigner, parseJSONL, publicKeyHexFromPem, SignedReceiptLog, verifySignedChain } from "../../src/verify/index.ts"
import { GRANTED } from "../helpers/granted.ts"
import { poison } from "../helpers/poison.ts"

const HEX64 = /^[0-9a-f]{64}$/
const later = <A>(answer: A, ms = 2) => new Promise<A>((resolve) => setTimeout(() => resolve(answer), ms))

const MATCH = { assessment: "match", confidence: 0.9, rationale: "fits" }
const UNSURE = { assessment: "unsure", confidence: 0.5, rationale: "unclear" }
const MISMATCH = { assessment: "mismatch", confidence: 0.9, rationale: "wrong" }

const spy = (assess: JudgmentProvider["assess"]) => {
  const calls: Array<Parameters<JudgmentProvider["assess"]>[0]> = []
  const provider: JudgmentProvider = {
    name: "judge",
    model: "judge@1",
    assess: (input, signal) => {
      calls.push(input)
      return assess(input, signal)
    },
  }
  return { provider, calls }
}
const answering = (answer: unknown) => spy(async () => answer as never)

type Mode = "observe" | "warn" | "enforce"
interface Opts {
  mode?: Mode
  floor?: number
  timeoutMs?: number
  granted?: GrantedPurpose
  redact?: Record<string, "raw" | "hash" | "truncate">
  judgmentExtra?: Record<string, unknown>
  requires?: Record<string, "untrusted" | "corroborated" | "verified">
  name?: string
  execute?: (args: any, ctx: any) => unknown
}
const judged = (provider: JudgmentProvider, opts: Opts = {}) => {
  const log = new ReceiptLog()
  const runs: Array<{ args: Record<string, Sourced<unknown>>; ctx: any }> = []
  const sink = makeSink<any, unknown>({
    name: opts.name ?? "pay",
    requires: opts.requires ?? { to: "verified", amount: "verified" },
    mode: opts.mode ?? "enforce",
    log,
    ...(opts.redact === undefined ? {} : { redact: opts.redact }),
    judgment: {
      provider,
      floor: opts.floor ?? 0.7,
      granted: opts.granted ?? GRANTED,
      ...(opts.timeoutMs === undefined ? {} : { timeoutMs: opts.timeoutMs }),
      ...(opts.judgmentExtra ?? {}),
    } as never,
    execute: (args: any, ctx: any) => {
      runs.push({ args, ctx })
      return opts.execute ? opts.execute(args, ctx) : "sent"
    },
  })
  return { log, runs, sink }
}
const auth = <T>(value: T) => Sourced.fromAuthority(value, "owner")
const pay = (to: unknown = "0xabc", amount: unknown = "5") => ({ to: auth(to), amount: auth(amount) })

const NETWORK = { network: "sui:testnet", asset: "0x2::sui::SUI" }
const PURPOSE_ARGS = { purposeArgs: { payee: "to", amount: "amount" }, ...NETWORK }
const withFields = (fields: Record<string, unknown>): GrantedPurpose => ({
  purpose: { statement: "Pay the invoices the owner approved", fields },
  grantHash: "b".repeat(64),
})

/** A receipt must carry a verdict that reproduces the digest it was linked by. */
const expectProvable = (receipt: Receipt, digest: string, action: string) => {
  const v = receipt.verdict as Verdict
  expect(v).toBeDefined()
  expect(verdictDigest(v)).toBe(digest)
  expect(v.actionDigest).toBe(action)
  expect(v.rationaleHash).toMatch(HEX64)
  expect(v.attestation).toBeNull()
  expect(Object.keys(v)).not.toContain("rationale")
}

describe("I4: in enforce, every doubt case is judgment-held and execute never runs", () => {
  const thrower = (err: unknown): JudgmentProvider["assess"] => () => { throw err }
  const cases: Array<[string, JudgmentProvider["assess"]]> = [
    ["unsure at high confidence", async () => ({ ...UNSURE, confidence: 0.99 }) as never],
    ["unsure at low confidence", async () => UNSURE as never],
    ["a match below the floor", async () => ({ ...MATCH, confidence: 0.69 }) as never],
    ["a mismatch below the floor", async () => ({ ...MISMATCH, confidence: 0.69 }) as never],
    ["a synchronous throw", thrower(new Error("scorer down"))],
    ["a rejected promise", async () => { throw new Error("503") }],
    ["a rejection that cannot be rendered", () => Promise.reject(Object.create(null))],
    ["null", async () => null as never],
    ["undefined", async () => undefined as never],
    ["a string", async () => "match" as never],
    ["a number", async () => 7 as never],
    ["an array", async () => [] as never],
    ["an unknown assessment", async () => ({ ...MATCH, assessment: "perhaps" }) as never],
    ["an inherited assessment", async () => Object.create(MATCH) as never],
    ["a NaN confidence", async () => ({ ...MATCH, confidence: NaN }) as never],
    ["an Infinity confidence", async () => ({ ...MATCH, confidence: Infinity }) as never],
    ["a confidence above 1", async () => ({ ...MATCH, confidence: 1.5 }) as never],
    ["a confidence below 0", async () => ({ ...MATCH, confidence: -0.1 }) as never],
    ["a string confidence", async () => ({ ...MATCH, confidence: "0.9" }) as never],
    ["no confidence", async () => ({ assessment: "match", rationale: "fits" }) as never],
    ["a mismatch with a NaN confidence", async () => ({ ...MISMATCH, confidence: NaN }) as never],
    ["a getter that throws", async () => ({ get assessment() { throw new Error("gotcha") } }) as never],
  ]

  it.each(cases)("%s", async (_label, assess) => {
    const { sink, log, runs } = judged(spy(assess).provider)
    const r = await sink(pay())
    expect(r.ok).toBe(false)
    expect(runs).toHaveLength(0)
    expect(r.receipt.decision).toBe("judgment-held")
    expect(log.all().map((x) => x.decision)).toEqual(["judgment-held"])
    if (r.ok || r.held === undefined) throw new Error("expected a held result")
    expect(r.refusal).toContain("judgment-held")
    expect(r.held.verdictDigest).toMatch(HEX64)
    expect(r.held.grantHash).toBe(GRANTED.grantHash)
    expect(r.held.actionDigest).toBe(actionDigest({ sink: "pay", args: { to: "0xabc", amount: "5" } }))
    expect(Object.keys(r.held).sort()).toEqual(["actionDigest", "grantHash", "verdictDigest"])
    expectProvable(r.receipt, r.held.verdictDigest, r.held.actionDigest)
    expect(log.verifyChain()).toBe(true)
  })

  it("a timeout is held, the signal fires, and a late match never executes", async () => {
    let signal!: AbortSignal
    const { provider } = spy((_input, s) => {
      signal = s
      return later(MATCH, 30) as never
    })
    const { sink, runs, log } = judged(provider, { timeoutMs: 5 })
    const r = await sink(pay())
    expect(r.receipt.decision).toBe("judgment-held")
    expect(r.ok ? undefined : r.refusal).toBe("⚖ pay judgment-held")
    expect(r.receipt.reason).toContain("no verdict within 5ms")
    expect(signal.aborted).toBe(true)
    await later(null, 50)
    expect(runs).toHaveLength(0)
    expect(log.all().map((x) => x.decision)).toEqual(["judgment-held"])
  })

  it("a held receipt written when the provider threw still names a verdict, and records the doubt, not a guess", async () => {
    const { sink } = judged(spy(() => { throw new Error("scorer down") }).provider)
    const r = await sink(pay())
    const v = r.receipt.verdict!
    expect(v.assessment).toBe("unsure")
    expect(v.confidence).toBe(0)
    expect(v.provider).toBe("judge")
    expect(v.model).toBe("judge@1")
    expect(r.receipt.reason).toContain("scorer down")
  })

  it("floor 0: a provider failure is still held, though its recorded confidence is 0", async () => {
    const { sink, runs } = judged(spy(() => { throw new Error("down") }).provider, { floor: 0 })
    expect((await sink(pay())).receipt.decision).toBe("judgment-held")
    expect(runs).toHaveLength(0)
  })

  it("-0 is a confidence of 0 and does not break the digest", async () => {
    const { sink, runs } = judged(answering({ ...MATCH, confidence: -0 }).provider)
    const r = await sink(pay())
    expect(r.receipt.decision).toBe("judgment-held")
    expect(Object.is(r.receipt.verdict!.confidence, 0)).toBe(true)
    expect(runs).toHaveLength(0)
  })

  it("a second identical call while the hold is open answers from it, on a new receipt, with the same verdict", async () => {
    const { sink, log } = judged(answering(UNSURE).provider)
    await sink(pay())
    await later(null, 2)
    await sink(pay())
    const [a, b] = log.all()
    expect(a!.verdict).toEqual(b!.verdict)
    expect(a!.hash).not.toBe(b!.hash)
  })
})

describe("the rest of § 3.3", () => {
  it("a match at exactly the floor executes", async () => {
    const { sink, runs } = judged(answering({ ...MATCH, confidence: 0.7 }).provider)
    const r = await sink(pay())
    expect(r.ok).toBe(true)
    expect(runs).toHaveLength(1)
    expect(r.receipt.decision).toBe("executed")
  })

  it("a mismatch at exactly the floor blocks, with a verdict, and nothing is held", async () => {
    const { sink, runs } = judged(answering({ ...MISMATCH, confidence: 0.7 }).provider)
    const r = await sink(pay())
    expect(r.ok).toBe(false)
    expect(runs).toHaveLength(0)
    expect(r.receipt.decision).toBe("judgment-blocked")
    expect(r.receipt.verdict?.assessment).toBe("mismatch")
    expect((r as { held?: unknown }).held).toBeUndefined()
    if (!r.ok) expect(r.refusal).toContain("judgment-blocked")
  })

  it("a match's receipt records provider, model, confidence and digests", async () => {
    const { sink, log } = judged(answering(MATCH).provider, { judgmentExtra: PURPOSE_ARGS })
    const r = await sink(pay())
    const v = r.receipt.verdict!
    expect(v).toMatchObject({ assessment: "match", confidence: 0.9, provider: "judge", model: "judge@1", grantHash: GRANTED.grantHash, attestation: null })
    expect(v.rationaleHash).toBe(sha256Hex("fits"))
    expect(v.actionDigest).toBe(actionDigest({ sink: "pay", args: { to: "0xabc", amount: "5" } }))
    expect(v.paymentDigest).toBe(paymentDigest({ ...NETWORK, recipient: "0xabc", amount: "5" }))
    expect(Number.isNaN(Date.parse(v.judgedAt))).toBe(false)
    expect(r.receipt.reason).toBeUndefined()
    expect(log.verifyChain()).toBe(true)
  })

  it("execute receives { authorizedBy } naming exactly the receipt's verdict", async () => {
    const { sink, runs } = judged(answering(MATCH).provider, { judgmentExtra: PURPOSE_ARGS })
    const r = await sink(pay())
    expect(runs[0]!.ctx.authorizedBy).toEqual({ verdictDigest: verdictDigest(r.receipt.verdict!), paymentDigest: r.receipt.verdict!.paymentDigest })
    expect(SpendAuthorization.is(runs[0]!.ctx.authorization)).toBe(true)
  })

  it("with no purposeArgs, paymentDigest is null on the verdict and on authorizedBy", async () => {
    const { sink, runs } = judged(answering(MATCH).provider)
    const r = await sink(pay())
    expect(r.receipt.verdict!.paymentDigest).toBeNull()
    expect(runs[0]!.ctx.authorizedBy.paymentDigest).toBeNull()
  })

  it("an unjudged sink's execute gets no second argument and its receipt has no verdict key", async () => {
    const log = new ReceiptLog()
    const seen: unknown[][] = []
    const sink = makeSink<any, string>({ name: "x", requires: { to: "verified" }, mode: "enforce", log, execute: (...a: unknown[]) => { seen.push(a); return "ok" } })
    const r = await sink({ to: auth("a") })
    expect(seen[0]).toHaveLength(1)
    expect("verdict" in r.receipt).toBe(false)
    expect("approval" in r.receipt).toBe(false)
  })

  it("an execute that throws after a match leaves an errored receipt carrying the verdict", async () => {
    const boom = new Error("no signer")
    const { sink, log } = judged(answering(MATCH).provider, { execute: () => { throw boom } })
    await expect(sink(pay())).rejects.toBe(boom)
    const [attempted, errored] = log.all()
    expect(attempted!.decision).toBe("attempted")
    expect(errored!.decision).toBe("errored")
    expect(errored!.verdict?.assessment).toBe("match")
    expect(log.verifyChain()).toBe(true)
  })

  it("an execute that rejects after a match: executed, then errored, both carrying the verdict", async () => {
    const boom = new Error("rpc down")
    const { sink, log } = judged(answering(MATCH).provider, { execute: async () => { throw boom } })
    await expect(sink(pay())).rejects.toBe(boom)
    expect(log.all().map((x) => x.decision)).toEqual(["attempted", "executed", "errored"])
    expect(log.all()[0]!.verdict).toEqual(log.all()[1]!.verdict)
    expect(log.all()[1]!.verdict).toEqual(log.all()[2]!.verdict)
    expect(log.all()[2]!.verdict?.assessment).toBe("match")
  })

  describe.each(["observe", "warn"] as const)("%s", (mode) => {
    const doubts: Array<[string, unknown]> = [
      ["unsure", UNSURE],
      ["a match below the floor", { ...MATCH, confidence: 0.3 }],
      ["a mismatch below the floor", { ...MISMATCH, confidence: 0.3 }],
      ["a confident mismatch", MISMATCH],
      ["no verdict", 7],
    ]
    it.each(doubts)("%s runs, flagged, with the verdict recorded", async (_label, answer) => {
      const { sink, runs, log } = judged(answering(answer).provider, { mode })
      const r = await sink(pay())
      expect(r.ok).toBe(true)
      expect(runs).toHaveLength(1)
      expect(r.receipt.decision).toBe("judgment-flagged")
      expect(r.receipt.verdict).toBeDefined()
      // Doubt is not authority: a flagged action names no verdict and carries no token (ADR 0010).
      expect(runs[0]!.ctx).toBeUndefined()
      expect(log.verifyChain()).toBe(true)
    })

    it("a provider that throws runs, flagged, with a verdict on the receipt", async () => {
      const { sink, runs } = judged(spy(() => { throw new Error("down") }).provider, { mode })
      const r = await sink(pay())
      expect(runs).toHaveLength(1)
      expect(r.receipt.decision).toBe("judgment-flagged")
      expect(r.receipt.verdict?.assessment).toBe("unsure")
    })

    it("nothing is held: no held key on the result", async () => {
      const { sink } = judged(answering(UNSURE).provider, { mode })
      expect((await sink(pay())) as object).not.toHaveProperty("held")
    })
  })
})

describe("I1: purpose fields are checked before the judge, and refuse like the tier wall", () => {
  const refusedWithoutJudge = async (opts: Opts, args: Record<string, Sourced<unknown>>) => {
    const { provider, calls } = answering(MATCH)
    const { sink, runs, log } = judged(provider, opts)
    const r = await sink(args)
    expect(r.ok).toBe(false)
    expect(r.receipt.decision).toBe("refused")
    expect(calls).toHaveLength(0)
    expect(runs).toHaveLength(0)
    expect("verdict" in r.receipt).toBe(false)
    expect(log.verifyChain()).toBe(true)
    return r
  }
  const payees = withFields({ payees: ["0xabc"] })
  const capped = withFields({ maxPerAction: "500" })

  it("a payee outside the purpose", () => refusedWithoutJudge({ granted: payees, judgmentExtra: PURPOSE_ARGS }, pay("0xevil")))
  it("an amount over maxPerAction", () => refusedWithoutJudge({ granted: capped, judgmentExtra: PURPOSE_ARGS }, pay("0xabc", "501")))
  it("a sink name outside actions", () => refusedWithoutJudge({ granted: withFields({ actions: ["other"] }) }, pay()))

  it("payee comparison is exact: case, padding and a NUL are all different payees", async () => {
    for (const near of ["0xABC", "0xabc ", " 0xabc", "0xabc\0", "0xab"]) {
      await refusedWithoutJudge({ granted: payees, judgmentExtra: PURPOSE_ARGS }, pay(near))
    }
  })

  it("a non-string payee is a violation, even when it stringifies to a listed one", async () => {
    await refusedWithoutJudge({ granted: payees, judgmentExtra: PURPOSE_ARGS }, pay(["0xabc"]))
    await refusedWithoutJudge({ granted: payees, judgmentExtra: PURPOSE_ARGS }, pay(123))
  })

  const badAmounts: Array<[string, unknown]> = [
    ["a number", 5],
    ["a float", 1.5],
    ["a decimal string with a point", "1.5"],
    ["a negative string", "-1"],
    ["a hex string", "0x10"],
    ["a scientific string", "1e3"],
    ["a padded string", " 5"],
    ["a trailing newline", "5\n"],
    ["an empty string", ""],
    ["a negative bigint", -1n],
    ["null", null],
    ["an object", { n: 1 }],
  ]
  it.each(badAmounts)("%s is not an amount under maxPerAction", async (_label, amount) => {
    await refusedWithoutJudge({ granted: capped, judgmentExtra: PURPOSE_ARGS }, pay("0xabc", amount))
  })
  it.each(badAmounts)("%s is not an amount even with no maxPerAction, since the payment must be digested", async (_label, amount) => {
    await refusedWithoutJudge({ judgmentExtra: PURPOSE_ARGS }, pay("0xabc", amount))
  })

  it("a bigint amount is compared as an integer, past 2^53", async () => {
    const max = 9007199254740993n
    const granted = withFields({ maxPerAction: String(max) })
    await refusedWithoutJudge({ granted, judgmentExtra: PURPOSE_ARGS }, pay("0xabc", max + 1n))
    const { sink, runs } = judged(answering(MATCH).provider, { granted, judgmentExtra: PURPOSE_ARGS })
    const r = await sink(pay("0xabc", max))
    expect(r.ok).toBe(true)
    expect(runs).toHaveLength(1)
    expect(r.receipt.verdict!.paymentDigest).toBe(paymentDigest({ ...NETWORK, recipient: "0xabc", amount: String(max) }))
  })

  it("a bigint amount and its decimal string digest the same payment", async () => {
    const asBigint = await judged(answering(MATCH).provider, { judgmentExtra: PURPOSE_ARGS }).sink(pay("0xabc", 5n))
    const asString = await judged(answering(MATCH).provider, { judgmentExtra: PURPOSE_ARGS }).sink(pay("0xabc", "5"))
    expect(asBigint.receipt.verdict!.paymentDigest).toBe(asString.receipt.verdict!.paymentDigest)
  })

  it("the asset can come from a named arg, and a non-string one is a violation", async () => {
    const extra = { purposeArgs: { payee: "to", amount: "amount", asset: "coin" }, network: "sui:testnet" }
    const requires = { to: "verified", amount: "verified", coin: "verified" } as const
    const { sink } = judged(answering(MATCH).provider, { judgmentExtra: extra, requires })
    const r = await sink({ ...pay(), coin: auth("0x2::sui::SUI") })
    expect(r.receipt.verdict!.paymentDigest).toBe(paymentDigest({ ...NETWORK, recipient: "0xabc", amount: "5" }))
    await refusedWithoutJudge({ judgmentExtra: extra, requires }, { ...pay(), coin: auth(1) })
  })

  it("a purpose arg missing at call time is refused and the judge is not called", async () => {
    await refusedWithoutJudge({ granted: payees, judgmentExtra: PURPOSE_ARGS }, { to: auth("0xabc") })
  })

  it("no purpose violation carries the value: a hash-redacted payee stays off the receipt", async () => {
    const r = await refusedWithoutJudge({ granted: payees, judgmentExtra: PURPOSE_ARGS, redact: { to: "hash" } }, pay("secret-payee@clinic.example"))
    expect(JSON.stringify(r.receipt)).not.toContain("secret-payee")
  })

  it("a verified tier does not excuse a purpose field, and a judge's match cannot override one", async () => {
    const r = await refusedWithoutJudge({ granted: payees, judgmentExtra: PURPOSE_ARGS, floor: 0 }, pay("0xevil"))
    if (!r.ok) expect(r.refusal).toContain("refused")
  })

  it("a tier violation is refused without calling the judge, and without a verdict", () =>
    refusedWithoutJudge({}, { to: Sourced.fromChannel("0xabc", "email"), amount: auth("5") }))

  it.each(["observe", "warn"] as const)("in %s a purpose-field failure runs, recorded as a violation, unjudged", async (mode) => {
    const { provider, calls } = answering(MATCH)
    const { sink, runs } = judged(provider, { mode, granted: payees, judgmentExtra: PURPOSE_ARGS })
    const r = await sink(pay("0xevil"))
    expect(r.ok).toBe(true)
    expect(runs).toHaveLength(1)
    expect(calls).toHaveLength(0)
    expect(r.receipt.reason).toContain("violations")
    expect("verdict" in r.receipt).toBe(false)
  })
})

describe("construction: a misconfigured purpose never makes a sink", () => {
  const build = (judgmentExtra: Record<string, unknown>, granted: GrantedPurpose = GRANTED, requires: Opts["requires"] = { to: "verified", amount: "verified" }) => () =>
    judged(answering(MATCH).provider, { judgmentExtra, granted, requires })

  it("payees set with no payee arg named", () => expect(build({}, withFields({ payees: ["0xabc"] }))).toThrow(/payee/))
  it("maxPerAction set with no amount arg named", () => expect(build({}, withFields({ maxPerAction: "5" }))).toThrow(/amount/))
  it("a named arg that requires does not declare", () => expect(build({ ...PURPOSE_ARGS, purposeArgs: { payee: "nobody", amount: "amount" } })).toThrow(/nobody/))
  it("an inherited name is not a declared arg", () => expect(build({ ...PURPOSE_ARGS, purposeArgs: { payee: "constructor", amount: "amount" } })).toThrow(TypeError))
  it("purposeArgs without network", () => expect(build({ purposeArgs: PURPOSE_ARGS.purposeArgs, asset: "a" })).toThrow(/network/))
  it("purposeArgs without an asset or asset arg", () => expect(build({ purposeArgs: PURPOSE_ARGS.purposeArgs, network: "sui:testnet" })).toThrow(/asset/))
  it("both an asset and an asset arg", () =>
    expect(build({ purposeArgs: { payee: "to", amount: "amount", asset: "amount" }, ...NETWORK })).toThrow(/asset/))
  it("purposeArgs missing payee or amount", () => expect(build({ ...NETWORK, purposeArgs: { payee: "to" } })).toThrow(/amount/))
  it.each(["5.0", "-1", "", 5, null])("maxPerAction %j on the grant", (max) =>
    expect(build(PURPOSE_ARGS, withFields({ maxPerAction: max }))).toThrow(/maxPerAction/))
  it("non-string payees on the grant", () => expect(build(PURPOSE_ARGS, withFields({ payees: [1] }))).toThrow(/payees/))
  it("non-array actions on the grant", () => expect(build({}, withFields({ actions: "pay" }))).toThrow(/actions/))
  it("a sink with only actions set needs no purposeArgs", () => expect(build({}, withFields({ actions: ["pay"] }))).not.toThrow())
  it("a sink with no fields needs no purposeArgs", () => expect(build({})).not.toThrow())

  it("the nested purpose bag is read once, own keys only", async () => {
    const { provider } = answering(MATCH)
    const log = new ReceiptLog()
    const sink = makeSink<any, string>({
      name: "pay",
      requires: { to: "verified", amount: "verified" },
      mode: "enforce",
      log,
      execute: () => "ok",
      judgment: {
        provider,
        floor: 0.7,
        granted: GRANTED,
        purposeArgs: poison({ payee: "to", amount: "amount" }, "purposeArgs"),
        ...NETWORK,
      } as never,
    })
    expect((await sink(pay())).ok).toBe(true)
  })
})

describe("I2: the frozen snapshot the judge saw is the thing that executes", () => {
  it("mutating a caller-held nested arg while the judge runs changes nothing that executes", async () => {
    const nested = { a: { n: 1 } }
    const { provider } = spy(async () => {
      nested.a.n = 2
      return MATCH as never
    })
    const { sink, runs } = judged(provider, { requires: { to: "verified" } })
    const r = await sink({ to: auth(nested) })
    expect((runs[0]!.args.to!.value as typeof nested).a.n).toBe(1)
    expect(r.receipt.verdict!.actionDigest).toBe(actionDigest({ sink: "pay", args: { to: { a: { n: 1 } } } }))
  })

  it("the snapshot is deep-frozen, for the judge and for execute", async () => {
    const seen: unknown[] = []
    const { provider } = spy(async (input) => {
      seen.push(input.action.args.to)
      return MATCH as never
    })
    const { sink, runs } = judged(provider, { requires: { to: "verified" } })
    await sink({ to: auth({ a: { b: [1, { c: 2 }] } }) })
    const executed = runs[0]!.args.to!.value as { a: { b: [number, object] } }
    expect(Object.isFrozen(executed)).toBe(true)
    expect(Object.isFrozen(executed.a)).toBe(true)
    expect(Object.isFrozen(executed.a.b)).toBe(true)
    expect(Object.isFrozen(executed.a.b[1])).toBe(true)
    expect(seen[0]).toBe(executed)
  })

  it("execute gets genuine Sourced values with the original tier and provenance", async () => {
    const value = Sourced.fromAuthority({ id: 1 }, "registry")
    const { sink, runs } = judged(answering(MATCH).provider, { requires: { to: "verified" } })
    await sink({ to: value })
    const got = runs[0]!.args.to!
    expect(Sourced.is(got)).toBe(true)
    expect(got.tier).toBe(value.tier)
    expect(got.provenance.origin).toBe(value.provenance.origin)
    expect([...got.provenance.ancestors]).toEqual([...value.provenance.ancestors])
    expect(got.describe()).toBe(value.describe())
    expect(got).not.toBe(value)
  })

  it("provenance confidence and chain ride across the re-wrap", async () => {
    const seen: Sourced<unknown>[] = []
    const value = Sourced.fromLLM({ id: 1 }, "Extract", [], 0.42)
    const { sink } = judged(answering(MATCH).provider, { requires: { to: "untrusted" }, execute: (args) => seen.push(args.to) })
    await sink({ to: value })
    expect(seen[0]!.tier).toBe("untrusted")
    expect(seen[0]!.provenance.confidence).toBe(0.42)
  })

  it("the digest on the receipt is the digest of what execute received", async () => {
    const { sink, runs } = judged(answering(MATCH).provider, { requires: { to: "verified", amount: "verified" } })
    const r = await sink({ to: auth({ nested: [1, 2n] }), amount: auth(9n) })
    const executed = { to: runs[0]!.args.to!.value, amount: runs[0]!.args.amount!.value }
    expect(r.receipt.verdict!.actionDigest).toBe(actionDigest({ sink: "pay", args: executed }))
  })

  it("a bigint stays a bigint for the judge and for execute", async () => {
    const seen: unknown[] = []
    const { provider } = spy(async (input) => {
      seen.push(input.action.args.amount)
      return MATCH as never
    })
    const { sink, runs } = judged(provider)
    await sink(pay("0xabc", 42n))
    expect(seen[0]).toBe(42n)
    expect(runs[0]!.args.amount!.value).toBe(42n)
  })

  const refusals: Array<[string, unknown]> = [
    ["undefined", undefined],
    ["undefined nested", { a: undefined }],
    ["-0", -0],
    ["NaN", NaN],
    ["a Map", new Map([["a", 1]])],
    ["a Set", new Set([1])],
    ["a Date", new Date(0)],
    ["a cycle", (() => { const a: Record<string, unknown> = {}; a.self = a; return a })()],
    ["a raw $bigint key", { $bigint: "1" }],
    ["a nested raw $bigint key", { a: [{ $bigint: "1" }] }],
    ["a function", () => "secret-source"],
    ["a class instance", new (class Secret { #hidden = 1; visible = 1; get hidden() { return this.#hidden } })()],
    ["a Proxy", new Proxy({ a: 1 }, {})],
    ["a Proxy whose trap throws", new Proxy({}, { getPrototypeOf() { throw new TypeError("trap-text") } })],
    ["a symbol", Symbol("s")],
  ]
  it.each(refusals)("%s is a tier-wall violation: refused, judge not called", async (_label, value) => {
    const { provider, calls } = answering(MATCH)
    const { sink, runs } = judged(provider, { requires: { to: "verified" } })
    const r = await sink({ to: auth(value) })
    expect(r.ok).toBe(false)
    expect(r.receipt.decision).toBe("refused")
    expect(calls).toHaveLength(0)
    expect(runs).toHaveLength(0)
    expect(JSON.stringify(r.receipt.reason)).not.toContain("secret-source")
    expect(JSON.stringify(r.receipt.reason)).not.toContain("trap-text")
  })

  it("an accessor is refused without being run", async () => {
    let reads = 0
    const value = {
      get price() {
        reads++
        return 1
      },
    }
    const { provider, calls } = answering(MATCH)
    const { sink, runs } = judged(provider, { requires: { to: "verified" } })
    const r = await sink({ to: Sourced.fromAuthority(value, "owner") })
    expect(r.receipt.decision).toBe("refused")
    expect(calls).toHaveLength(0)
    expect(runs).toHaveLength(0)
    // JSON rendering for the receipt runs once and the snapshot never does.
    expect(reads).toBeLessThanOrEqual(1)
  })

  it("nesting too deep is a refusal, never a rejection with no receipt", async () => {
    let deep: unknown = 1
    for (let i = 0; i < 200_000; i++) deep = [deep]
    const { provider, calls } = answering(MATCH)
    const { sink, runs } = judged(provider, { requires: { to: "verified" } })
    const r = await sink({ to: auth(deep) })
    expect(r.ok).toBe(false)
    expect(r.receipt.decision).toBe("refused")
    expect(calls).toHaveLength(0)
    expect(runs).toHaveLength(0)
  })

  it("an unjudged sink takes the same rule: a class instance is refused in enforce and only observe and warn run it (2026-11-08 audit, G2)", async () => {
    class Tool { readonly on = true }
    const build = (mode: "enforce" | "warn") => {
      const runs: unknown[] = []
      const sink = makeSink<any, string>({ name: "x", requires: { to: "verified" }, mode, log: new ReceiptLog(), execute: (a: { to: Sourced<unknown> }) => { runs.push(a.to.value); return "ok" } })
      return { sink, runs }
    }
    const tool = new Tool()
    const refused = build("enforce")
    const r = await refused.sink({ to: Sourced.fromAuthority(tool, "owner") })
    expect(r.receipt.decision).toBe("refused")
    expect(r.receipt.reason).toContain("not plain JSON")
    expect(refused.runs).toHaveLength(0)
    const warned = build("warn")
    expect((await warned.sink({ to: Sourced.fromAuthority(tool, "owner") })).receipt.decision).toBe("warned")
    expect(warned.runs).toEqual([tool])
  })
})

describe("redaction: the provider's words never reach the receipt of a redacting sink", () => {
  const SECRET = "patient@clinic.example"
  const echo = (assessment: string, confidence: number): JudgmentProvider["assess"] => async ({ action }) =>
    ({ assessment, confidence, rationale: `could not classify ${String(action.args.to)}` }) as never

  const cases: Array<[string, JudgmentProvider["assess"], "enforce" | "warn"]> = [
    ["held: unsure echoing the value", echo("unsure", 0.9), "enforce"],
    ["held: below floor echoing the value", echo("match", 0.2), "enforce"],
    ["held: a provider error echoing the value", async ({ action }) => { throw new Error(`down on ${String(action.args.to)}`) }, "enforce"],
    ["held: an unknown assessment that is the value", async ({ action }) => ({ assessment: String(action.args.to), confidence: 0.9, rationale: "" }) as never, "enforce"],
    ["held: a non-string rationale", async ({ action }) => ({ assessment: "unsure", confidence: 0.9, rationale: { to: action.args.to } }) as never, "enforce"],
    ["blocked: a mismatch echoing the value", echo("mismatch", 0.95), "enforce"],
    ["flagged: warn mode", echo("unsure", 0.5), "warn"],
  ]

  it.each(cases)("%s", async (_label, assess, mode) => {
    const { sink } = judged(spy(assess).provider, { mode, redact: { to: "hash" }, requires: { to: "verified" } })
    const r = await sink({ to: auth(SECRET) })
    expect(JSON.stringify(r.receipt)).not.toContain(SECRET)
    expect(canonicalLeak(r.receipt)).toBe(false)
    expect(r.receipt.verdict).toBeDefined()
    expect(Object.keys(r.receipt.verdict!)).not.toContain("rationale")
  })

  // Strings that survive JSON.stringify escaping only count if the secret is literal; this also walks the verdict.
  const canonicalLeak = (receipt: Receipt) => Object.values(receipt.verdict ?? {}).some((v) => typeof v === "string" && v.includes(SECRET))

  it("the refusal never quotes the judge by default; a host opts in, and only the durable receipt stays redacted", async () => {
    const plain = judged(spy(echo("unsure", 0.5)).provider, { redact: { to: "hash" }, requires: { to: "verified" } })
    const silent = await plain.sink({ to: auth(SECRET) })
    if (silent.ok) throw new Error("expected held")
    expect(silent.refusal).not.toContain(SECRET)
    const opted = judged(spy(echo("unsure", 0.5)).provider, { redact: { to: "hash" }, requires: { to: "verified" }, judgmentExtra: { rationaleInRefusal: true } })
    const told = await opted.sink({ to: auth(SECRET) })
    if (told.ok) throw new Error("expected held")
    expect(told.refusal).toContain(SECRET)
    expect(told.receipt.reason).not.toContain(SECRET)
  })

  it("rationaleHash is the hash of the provider's text, whether or not the sink redacts", async () => {
    const { sink } = judged(answering({ ...UNSURE, rationale: "the words" }).provider, { redact: { to: "hash" }, requires: { to: "verified" } })
    expect((await sink({ to: auth(SECRET) })).receipt.verdict!.rationaleHash).toBe(sha256Hex("the words"))
  })

  it("an unredacted sink keeps the rationale in reason", async () => {
    const { sink } = judged(answering({ ...UNSURE, rationale: "SPECIFIC-42" }).provider)
    expect((await sink(pay())).receipt.reason).toContain("SPECIFIC-42")
  })
})

describe("the receipt: verdict and approval are inside the hash, and an unjudged one is unchanged", () => {
  const base = { seq: 0, prevHash: "genesis", at: "2026-01-01T00:00:00.000Z", sink: "pay", decision: "executed", args: { to: { value: "x", tier: "verified", provenance: "p" } } } as const
  const FIXTURE_BODY = '{"args":{"to":{"provenance":"p","tier":"verified","value":"x"}},"at":"2026-01-01T00:00:00.000Z","decision":"executed","prevHash":"genesis","seq":0,"sink":"pay"}'

  it("a 0.5.0-shaped receipt's body is byte-identical", () => {
    expect(receiptBody(base as never)).toBe(FIXTURE_BODY)
    expect(sha256Hex(receiptBody(base as never))).toBe(sha256Hex(FIXTURE_BODY))
  })

  it("an explicit undefined verdict or approval also hashes as 0.5.0", () => {
    expect(receiptBody({ ...base, verdict: undefined, approval: undefined } as never)).toBe(FIXTURE_BODY)
  })

  it("a null verdict is NOT a 0.5.0 receipt: only omission keeps the bytes", () => {
    expect(receiptBody({ ...base, verdict: null } as never)).not.toBe(FIXTURE_BODY)
  })

  it("verdict and approval are hashed", () => {
    expect(receiptBody({ ...base, verdict: { assessment: "match" } } as never)).not.toBe(FIXTURE_BODY)
    expect(receiptBody({ ...base, approval: { signature: "x" } } as never)).not.toBe(FIXTURE_BODY)
  })

  it("a real unjudged sink's receipt hashes from a body with no verdict or approval key", async () => {
    const log = new ReceiptLog()
    const sink = makeSink<any, string>({ name: "pay", requires: { to: "verified" }, mode: "enforce", log, execute: () => "ok" })
    const { receipt } = await sink({ to: auth("x") })
    expect(receipt.hash).toBe(sha256Hex(receiptBody(receipt)))
    expect(receiptBody(receipt)).not.toContain("verdict")
    expect(receiptBody(receipt)).not.toContain("approval")
    expect(Object.keys(receipt).sort()).toEqual(["args", "at", "decision", "hash", "prevHash", "seq", "sink"])
  })

  it("editing a stored verdict is caught by the chain", async () => {
    const { sink, log } = judged(answering(UNSURE).provider)
    await sink(pay())
    const [held] = log.all()
    expect(log.verifyChain()).toBe(true)
    const tampered = { ...held!, verdict: { ...held!.verdict!, assessment: "match" } }
    expect(sha256Hex(receiptBody(tampered as never))).not.toBe(held!.hash)
    expect(verdictDigest(tampered.verdict as Verdict)).not.toBe(verdictDigest(held!.verdict!))
  })

  it("a signed log of judged receipts verifies end to end, through JSON and back", async () => {
    const keys = generateSigningKeypair()
    const pin = { trustedSignerPublicKeyHex: publicKeyHexFromPem(keys.publicKeyPem) }
    const log = new SignedReceiptLog(makeEd25519ReceiptSigner(keys))
    const provider = answering(UNSURE).provider
    const sink = makeSink<any, string>({ name: "pay", requires: { to: "verified" }, mode: "enforce", log, execute: () => "ok", judgment: { provider, floor: 0.7, granted: GRANTED } })
    await sink({ to: auth("x") })
    const parsed = parseJSONL(log.exportJSONL())
    expect(log.all()[0]!.verdict?.assessment).toBe("unsure")
    expect(verifySignedChain(parsed, pin).valid).toBe(true)
    const line = log.exportJSONL().replace('"assessment":"unsure"', '"assessment":"match"')
    expect(verifySignedChain(parseJSONL(line), pin).valid).toBe(false)
  })
})

describe("the types the receipt needs are importable", () => {
  it("encodeAction's output is what the digest covers (a guard on the shared helper)", () => {
    expect(encodeAction({ sink: "s", args: { n: 2n } }).args).toEqual({ n: { $bigint: "2" } })
  })
})
