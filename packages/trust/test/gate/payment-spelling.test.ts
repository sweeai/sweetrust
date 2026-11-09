/**
 * One payment has one spelling (DAN-1457).
 *
 * A block or a hold names an action as written, and the kernel knows no chain's
 * address format, so `0xABC` after a doubt on `0xabc` used to be a new action
 * with a fresh judge. `judgment.spelling` lets the host state the rail's
 * canonical form; anything else is refused before a judge is asked.
 */
import { describe, expect, it } from "vitest"
import { actionDigest, makeSink, paymentDigest, ReceiptLog, Sourced, type EnforcementMode, type JudgmentProvider, type JudgmentVerdict } from "../../src/gate/index.ts"
import { GRANTED } from "../helpers/granted.ts"

const auth = <T>(value: T) => Sourced.fromAuthority(value, "owner")
const lower = (value: string) => value.toLowerCase()
const MATCH: JudgmentVerdict = { assessment: "match", confidence: 0.9, rationale: "fits" }
const UNSURE: JudgmentVerdict = { assessment: "unsure", confidence: 0.9, rationale: "doubtful" }
const FIXED = { purposeArgs: { payee: "to", amount: "amount" }, network: "sui:testnet", asset: "0xcoin" }

const judged = (judgment: Record<string, unknown>, opts: { answer?: JudgmentVerdict; requires?: Record<string, "verified">; mode?: EnforcementMode; granted?: typeof GRANTED; redact?: Record<string, "hash"> } = {}) => {
  const state = { judged: 0, ran: 0 }
  const provider: JudgmentProvider = {
    name: "judge",
    model: "judge@1",
    assess: async () => {
      state.judged++
      return opts.answer ?? MATCH
    },
  }
  const log = new ReceiptLog()
  const sink = makeSink<any, string>({
    name: "pay",
    requires: opts.requires ?? { to: "verified", amount: "verified" },
    mode: opts.mode ?? "enforce",
    log,
    ...(opts.redact ? { redact: opts.redact } : {}),
    judgment: { provider, floor: 0.7, granted: opts.granted ?? GRANTED, ...judgment } as never,
    execute: () => {
      state.ran++
      return "sent"
    },
  })
  return { sink, state, log }
}

describe("a sink that declares its rail's spelling", () => {
  it("refuses a respelled payee before any judge, and records it", async () => {
    const { sink, state, log } = judged({ ...FIXED, spelling: { payee: lower } })
    const result = await sink({ to: auth("0xABC"), amount: auth("5") })
    expect(result.ok).toBe(false)
    expect(state).toEqual({ judged: 0, ran: 0 })
    expect(log.all()).toHaveLength(1)
    expect(result.receipt.decision).toBe("refused")
    expect(result.receipt.reason).toContain("to is not in the spelling")
  })

  it("judges and runs the canonical spelling", async () => {
    const { sink, state } = judged({ ...FIXED, spelling: { payee: lower } })
    const result = await sink({ to: auth("0xabc"), amount: auth("5") })
    expect(result.ok).toBe(true)
    expect(state).toEqual({ judged: 1, ran: 1 })
  })

  it("a respelling cannot escape a doubt on the canonical payee", async () => {
    const { sink, state } = judged({ ...FIXED, spelling: { payee: lower } }, { answer: UNSURE })
    const held = await sink({ to: auth("0xabc"), amount: auth("5") })
    expect(held.ok).toBe(false)
    expect(held.receipt.decision).toBe("judgment-held")
    const respelled = await sink({ to: auth("0xABC"), amount: auth("5") })
    expect(respelled.ok).toBe(false)
    expect(respelled.receipt.decision).toBe("refused")
    expect(state).toEqual({ judged: 1, ran: 0 })
  })

  it("holds an asset argument to its spelling", async () => {
    const requires = { to: "verified", amount: "verified", coin: "verified" } as const
    const purposeArgs = { payee: "to", amount: "amount", asset: "coin" }
    const { sink, state } = judged({ purposeArgs, network: "sui:testnet", spelling: { asset: lower } }, { requires })
    const refused = await sink({ to: auth("0xabc"), amount: auth("5"), coin: auth("0xCOIN") })
    expect(refused.ok).toBe(false)
    expect(refused.receipt.reason).toContain("coin is not in the spelling")
    expect(state.judged).toBe(0)
    expect((await sink({ to: auth("0xabc"), amount: auth("5"), coin: auth("0xcoin") })).ok).toBe(true)
  })

  it.each([
    ["throws", () => { throw new Error("0xsecret-in-the-message") }],
    ["returns a non-string", () => 7],
    ["returns a promise", async (value: string) => value],
  ])("refuses when the spelling function %s", async (_name, spell) => {
    const { sink, state } = judged({ ...FIXED, spelling: { payee: spell } })
    const result = await sink({ to: auth("0xabc"), amount: auth("5") })
    expect(result.ok).toBe(false)
    expect(state).toEqual({ judged: 0, ran: 0 })
    expect(JSON.stringify(result.receipt)).not.toContain("0xsecret-in-the-message")
  })

  it("names the argument and not the value, so a redacting receipt stays redacted", async () => {
    const { sink } = judged({ ...FIXED, spelling: { payee: lower } }, { redact: { to: "hash" } })
    const result = await sink({ to: auth("0xABCDEF"), amount: auth("5") })
    expect(result.ok).toBe(false)
    expect(JSON.stringify(result.receipt)).not.toContain("0xABCDEF")
  })

  it("flags and runs in warn mode, like any other purpose violation", async () => {
    const { sink, state } = judged({ ...FIXED, spelling: { payee: lower } }, { mode: "warn" })
    const result = await sink({ to: auth("0xABC"), amount: auth("5") })
    expect(result.ok).toBe(true)
    expect(result.receipt.decision).toBe("warned")
    expect(result.receipt.reason).toContain("to is not in the spelling")
    expect(state.judged).toBe(0)
  })
})

describe("a sink that declares no spelling", () => {
  it("compares as written, as it always did", async () => {
    const { sink, state } = judged(FIXED)
    expect((await sink({ to: auth("0xABC"), amount: auth("5") })).ok).toBe(true)
    expect(state).toEqual({ judged: 1, ran: 1 })
  })

  it("the digests are the ones a spelling never touches", () => {
    expect(actionDigest({ sink: "pay", args: { to: "0xABC" } })).not.toBe(actionDigest({ sink: "pay", args: { to: "0xabc" } }))
    const payment = { network: "sui:testnet", asset: "0xcoin", amount: "5" }
    expect(paymentDigest({ ...payment, recipient: "0xABC" })).not.toBe(paymentDigest({ ...payment, recipient: "0xabc" }))
  })
})

describe("a spelling that could never be satisfied is refused at build", () => {
  const withFields = (fields: Record<string, unknown>) => ({ purpose: { ...GRANTED.purpose, fields }, grantHash: GRANTED.grantHash }) as typeof GRANTED

  it("a purpose payee not in the canonical spelling", () => {
    expect(() => judged({ ...FIXED, spelling: { payee: lower } }, { granted: withFields({ payees: ["0xabc", "0xDEF"] }) })).toThrow(/purpose\.fields\.payees is not in the spelling/)
  })

  it("a purpose asset not in the canonical spelling", () => {
    expect(() => judged({ ...FIXED, asset: "0xCOIN", spelling: { asset: lower } }, { granted: withFields({ asset: "0xCOIN" }) })).toThrow(/purpose\.fields\.asset is not in the spelling/)
  })

  it("a fixed asset not in the canonical spelling", () => {
    expect(() => judged({ ...FIXED, asset: "0xCOIN", spelling: { asset: lower } })).toThrow(/judgment\.asset is not in the spelling/)
  })

  it("a spelling function that throws on the grant's own payee", () => {
    const spell = () => {
      throw new Error("no")
    }
    expect(() => judged({ ...FIXED, spelling: { payee: spell } }, { granted: withFields({ payees: ["0xabc"] }) })).toThrow(TypeError)
  })

  it("accepts a grant and a fixed asset already in the canonical spelling", () => {
    expect(() => judged({ ...FIXED, spelling: { payee: lower, asset: lower } }, { granted: withFields({ payees: ["0xabc"] }) })).not.toThrow()
  })
})

describe("a malformed spelling is refused at build", () => {
  it.each([
    ["no purposeArgs", { spelling: { payee: lower } }, /needs judgment\.purposeArgs/],
    ["a member that is not a function", { ...FIXED, spelling: { payee: "lowercase" } }, /spelling\.payee must be a function/],
    ["a misspelled key", { ...FIXED, spelling: { payees: lower } }, /unknown key "payees"/],
    ["not an object", { ...FIXED, spelling: lower }, /spelling must be/],
    ["an array", { ...FIXED, spelling: [lower] }, /spelling must be/],
  ])("%s", (_name, judgment, message) => {
    expect(() => judged(judgment as Record<string, unknown>)).toThrow(message as RegExp)
  })
})
