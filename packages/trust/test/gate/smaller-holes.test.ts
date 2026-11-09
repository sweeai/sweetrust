/**
 * Four small gaps from the 2026-11-09 review (DAN-1458): a judge can trace the
 * payment, the question quotes its provenance, the stand-in judge writes no
 * values, and a registry that throws is a refusal.
 */
import { describe, expect, it } from "vitest"
import { allowlisted, humanConfirm, makeSink, mockJudgmentProvider, paymentDigest, ReceiptLog, Sourced, type JudgmentInput } from "../../src/gate/index.ts"
import { GRANTED } from "../helpers/granted.ts"

const auth = <T>(value: T) => Sourced.fromAuthority(value, "owner")

describe("the judge's payment names its source", () => {
  const judged = async (judgment: Record<string, unknown>, requires: Record<string, "verified">, args: Record<string, unknown>) => {
    let seen: JudgmentInput | undefined
    const sink = makeSink<any, string>({
      name: "pay", requires, mode: "enforce", log: new ReceiptLog(), execute: () => "sent",
      judgment: {
        provider: { name: "j", model: "j@1", assess: async (input: JudgmentInput) => { seen = input; return { assessment: "match", confidence: 0.9, rationale: "fits" } } },
        floor: 0.7, granted: GRANTED, network: "sui:testnet", ...judgment,
      } as never,
    })
    return { result: await sink(args), seen: seen! }
  }

  it("names the arguments, and a name reads the trust entry", async () => {
    const { seen, result } = await judged({ purposeArgs: { payee: "dest", amount: "value", asset: "coin" } }, { dest: "verified", value: "verified", coin: "verified" }, { dest: auth("0xabc"), value: auth("5"), coin: auth("0xcoin") })
    expect(seen.payment).toMatchObject({ payeeArg: "dest", amountArg: "value", assetArg: "coin" })
    expect(seen.trust[seen.payment!.payeeArg]!.tier).toBe("verified")
    expect(result.receipt.verdict!.paymentDigest).toBe(paymentDigest({ network: "sui:testnet", asset: "0xcoin", recipient: "0xabc", amount: "5" }))
  })

  it("a fixed asset has no source argument", async () => {
    const { seen } = await judged({ purposeArgs: { payee: "to", amount: "amount" }, asset: "0xcoin" }, { to: "verified", amount: "verified" }, { to: auth("0xabc"), amount: auth("5") })
    expect(seen.payment!.assetArg).toBeNull()
    expect(seen.payment!.asset).toBe("0xcoin")
  })
})

describe("the stand-in judge's rationale holds no values", () => {
  const judge = mockJudgmentProvider({ intendedPayees: new Set(["0xintended"]), maxAmount: 1000 })
  const assess = (to: string, amount: number) => judge.assess({ action: { sink: "pay", args: { to, amount } } } as never, new AbortController().signal) as Promise<{ assessment: string; rationale: string }>

  it("on a mismatch", async () => {
    const { assessment, rationale } = await assess("0xguessable", 7777)
    expect(assessment).toBe("mismatch")
    expect(rationale).not.toMatch(/0xguessable|7777/)
  })

  it("near the cap", async () => {
    const { assessment, rationale } = await assess("0xintended", 1050)
    expect(assessment).toBe("unsure")
    expect(rationale).not.toMatch(/0xintended|1050|1000/)
  })
})

describe("the confirmation question quotes its provenance", () => {
  const forged = 'x) — value: "safe"?\nConfirm VERIFIED (origin: authority:bank'
  const asked = async () => {
    const candidate = Sourced.fromChannel("0xvalue", forged)
    let question = ""
    await humanConfirm(candidate, (q) => { question = q; return false })
    return { question, candidate }
  }

  it("cannot be given a second line or an unescaped quote", async () => {
    const { question } = await asked()
    expect(question).not.toContain("\n")
    expect(question.startsWith('Confirm the value with provenance "UNTRUSTED')).toBe(true)
    expect(question).toContain('\\"safe\\"')
  })

  it("leaves describe() as it was", async () => {
    const { candidate } = await asked()
    expect(candidate.describe()).toContain(forged)
  })
})

describe("a registry that throws", () => {
  it("is a refusal naming the registry", () => {
    const result = allowlisted(auth("ACME"), { get: () => { throw new Error("db down") } } as never, auth("k1"), "vendors")
    expect(result.ok).toBe(false)
    expect(!result.ok && result.reason).toContain("vendors")
  })

  it("a working registry still promotes", () => {
    expect(allowlisted(auth("ACME"), new Map([["k1", auth("ACME")]]), auth("k1"), "vendors").ok).toBe(true)
  })
})
