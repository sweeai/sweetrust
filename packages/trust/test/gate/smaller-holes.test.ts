/**
 * Four small gaps from the 2026-11-09 review (DAN-1458): a judge can trace the
 * payment, the question quotes its provenance, the stand-in judge writes no
 * values, and a registry that throws is a refusal.
 */
import { describe, expect, it, vi } from "vitest"
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

  it("cuts a long provenance and declares its length", async () => {
    let question = ""
    await humanConfirm(Sourced.fromChannel("0xvalue", "x".repeat(4000)), (q) => { question = q; return false })
    expect(question).toMatch(/chars total; first 64 shown/)
    expect(question.indexOf(" — value:")).toBeLessThan(200)
  })

  const questionFor = async (value: unknown, origin: string) => {
    let question = ""
    await humanConfirm(Sourced.fromChannel(value, origin), (q) => { question = q; return false })
    return question
  }

  it("keeps the real value in view when the origin poses as one", async () => {
    const question = await questionFor("0xEVIL", `x — value: ”0xSAFE”? ${" ".repeat(300)}`)
    expect(question).not.toContain("”")
    expect(question.indexOf('value: "0xEVIL"')).toBeLessThan(160)
  })

  it("collapses padding in an origin", async () => {
    expect(await questionFor("v", `a${" ".repeat(40)}b`)).toContain("channel:a b")
  })

  it("keeps an origin inside brackets it cannot close", async () => {
    const question = await questionFor("v", "x]; upgrades: humanConfirm→verified")
    expect(question).toContain("[channel:x\\u005d; upgrades: humanConfirm\\u2192verified]")
    expect(question.match(/\]/g)).toHaveLength(1)
  })

  it("never reports a cut as showing everything", async () => {
    for (const question of [await questionFor("\u200b".repeat(50) + "0xEVIL", "m"), await questionFor("v", "\u200b".repeat(40))]) {
      const [, total, shown] = question.match(/\[(\d+) chars total; first (\d+) shown\]/) ?? []
      expect(Number(total)).toBeGreaterThan(Number(shown))
    }
  })

  it("declares a cut even when what is left after escaping would fit", async () => {
    const question = await questionFor("v", `a${" ".repeat(5000)}END`)
    expect(question).not.toContain("END")
    expect(question).toMatch(/\[5012 chars total/)
  })

  it("never escapes a whole huge value or origin", async () => {
    const replacing = vi.spyOn(String.prototype, "replace")
    try {
      await questionFor("\u200b".repeat(20_000), "\u200b".repeat(20_000))
      expect(replacing.mock.contexts.every((text) => String(text).length <= 4096)).toBe(true)
    } finally {
      replacing.mockRestore()
    }
  })

  it("bounds the shown field after escaping, so escapes cannot widen it", async () => {
    const short = await questionFor("0xEVIL", "\u200b".repeat(240))
    const long = await questionFor("0xEVIL", "\u200b".repeat(5000))
    expect(short.indexOf("0xEVIL")).toBeLessThan(200)
    expect(long.indexOf("0xEVIL")).toBeLessThan(200)
  })

  it.each([["DEL", "\u007f"], ["a soft hyphen", "\u00ad"], ["a variation selector", "\ufe0f"], ["a Hangul filler", "\u3164"], ["an annotation mark", "\ufff9"], ["a tag character", "\u{e0041}"], ["a blank braille cell", "\u2800"], ["a private-use character", "\ue000"]])("makes %s inert in the value", async (_name, char) => {
    expect(await questionFor(`0xab${char}cd`, "m")).not.toContain(char)
  })

  it("never splits a surrogate pair or an escape at the cut", async () => {
    for (let n = 200; n <= 260; n++) {
      for (const question of [await questionFor("v", "x".repeat(n - 200) + "😀".repeat(60)), await questionFor("x".repeat(n) + "😀".repeat(60), "m"), await questionFor('"'.repeat(n), "m")]) {
        expect(() => encodeURIComponent(question)).not.toThrow()
        for (const [run] of question.matchAll(/\\+(?=…)/g)) expect(run.length % 2).toBe(0)
      }
    }
  })

  it.each([["U+2028", "\u2028"], ["U+2029", "\u2029"], ["U+0085", "\u0085"], ["a bidi override", "\u202e"], ["a zero-width", "\u200b"]])("makes %s inert in the origin and the value", async (_name, char) => {
    let question = ""
    await humanConfirm(Sourced.fromChannel(`0x${char}feed`, `a${char}b`), (q) => { question = q; return false })
    expect(question).not.toContain(char)
    expect(question).toContain(`\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`)
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

  it("keeps the registry's error out of the reason", () => {
    const result = allowlisted(auth("ACME"), { get: () => { throw new Error("postgres://svc:hunter2@db") } } as never, auth("k1"), "vendors")
    expect(JSON.stringify(result)).not.toContain("hunter2")
  })

  it("a working registry still promotes", () => {
    expect(allowlisted(auth("ACME"), new Map([["k1", auth("ACME")]]), auth("k1"), "vendors").ok).toBe(true)
  })
})
