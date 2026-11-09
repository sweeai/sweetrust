/** Regressions from the independent review of the 2026-11-08 fix series. */
import { describe, expect, it } from "vitest"
import { makeSink, ReceiptLog, Sourced } from "../../src/gate/index.ts"

const judged = (answers: string[], rationaleInRefusal = false) => {
  const state = { calls: 0, paid: [] as string[] }
  const sink = makeSink<any, string>({
    name: "pay", requires: { to: "untrusted", amount: "untrusted" }, mode: "enforce", log: new ReceiptLog(),
    execute: (a: any) => { state.paid.push(String(a.amount.value)); return "sent" },
    judgment: {
      floor: 0.5, rationaleInRefusal,
      granted: { purpose: { statement: "pay rent", fields: { payees: ["ACME"], maxPerAction: "100" } }, grantHash: "a".repeat(64) },
      purposeArgs: { payee: "to", amount: "amount" }, network: "sui:testnet", asset: "0x2::sui::SUI",
      provider: { name: "j", model: "j@1", assess: async () => ({ assessment: answers[state.calls++], confidence: 0.9, rationale: "r" }) as never },
    } as never,
  })
  return { sink, state }
}
const call = (sink: any, amount: string, options?: unknown) =>
  sink({ to: Sourced.fromLLM("ACME", "agent", []), amount: Sourced.fromLLM(amount, "agent", []) }, options)

describe("a payment amount has one spelling", () => {
  it.each(["0100", "00100", "00"])("%s is refused before the judge runs", async (amount) => {
    const { sink, state } = judged(["match"])
    const r = await call(sink, amount)
    expect(r.ok).toBe(false)
    expect(r.receipt.reason).toContain("canonical")
    expect(state).toEqual({ calls: 0, paid: [] })
  })

  it("CONTROL: 0 and 100 are still payable", async () => {
    for (const amount of ["0", "100"]) {
      const { sink, state } = judged(["match"])
      expect((await call(sink, amount)).ok).toBe(true)
      expect(state.paid).toEqual([amount])
    }
  })
})

describe("the agent cannot tell a block from a hold", () => {
  it("both answer with the same words", async () => {
    const blocked = await call(judged(["mismatch"]).sink, "100")
    const held = await call(judged(["unsure"]).sink, "100")
    expect(blocked.refusal).toBe(held.refusal)
    expect(blocked.receipt.decision).toBe("judgment-blocked")
    expect(held.receipt.decision).toBe("judgment-held")
  })

  it("the host can opt back in", async () => {
    expect((await call(judged(["mismatch"], true).sink, "100")).refusal).toContain("judgment-blocked")
  })
})

describe("a hold under another idempotency key", () => {
  it("says so, rather than handing back a digest this key cannot resume", async () => {
    const { sink } = judged(["unsure", "unsure"])
    expect((await call(sink, "100", { idempotencyKey: "A" })).ok).toBe(false)
    const second = await call(sink, "100", { idempotencyKey: "B" })
    expect(second.refusal).toContain("another idempotency key")
  })
})
