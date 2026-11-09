/**
 * `suiPaymentSpelling` is Sui's canonical form, handed to a judged sink (DAN-1457).
 * The address cases are the ones a Sui transport accepts as the same recipient.
 */
import { describe, expect, it } from "vitest"
import { makeSink, ReceiptLog, Sourced } from "sweetrust/gate"
import { suiPaymentSpelling } from "../src/index.ts"

const CANONICAL = "0x" + "ab".repeat(32)
const SUI_COIN = "0x" + "0".repeat(63) + "2::sui::SUI"
const auth = <T>(value: T) => Sourced.fromAuthority(value, "owner")

describe("suiPaymentSpelling", () => {
  it("maps a canonical address and coin type to themselves", () => {
    expect(suiPaymentSpelling.payee(CANONICAL)).toBe(CANONICAL)
    expect(suiPaymentSpelling.asset(SUI_COIN)).toBe(SUI_COIN)
  })

  it("maps every other spelling elsewhere", () => {
    expect(suiPaymentSpelling.payee("0x" + "AB".repeat(32))).toBe(CANONICAL)
    expect(suiPaymentSpelling.payee("ab".repeat(32))).toBe(CANONICAL)
    expect(suiPaymentSpelling.payee("0x2")).not.toBe("0x2")
    expect(suiPaymentSpelling.asset("0x2::sui::SUI")).toBe(SUI_COIN)
  })

  it("is frozen", () => {
    expect(Object.isFrozen(suiPaymentSpelling)).toBe(true)
  })

  it("makes a judged sink refuse a respelled address before the judge", async () => {
    let judged = 0
    const sink = makeSink<any, string>({
      name: "pay",
      requires: { to: "verified", amount: "verified" },
      mode: "enforce",
      log: new ReceiptLog(),
      judgment: {
        provider: {
          name: "judge",
          model: "judge@1",
          assess: async () => {
            judged++
            return { assessment: "match", confidence: 0.9, rationale: "fits" }
          },
        },
        floor: 0.7,
        granted: { purpose: { statement: "Pay the invoices" }, grantHash: "a".repeat(64) },
        purposeArgs: { payee: "to", amount: "amount" },
        network: "sui:testnet",
        asset: SUI_COIN,
        spelling: suiPaymentSpelling,
      } as never,
      execute: () => "sent",
    })
    const respelled = await sink({ to: auth("0x" + "AB".repeat(32)), amount: auth("5") })
    expect(respelled.ok).toBe(false)
    expect(judged).toBe(0)
    expect((await sink({ to: auth(CANONICAL), amount: auth("5") })).ok).toBe(true)
    expect(judged).toBe(1)
  })
})
