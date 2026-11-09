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

  it.each([
    ["non-hex", "0x" + "zz".repeat(32)],
    ["too long", "0x" + "a".repeat(65)],
    ["a doubled prefix", "0x0x" + "a".repeat(62)],
  ])("throws on a payee that is not an address: %s", (_name, payee) => {
    expect(() => suiPaymentSpelling.payee(payee)).toThrow(TypeError)
  })

  it.each([
    ["an MVR name", "@mysten/foo::coin::COIN"],
    ["a trailing space", SUI_COIN + " "],
    ["an extra segment", SUI_COIN + "::x"],
    ["a non-hex address", "0x" + "z".repeat(64) + "::a::B"],
    ["a too-long address", "0x" + "a".repeat(65) + "::a::B"],
  ])("throws on an asset that is not a resolved coin type: %s", (_name, asset) => {
    expect(() => suiPaymentSpelling.asset(asset)).toThrow()
  })

  it.each([
    ["deep nesting that exhausted the heap", "0x2::a::B<".repeat(60000) + "u8" + ">".repeat(60000)],
    ["nested vectors that blocked for 43 s", "0x2::a::B<vector<".repeat(800) + "u8" + ">>".repeat(800)],
    ["many generics inside the length limit", "0x2::a::B<".repeat(17) + "u8" + ">".repeat(17)],
    ["one long identifier", SUI_COIN + "x".repeat(2000)],
  ])("refuses without parsing: %s", (_name, asset) => {
    const started = performance.now()
    expect(() => suiPaymentSpelling.asset(asset)).toThrow(/plausible/)
    expect(performance.now() - started).toBeLessThan(100)
  })

  it("still accepts a coin type at the limits", () => {
    const L = "0x" + "0".repeat(63) + "2"
    const atDepth8 = `${L}::a::B<`.repeat(8) + "u8" + ">".repeat(8)
    expect(atDepth8.length).toBeLessThan(1024)
    expect(suiPaymentSpelling.asset(atDepth8)).toBe(atDepth8)
  })

  it("keeps a generic coin type in canonical form", () => {
    const generic = `${"0x" + "0".repeat(63) + "2"}::a::B<${SUI_COIN}>`
    expect(suiPaymentSpelling.asset(generic)).toBe(generic)
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
