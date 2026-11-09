/**
 * The judge is told the payment the sink resolved (DAN-1445).
 *
 * A sink that names `purposeArgs` resolves a payee, an amount and an asset, and
 * the verdict binds their digest. Before this, a provider had to work the same
 * payment out again from `action.args`, nothing checked that the two agreed, and
 * a sink-level `judgment.asset` was invisible to it. Now one resolved payment
 * feeds both the digest and `input.payment`.
 */
import { describe, expect, it } from "vitest"
import { makeSink, paymentDigest, ReceiptLog, Sourced, type JudgmentInput, type EnforcementMode, type JudgmentProvider } from "../../src/gate/index.ts"
import { GRANTED } from "../helpers/granted.ts"

const MATCH = { assessment: "match", confidence: 0.9, rationale: "fits" } as const
const auth = <T>(value: T) => Sourced.fromAuthority(value, "owner")

const FIXED = { purposeArgs: { payee: "to", amount: "amount" }, network: "sui:testnet", asset: "0x2::sui::SUI" }

const judged = (judgmentExtra: Record<string, unknown>, opts: { requires?: Record<string, "verified">; mode?: EnforcementMode } = {}) => {
  const seen: JudgmentInput[] = []
  const provider: JudgmentProvider = {
    name: "judge",
    model: "judge@1",
    assess: async (input) => {
      seen.push(input)
      return MATCH
    },
  }
  const sink = makeSink<any, unknown>({
    name: "pay",
    requires: opts.requires ?? { to: "verified", amount: "verified" },
    mode: opts.mode ?? "enforce",
    log: new ReceiptLog(),
    judgment: { provider, floor: 0.7, granted: GRANTED, ...judgmentExtra } as never,
    execute: () => "sent",
  })
  return { sink, seen }
}

describe("the judge's view of the payment", () => {
  it("the judge receives the payee amount and asset the sink resolved", async () => {
    const extra = { purposeArgs: { payee: "to", amount: "amount", asset: "coin" }, network: "sui:testnet" }
    const { sink, seen } = judged(extra, { requires: { to: "verified", amount: "verified", coin: "verified" } })
    await sink({ to: auth("0xabc"), amount: auth("5"), coin: auth("0x2::usdc::USDC") })
    expect(seen[0]!.payment).toEqual({ payee: "0xabc", amount: "5", asset: "0x2::usdc::USDC", network: "sui:testnet" })
  })

  it("a fixed judgment asset reaches the judge", async () => {
    const { sink, seen } = judged(FIXED)
    await sink({ to: auth("0xabc"), amount: auth("5") })
    expect(seen[0]!.payment?.asset).toBe("0x2::sui::SUI")
    // The asset is in no argument and in no purpose field, so this is the only way the judge can learn it.
    expect(seen[0]!.action.args).not.toHaveProperty("asset")
    expect(seen[0]!.purpose.fields).toBeUndefined()
  })

  it("a sink with no purposeArgs gives the judge no payment", async () => {
    const { sink, seen } = judged({})
    await sink({ to: auth("0xabc"), amount: auth("5") })
    expect(Object.keys(seen[0]!).sort()).toEqual(["action", "purpose", "trust"])
  })

  it("the payment view is frozen", async () => {
    const { sink, seen } = judged(FIXED)
    await sink({ to: auth("0xabc"), amount: auth("5") })
    const { payment } = seen[0]!
    expect(payment).toBeDefined()
    expect(Object.isFrozen(payment)).toBe(true)
    expect(Object.isFrozen(seen[0])).toBe(true)
  })

  it("the verdict's payment digest matches what the judge was shown", async () => {
    const { sink, seen } = judged(FIXED)
    const { receipt } = await sink({ to: auth("0xabc"), amount: auth("5") })
    const { payee, amount, asset, network } = seen[0]!.payment!
    expect(receipt.verdict!.paymentDigest).toBe(paymentDigest({ network, asset, recipient: payee, amount }))
    // And against a digest computed from nothing the sink produced.
    expect(receipt.verdict!.paymentDigest).toBe(paymentDigest({ network: "sui:testnet", asset: "0x2::sui::SUI", recipient: "0xabc", amount: "5" }))
  })

  it("a bigint amount is shown as the decimal string its digest hashes", async () => {
    const { sink, seen } = judged(FIXED)
    const { receipt } = await sink({ to: auth("0xabc"), amount: auth(5n) })
    const { payee, amount, asset, network } = seen[0]!.payment!
    expect(amount).toBe("5")
    expect(JSON.stringify(seen[0]!.payment)).toContain('"amount":"5"')
    expect(receipt.verdict!.paymentDigest).toBe(paymentDigest({ network: "sui:testnet", asset: "0x2::sui::SUI", recipient: "0xabc", amount: 5n }))
    expect(receipt.verdict!.paymentDigest).toBe(paymentDigest({ network, asset, recipient: payee, amount }))
  })

  it("an undeclared argument in warn mode leaves the judge its payment", async () => {
    const { sink, seen } = judged(FIXED, { mode: "warn" })
    await sink({ to: auth("0xabc"), amount: auth("5"), extra: auth("x") })
    expect(seen[0]!.payment).toEqual({ payee: "0xabc", amount: "5", asset: "0x2::sui::SUI", network: "sui:testnet" })
  })

  it("a payment planted on Object.prototype does not reach a sink with no purposeArgs", async () => {
    const { sink, seen } = judged({})
    const prototype = Object.prototype as { payment?: unknown }
    prototype.payment = { payee: "0xplanted", amount: "1", asset: "a", network: "n" }
    try {
      await sink({ to: auth("0xabc"), amount: auth("5") })
      expect(seen[0]!.payment).toBeUndefined()
    } finally {
      delete prototype.payment
    }
  })
})
