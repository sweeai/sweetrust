/**
 * A recipient has one spelling, and no coin type reaches the SDK's parser
 * unbounded (DAN-1458).
 */
import { describe, expect, it, vi } from "vitest"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"
import { normalizeSuiAddress } from "@mysten/sui/utils"
import { defineScale, suiAllowances, type SuiAllowance } from "../src/index.ts"
import { ALLOWANCE_ID, CAP_ID, allowanceState, mockChain } from "./helpers/mock-chain.ts"

const principal = Ed25519Keypair.generate()
const agent = Ed25519Keypair.generate()
const P = principal.toSuiAddress()
const A = agent.toSuiAddress()
const MERCHANT = normalizeSuiAddress("0x5e11e5")
const SUI = "0x" + "0".repeat(63) + "2::sui::SUI"
const NESTED = "0x2::a::B<".repeat(60000) + "u8" + ">".repeat(60000)
const scale = defineScale({ unit: "SUI", baseUnitsPerUnit: 1_000_000_000n, decimals: 9, coinType: SUI })
const chainFor = () => mockChain(allowanceState({ funder: P, spender: A, lifetimeCap: 1_000_000n }), 0n)
const handle = (asset = SUI): SuiAllowance => ({ network: "sui:testnet", asset, allowanceId: ALLOWANCE_ID, capId: CAP_ID, funder: P, spender: A, limits: { lifetimeCap: 1_000_000n } })
const fast = async (run: () => unknown) => {
  const started = performance.now()
  const out = await run()
  // A wide margin: an unbounded parse of this input ended the process.
  expect(performance.now() - started).toBeLessThan(2000)
  return out
}

describe("spend", () => {
  it("refuses a respelled recipient with no authorization required", async () => {
    const chain = chainFor()
    const r = await suiAllowances({ client: chain.client, network: "sui:testnet", scale }).spend({ signer: agent, allowance: handle(), amount: 5n, recipient: `0x${MERCHANT.slice(2).toUpperCase()}` })
    expect(chain.executed).toHaveLength(0)
    expect(r.refusal?.code).toBe("invalid-address")
    expect(r.refusal?.why).toContain(MERCHANT)
  })

  it.each([[true], [false]])("refuses a handle with an oversized coin type (requireAuthorization %s)", async (requireAuthorization) => {
    const chain = chainFor()
    const adapter = suiAllowances({ client: chain.client, network: "sui:testnet", scale, requireAuthorization })
    await fast(async () => {
      await expect(Promise.resolve().then(() => adapter.spend({ signer: agent, allowance: handle(NESTED), amount: 5n, recipient: MERCHANT }))).rejects.toThrow(/too long or too nested/)
    })
    expect(chain.executed).toHaveLength(0)
  })

  it("refuses an over-long recipient before lowercasing it", async () => {
    const chain = chainFor()
    const adapter = suiAllowances({ client: chain.client, network: "sui:testnet", scale, requireAuthorization: true })
    const lowercasing = vi.spyOn(String.prototype, "toLowerCase")
    try {
      const r = await adapter.spend({ signer: agent, allowance: handle(), amount: 5n, recipient: "İ".repeat(70) })
      expect(r.refusal?.code).toBe("not-authorized")
      expect(lowercasing.mock.contexts.some((text) => String(text).includes("İ"))).toBe(false)
    } finally {
      lowercasing.mockRestore()
    }
  })
})

describe("open", () => {
  it("bounds a coin type before parsing it, and keeps its own error", async () => {
    const chain = chainFor()
    const adapter = suiAllowances({ client: chain.client, network: "sui:testnet", scale })
    await fast(async () => {
      await expect(adapter.open({ signer: principal, name: "n", allowance: { asset: NESTED, spender: A, limits: { lifetimeCap: 1n } } } as never)).rejects.toThrow(/not a Move type/)
    })
  })
})
