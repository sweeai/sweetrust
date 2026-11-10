/**
 * A limit past u256 (DAN-1469). Formatting `1n << 1073741000n` never finishes,
 * so a limit that size must never reach `scale.format` or a template string.
 * On a hand-built handle it is a programmer error, thrown at intake before any
 * chain read; at `open()` it stays a refusal, with today's code, and the value
 * is named by one fixed phrase. Each test answering at all is part of the proof:
 * the huge cases would otherwise hang the worker.
 */
import { describe, expect, it, vi } from "vitest"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"
import { normalizeSuiAddress } from "@mysten/sui/utils"
import { defineScale, suiAllowances, type AllowanceLimits, type DelegatedAllowance, type SuiAllowance } from "../src/index.ts"
import { ALLOWANCE_ID, CAP_ID, allowanceState, mockChain, type MockChain } from "./helpers/mock-chain.ts"

const principal = Ed25519Keypair.generate()
const agent = Ed25519Keypair.generate()
const P = principal.toSuiAddress()
const A = agent.toSuiAddress()
const MERCHANT = normalizeSuiAddress("0x5e11e5")
const testUSD = defineScale({ unit: "testUSD", baseUnitsPerUnit: 100_000n, decimals: 2, coinType: "0x2::sui::SUI" })
const DAY = 86_400_000
const FAR = new Date(Date.parse("2027-01-01T00:00:00Z"))

const U256 = (1n << 256n) - 1n
/** Just past u256: cheap to write out, so a test can prove its digits appear nowhere. */
const JUST_PAST = U256 + 1n
/** Never finishes formatting. */
const HUGE = 1n << 1_073_741_000n
const PHRASE = "an amount past u256 (not written out)"

const adapter = (chain: MockChain) => suiAllowances({ client: chain.client, network: "sui:testnet", scale: testUSD, now: () => 0, confirmTimeoutMs: 0 })
const handle = (limits: AllowanceLimits): SuiAllowance => ({
  network: "sui:testnet", asset: "0x2::sui::SUI", allowanceId: ALLOWANCE_ID, capId: CAP_ID, funder: P, spender: A, limits,
})
const grant = (limits: AllowanceLimits): DelegatedAllowance => ({ network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits })
const json = (v: unknown): string => JSON.stringify(v, (_, x) => (typeof x === "bigint" ? "<bigint>" : x))

/** Each limit field that carries an amount, holding `v`, with whatever else the field needs to be a well-formed handle. */
const withLimit = (field: "lifetimeCap" | "rate.amount" | "perSpendMax", v: bigint): AllowanceLimits =>
  field === "lifetimeCap" ? { lifetimeCap: v }
    : field === "rate.amount" ? { rate: { amount: v, windowMs: DAY } }
      : { lifetimeCap: 100n, perSpendMax: v }

describe("a hand-built handle with a limit past u256 is a programmer error, thrown at intake", () => {
  for (const field of ["lifetimeCap", "rate.amount", "perSpendMax"] as const) {
    it.each([
      ["huge", HUGE], ["huge negative", -HUGE], ["just past u256", JUST_PAST], ["just past -u256", -JUST_PAST],
    ] as const)(`${field} %s: spend, revoke and remaining throw a TypeError naming the field and u256, before any chain read`, async (_label, v) => {
      const chain = mockChain(allowanceState({ funder: P, spender: A }), 0n)
      const core = chain.client.core as unknown as Record<string, (...a: Array<unknown>) => unknown>
      const spies = Object.keys(core).map((k) => vi.spyOn(core, k))
      const bad = handle(withLimit(field, v))
      const a = adapter(chain)
      for (const call of [
        () => a.spend({ signer: agent, allowance: bad, amount: 1n, recipient: MERCHANT }),
        () => a.revoke({ signer: principal, allowance: bad }),
        () => a.remaining({ allowance: bad }),
      ]) {
        const err = await call().then(() => null, (e: unknown) => e)
        expect(err).toBeInstanceOf(TypeError)
        const message = (err as TypeError).message
        expect(message).toContain(`allowance.limits.${field} is past u256`)
        expect(message.length).toBeLessThan(400)
        expect(message).not.toMatch(/\d{20}/)
      }
      expect(spies.reduce((n, s) => n + s.mock.calls.length, 0)).toBe(0)
      expect(chain.executed).toHaveLength(0)
    })
  }

  it("a handle whose limits are exactly u256 still passes intake and reaches the chain", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A }), 0n)
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ lifetimeCap: U256, rate: { amount: U256, windowMs: DAY } }), amount: 5n, recipient: MERCHANT })
    expect(r.refusal).toBeNull()
    expect(chain.executed).toHaveLength(1)
  })
})

describe("open() refuses a limit past u256 as a result, with today's code, and never writes it out", () => {
  const cases = [
    { name: "a huge lifetime cap", limits: { lifetimeCap: HUGE, expiry: FAR }, code: "invalid-limit", line: "lifetimeCap", value: `${PHRASE} in total`, why: "Refused at open(); nothing was sent. The lifetime cap does not fit Sui's u256." },
    { name: "a huge negative lifetime cap", limits: { lifetimeCap: -HUGE, expiry: FAR }, code: "invalid-limit", line: "lifetimeCap", value: `${PHRASE} in total`, why: `Refused at open(); nothing was sent to Sui. Sui's rule (0x2::allowance::EZeroLifetimeCap, abort code 13): a lifetime cap must be greater than zero; this one is ${PHRASE}.` },
    { name: "a huge rate", limits: { rate: { amount: HUGE, windowMs: DAY } }, code: "invalid-limit", line: "rate", value: `${PHRASE} per day, in fixed windows counted from the first charge`, why: "Refused at open(); nothing was sent. The rate does not fit Sui's integer types (u256 amount, u64 window)." },
    { name: "a huge negative rate", limits: { rate: { amount: -HUGE, windowMs: 1000 } }, code: "invalid-limit", line: "rate", value: `${PHRASE} per second, in fixed windows counted from the first charge`, why: `Refused at open(); nothing was sent to Sui. Sui's rule (0x2::allowance::EBadRateLimit, abort code 7): a rate needs a positive window and a positive amount; this one is ${PHRASE} per 1000 ms.` },
    { name: "a huge per-spend maximum", limits: { lifetimeCap: 100n, perSpendMax: HUGE, expiry: FAR }, code: "limit-unheld", line: "perSpendMax", value: `${PHRASE} per spend`, why: null },
    { name: "a huge negative per-spend maximum", limits: { lifetimeCap: 100n, perSpendMax: -HUGE, expiry: FAR }, code: "limit-unheld", line: "perSpendMax", value: `${PHRASE} per spend`, why: null },
  ] as const
  for (const c of cases) {
    it(c.name, async () => {
      const chain = mockChain(null, 0n)
      const { receipt, allowance } = await adapter(chain).open({ signer: principal, allowance: grant(c.limits) })
      expect(allowance).toBeNull()
      expect(chain.executed).toHaveLength(0)
      expect(receipt.verdict).toBe("refused")
      expect(receipt.refusal?.code).toBe(c.code)
      if (c.why !== null) expect(receipt.refusal?.why).toBe(c.why)
      expect(receipt.limits.find((l) => l.limit === c.line)?.value).toBe(c.value)
      expect(json(receipt).length).toBeLessThan(20_000)
    })
  }

  it.each([
    ["lifetimeCap", { lifetimeCap: JUST_PAST, expiry: FAR }],
    ["rate", { rate: { amount: JUST_PAST, windowMs: DAY } }],
    ["negative rate", { rate: { amount: -JUST_PAST, windowMs: DAY } }],
    ["perSpendMax", { lifetimeCap: 100n, perSpendMax: JUST_PAST, expiry: FAR }],
  ] as const)("a %s just past u256 is named by the phrase, and its digits appear nowhere on the receipt", async (_label, limits) => {
    const chain = mockChain(null, 0n)
    const { receipt } = await adapter(chain).open({ signer: principal, allowance: grant(limits) })
    expect(chain.executed).toHaveLength(0)
    const text = json(receipt)
    expect(text).toContain(PHRASE)
    expect(text).not.toContain(JUST_PAST.toString())
    expect(text).not.toContain(JUST_PAST.toLocaleString("en-US").slice(0, 20))
  })

  it("an amount up to u256 keeps today's text", async () => {
    const zero = (await adapter(mockChain(null, 0n)).open({ signer: principal, allowance: grant({ lifetimeCap: 0n, rate: { amount: 1n, windowMs: DAY } }) })).receipt
    expect(zero.refusal?.why).toContain("a lifetime cap must be greater than zero; this one is 0.00 testUSD.")
    const negRate = (await adapter(mockChain(null, 0n)).open({ signer: principal, allowance: grant({ rate: { amount: -U256, windowMs: 1000 } }) })).receipt
    expect(negRate.refusal?.why).toContain(`this one is ${testUSD.format(-U256)} per 1000 ms.`)
    expect(negRate.limits.find((l) => l.limit === "rate")?.value).toBe(`${testUSD.format(-U256)} per second, in fixed windows counted from the first charge`)
    const per = (await adapter(mockChain(null, 0n)).open({ signer: principal, allowance: grant({ lifetimeCap: 100n, perSpendMax: U256, expiry: FAR }) })).receipt
    expect(per.limits.find((l) => l.limit === "perSpendMax")?.value).toBe(`${testUSD.format(U256)} per spend`)
  })
})
