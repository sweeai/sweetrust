/**
 * The `enforces` declaration is held to recorded evidence, offline: every limit
 * it labels `chain` must have a recorded Sui refusal in testnet-digests.json,
 * with the abort the module declares for it. Relabel a limit `chain` without a
 * recorded refusal and this goes red. (The live suite beside it re-records.)
 */
import { readFileSync } from "node:fs"
import { describe, expect, it } from "vitest"
import { SUI_ALLOWANCE_ABORTS, enforces, type LimitName } from "../../src/index.ts"

const fixture = JSON.parse(readFileSync(new URL("./testnet-digests.json", import.meta.url), "utf8")) as {
  network: string
  recordedAt: string
  cases: Array<{ limit: LimitName; date: string; digest: string; explorer: string; abort: { module: string; abortName: string; abortCode: number; rawAbortCode: string }; why: string }>
}

const EXPECTED_ABORT: Partial<Record<LimitName, string>> = {
  lifetimeCap: "EExceedsLifetimeCap",
  rate: "EExceedsRateLimit",
  start: "ENotStarted",
  expiry: "EExpired",
}

describe("recorded testnet refusals back every `chain` label", () => {
  const chainHeld = (Object.keys(enforces) as Array<LimitName>).filter((l) => enforces[l] === "chain")

  it("covers exactly the limits labeled `chain`, on sui:testnet", () => {
    expect(fixture.network).toBe("sui:testnet")
    expect(fixture.cases.map((c) => c.limit).sort()).toEqual([...chainHeld].sort())
    expect(chainHeld.length).toBe(4)
  })

  for (const limit of ["lifetimeCap", "rate", "start", "expiry"] as const) {
    it(`${limit}: a distinct failed transaction with the module's own abort quoted`, () => {
      const c = fixture.cases.find((x) => x.limit === limit)
      expect(c).toBeDefined()
      if (c === undefined) return
      const abortName = EXPECTED_ABORT[limit] as string
      expect(c.digest).toMatch(/^[1-9A-HJ-NP-Za-km-z]{43,44}$/)
      expect(c.explorer).toBe(`https://suiscan.xyz/testnet/tx/${c.digest}`)
      expect(c.abort).toMatchObject({ module: "0x2::allowance", abortName, abortCode: SUI_ALLOWANCE_ABORTS[abortName] })
      expect(c.abort.rawAbortCode).toMatch(/^\d+$/)
      expect(c.why).toContain(`Refused by Sui validators (allowance::${abortName})`)
      expect(Number.isNaN(Date.parse(c.date))).toBe(false)
    })
  }

  it("has four different digests", () => {
    expect(new Set(fixture.cases.map((c) => c.digest)).size).toBe(fixture.cases.length)
  })
})
