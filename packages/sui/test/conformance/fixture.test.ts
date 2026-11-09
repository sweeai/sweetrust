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

const wrapper = JSON.parse(readFileSync(new URL("./wrapper-spend.json", import.meta.url), "utf8")) as {
  network: string
  digest: string
  explorer: string
  amount: string
  commands: string[]
  withdrawalSource: string
  onChainSpent: string
  chainSpends: { status: string; amount: string }
  reconcile: { ok: boolean; orphans: Array<{ digest: string; reason: string }> }
  preFix: { chainSpendsRows: number; reconcile: { ok: boolean; orphans: unknown[] } }
}

describe("recorded testnet spend through a spender's own Move module (DAN-1403 / R1)", () => {
  it("was a real spend with no top-level 0x2::allowance command", () => {
    expect(wrapper.network).toBe("sui:testnet")
    expect(wrapper.digest).toMatch(/^[1-9A-HJ-NP-Za-km-z]{43,44}$/)
    expect(wrapper.explorer).toBe(`https://suiscan.xyz/testnet/tx/${wrapper.digest}`)
    expect(wrapper.withdrawalSource).toBe("SENDER_ALLOWANCE")
    expect(wrapper.commands.some((c) => c.startsWith("0x2::allowance::"))).toBe(false)
    expect(wrapper.onChainSpent).toBe(wrapper.amount)
  })

  it("chainSpends saw it with the right amount, and reconcile reported it", () => {
    expect(wrapper.chainSpends).toEqual({ status: "success", amount: wrapper.amount })
    expect(wrapper.reconcile).toEqual({ ok: false, orphans: [{ digest: wrapper.digest, reason: "no-receipt" }] })
  })

  it("the pre-fix code missed this same transaction, so the record can tell the two apart", () => {
    expect(wrapper.preFix).toEqual({ chainSpendsRows: 0, reconcile: { ok: true, orphans: [] } })
  })
})
