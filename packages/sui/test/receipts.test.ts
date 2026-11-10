/**
 * Receipts: shape and WHY text for every verdict, against a mocked fullnode.
 *
 * The bar (Danny, 2026-11-06): "be very communicative on the receipt about WHY
 * SweeTrust judged something outside a limit." So the refusal texts are pinned
 * here word for word where the numbers decide them, and by their load-bearing
 * phrases elsewhere.
 */
import { describe, expect, it, vi } from "vitest"
import { ObjectError } from "@mysten/sui/client"
import { Transaction } from "@mysten/sui/transactions"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"
import { normalizeStructTag, normalizeSuiAddress } from "@mysten/sui/utils"
import { ReceiptLog, Sourced, SpendAuthorization, makeSink, paymentDigest } from "sweetrust/gate"
import { SignedReceiptLog, generateSigningKeypair, makeEd25519ReceiptSigner, verifySignedChain } from "sweetrust/verify"
import { defineScale, enforces, suiAllowances, type AllowanceReceipt, type SuiAllowance } from "../src/index.ts"
import { ALLOWANCE_ID, CAP_ID, DIGEST, MAINNET_GENESIS, TESTNET_GENESIS, allowanceState, mockChain, signedDigest, targetsOf, type MockChain } from "./helpers/mock-chain.ts"

const principal = Ed25519Keypair.generate()
const agent = Ed25519Keypair.generate()
const P = principal.toSuiAddress()
const A = agent.toSuiAddress()
const MERCHANT = normalizeSuiAddress("0x5e11e5")
const STRANGER = normalizeSuiAddress("0xbad")

/** Basecamp's scale: 1 cent = 1,000 MIST, so 1.00 testUSD = 100,000 MIST. */
const testUSD = defineScale({ unit: "testUSD", baseUnitsPerUnit: 100_000n, decimals: 2, coinType: "0x2::sui::SUI" })
const DAY = 86_400_000
const T = (iso: string): number => Date.parse(iso)
const LOCAL_NOW = T("2026-11-06T17:00:00Z")

const adapter = (chain: MockChain, log?: SignedReceiptLog) =>
  suiAllowances({ client: chain.client, network: "sui:testnet", scale: testUSD, now: () => LOCAL_NOW, ...(log ? { log } : {}) })

const handle = (limits: SuiAllowance["limits"]): SuiAllowance => ({
  network: "sui:testnet", asset: "0x2::sui::SUI", allowanceId: ALLOWANCE_ID, capId: CAP_ID, funder: P, spender: A, limits,
})

const lineOf = (r: { limits: AllowanceReceipt["limits"] }, limit: string) => {
  const l = r.limits.find((x) => x.limit === limit)
  if (l === undefined) throw new Error(`no ${limit} line`)
  return l
}

// ── The declaration ──────────────────────────────────────────────────────────

describe("enforces: who holds each limit on Sui", () => {
  it("is one frozen declaration: four limits on chain, recipients in the library, per-spend held by nobody", () => {
    expect(enforces).toEqual({ lifetimeCap: "chain", rate: "chain", start: "chain", expiry: "chain", recipients: "library", perSpendMax: "nobody" })
    expect(Object.isFrozen(enforces)).toBe(true)
    expect(adapter(mockChain(null, 0n)).enforces).toBe(enforces)
  })
})

// ── open() ───────────────────────────────────────────────────────────────────

describe("open(): a limit nobody can hold is refused, never dropped", () => {
  it("refuses a per-spend maximum before anything is sent, labels it `nobody`, and names its on-chain successor", async () => {
    const chain = mockChain(null, 0n)
    const { receipt, allowance } = await adapter(chain).open({
      signer: principal,
      allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits: { rate: { amount: testUSD.of(30), windowMs: DAY }, perSpendMax: testUSD.of(5) } },
    })
    expect(allowance).toBeNull()
    expect(chain.executed).toHaveLength(0)
    expect(receipt).toMatchObject({ schema: "sweetrust-sui/receipt@2", verb: "open", verdict: "refused", network: "sui:testnet", digest: null, allowanceId: null, explorer: null, atSource: "local", at: "2026-11-06T17:00:00.000Z" })
    expect(receipt.refusal).toMatchObject({ code: "limit-unheld", refusedBy: "library", native: null })
    const per = lineOf(receipt, "perSpendMax")
    expect(per).toMatchObject({ heldBy: "nobody", verdict: "unheld", value: "5.00 testUSD per spend" })
    for (const why of [receipt.refusal?.why ?? "", per.why]) {
      expect(why).toContain("Refused at open(); nothing was sent to Sui.")
      expect(why).toContain("Opening anyway would drop the limit silently, so nothing was opened.")
      expect(why).toContain("Sui Agent Payments' per-payment cap")
      expect(why).toContain("testnet-only with no public package yet")
    }
    expect(lineOf(receipt, "rate")).toMatchObject({ heldBy: "chain", verdict: "unchecked" })
  })
})

describe("open(): Sui's own rules are checked before sending, and explained in words", () => {
  const cases = [
    {
      name: "ENoLimit: neither a lifetime cap nor a rate",
      limits: { expiry: new Date(T("2026-12-01T00:00:00Z")) },
      code: "unbounded-amount", abort: "ENoLimit", abortCode: 5,
      phrase: "every allowance has a lifetime cap or a rate, so it can never be unbounded in amount",
    },
    {
      name: "ENoExpiration: a lifetime cap alone never ends",
      limits: { lifetimeCap: testUSD.of(30) },
      code: "unbounded-time", abort: "ENoExpiration", abortCode: 15,
      phrase: "every allowance has an expiry or a rate, so it can never be unbounded in time. A lifetime cap alone never ends",
    },
    {
      name: "EZeroLifetimeCap",
      limits: { lifetimeCap: 0n, rate: { amount: 1n, windowMs: DAY } },
      code: "invalid-limit", abort: "EZeroLifetimeCap", abortCode: 13, phrase: "a lifetime cap must be greater than zero",
    },
    {
      name: "EBadTimeWindow",
      limits: { lifetimeCap: 1n, start: new Date(T("2026-12-02T00:00:00Z")), expiry: new Date(T("2026-12-01T00:00:00Z")) },
      code: "invalid-limit", abort: "EBadTimeWindow", abortCode: 14, phrase: "the expiry must come after the start",
    },
    {
      name: "EBadRateLimit",
      limits: { rate: { amount: 0n, windowMs: DAY } },
      code: "invalid-limit", abort: "EBadRateLimit", abortCode: 7, phrase: "a rate needs a positive window and a positive amount",
    },
  ] as const
  for (const c of cases) {
    it(c.name, async () => {
      const chain = mockChain(null, 0n)
      const { receipt } = await adapter(chain).open({ signer: principal, allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits: c.limits } })
      expect(chain.executed).toHaveLength(0)
      expect(receipt.verdict).toBe("refused")
      expect(receipt.digest).toBeNull()
      expect(receipt.refusal).toMatchObject({
        code: c.code, refusedBy: "library",
        native: { module: "0x2::allowance", abortName: c.abort, abortCode: c.abortCode, rawAbortCode: null },
      })
      expect(receipt.refusal?.why).toContain(`Refused at open(); nothing was sent to Sui. Sui's rule (0x2::allowance::${c.abort}, abort code ${c.abortCode})`)
      expect(receipt.refusal?.why).toContain(c.phrase)
    })
  }

  it("refuses an allowance for another network without sending", async () => {
    const chain = mockChain(null, 0n)
    const { receipt } = await adapter(chain).open({ signer: principal, allowance: { network: "sui:mainnet", asset: "0x2::sui::SUI", spender: A, limits: { rate: { amount: 1n, windowMs: DAY } } } })
    expect(chain.executed).toHaveLength(0)
    expect(receipt.refusal?.code).toBe("wrong-network")
    expect(receipt.refusal?.why).toContain("connected to sui:testnet")
  })
})

describe("open(): executed", () => {
  it("calls allowance::new on the plain path, executes without simulating, and labels every limit chain or library", async () => {
    const chain = mockChain(null, 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(0), timestampMs: T("2026-11-06T18:00:00Z"), created: true })
    const { receipt, allowance } = await adapter(chain).open({
      signer: principal,
      allowance: {
        network: "sui:testnet", asset: "0x2::sui::SUI", spender: A,
        limits: { lifetimeCap: testUSD.of(100), rate: { amount: testUSD.of(30), windowMs: DAY }, expiry: new Date(T("2026-12-01T00:00:00Z")), recipients: [MERCHANT] },
      },
      name: "errands",
    })
    expect(chain.simulated).toHaveLength(0)
    expect(chain.executed).toHaveLength(1)
    expect(chain.executed[0].sender).toBe(normalizeSuiAddress(P))
    expect(targetsOf(chain.executed[0].bytes)).toEqual(["0x2::allowance::periodic_rate_limit", "0x1::option::some", "0x2::allowance::new"])
    expect(allowance).toMatchObject({ allowanceId: ALLOWANCE_ID, capId: CAP_ID, funder: normalizeSuiAddress(P), spender: normalizeSuiAddress(A), network: "sui:testnet" })
    expect(receipt).toMatchObject({
      verb: "open", verdict: "executed", digest: signedDigest(chain), allowanceId: ALLOWANCE_ID, at: "2026-11-06T18:00:00.000Z", atSource: "chain",
      explorer: `https://suiscan.xyz/testnet/tx/${signedDigest(chain)}`, refusal: null,
    })
    expect(receipt.limits.map((l) => [l.limit, l.heldBy, l.verdict])).toEqual([
      ["lifetimeCap", "chain", "held"], ["rate", "chain", "held"], ["expiry", "chain", "held"], ["recipients", "library", "held"],
    ])
    expect(lineOf(receipt, "rate").value).toBe("30.00 testUSD per day, in fixed windows counted from the first charge")
    expect(lineOf(receipt, "rate").why).toBe(
      "Held by Sui: at most 30.00 testUSD per day; a spend past it aborts on chain (allowance::EExceedsRateLimit, abort code 4). " +
      "Sui's windows are fixed, not rolling: the first charge opens the first window, and each window lasts exactly 1 day.")
    expect(lineOf(receipt, "recipients").why).toContain("Held by the library, in-process")
    expect(lineOf(receipt, "recipients").why).toContain("Sui Agent Payments' allowed services, which is testnet-only with no public package yet")
    expect(receipt.summary).toContain("Sui holds the lifetime cap, the rate, the expiry; the library holds the recipient list in-process.")
    expect(Object.isFrozen(receipt) && Object.isFrozen(receipt.limits[0])).toBe(true)
  })
})

// ── spend() ──────────────────────────────────────────────────────────────────

const RATE = { amount: testUSD.of(30), windowMs: DAY }
const ANCHOR = T("2026-11-06T18:02:00Z")
const windowed = (spent: bigint, anchorMs: number | null, index = 0n) => ({
  limit: testUSD.of(30), spent, anchorMs: anchorMs === null ? null : BigInt(anchorMs), index, window: { kind: "periodic" as const, periodMs: BigInt(DAY) },
})

describe("spend(): executed", () => {
  it("transfers through balance_spend and says what each limit now holds", async () => {
    const before = allowanceState({ funder: P, spender: A, lifetimeCap: testUSD.of(100), rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    chain.script.push({
      kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR,
      after: { ...before, currentSpend: testUSD.of(24), rate: windowed(testUSD.of(24), ANCHOR) },
    })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ lifetimeCap: testUSD.of(100), rate: RATE, recipients: [MERCHANT] }), amount: testUSD.of(24), recipient: MERCHANT })
    expect(chain.simulated).toHaveLength(0)
    expect(targetsOf(chain.executed[0].bytes)).toEqual(["0x2::allowance::balance_spend", "0x2::coin::from_balance", "TransferObjects"])
    expect(r).toMatchObject({ verb: "spend", verdict: "executed", digest: signedDigest(chain), amount: "2400000", amountText: "24.00 testUSD", recipient: MERCHANT, refusal: null, atSource: "chain" })
    expect(lineOf(r, "lifetimeCap")).toMatchObject({ heldBy: "chain", verdict: "within", why: "Sui checked it: 24.00 testUSD of the 100.00 testUSD cap is now spent, 76.00 testUSD left." })
    expect(lineOf(r, "rate").why).toBe(
      "Sui checked it: the current window now holds 24.00 testUSD of 30.00 testUSD. " +
      "This spend opened the first window (Sui anchors windows at the first charge, 2026-11-06 18:02:00 UTC). The window resets at 2026-11-07 18:02:00 UTC.")
    expect(lineOf(r, "recipients")).toMatchObject({ heldBy: "library", verdict: "within" })
    expect(lineOf(r, "recipients").why).toContain("was checked against the allowed list before sending")
    expect(r.summary).toBe(`Sent 24.00 testUSD to ${MERCHANT} under allowance ${ALLOWANCE_ID} on sui:testnet (tx ${signedDigest(chain)}).`)
  })
})

describe("spend(): refused by Sui validators, a result with a digest", () => {
  it("EExceedsRateLimit: the WHY gives the window's numbers and its fixed bounds", async () => {
    const state = allowanceState({ funder: P, spender: A, lifetimeCap: testUSD.of(100), currentSpend: testUSD.of(24), rate: windowed(testUSD.of(24), ANCHOR) })
    const chain = mockChain(state, 0n)
    chain.script.push({ kind: "abort", digest: DIGEST(2), timestampMs: T("2026-11-06T19:00:00Z"), abortName: "EExceedsRateLimit", errorCode: 4 })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ lifetimeCap: testUSD.of(100), rate: RATE, recipients: [MERCHANT] }), amount: testUSD.of(10), recipient: MERCHANT })
    expect(chain.simulated).toHaveLength(0)
    expect(r).toMatchObject({ verdict: "refused", digest: signedDigest(chain), explorer: `https://suiscan.xyz/testnet/tx/${signedDigest(chain)}`, at: "2026-11-06T19:00:00.000Z", atSource: "chain" })
    expect(r.refusal).toEqual({
      code: "rate-exceeded",
      refusedBy: "chain",
      native: { module: "0x2::allowance", abortName: "EExceedsRateLimit", abortCode: 4, rawAbortCode: "13836185853565075465" },
      why:
        "Refused by Sui validators (allowance::EExceedsRateLimit): this 10.00 testUSD spend would bring the current window to 34.00 testUSD, " +
        "over the rate of 30.00 testUSD per day. Sui's window is fixed: it opened at the first charge (2026-11-06 18:02:00 UTC) and resets at 2026-11-07 18:02:00 UTC.",
    })
    expect(lineOf(r, "rate")).toMatchObject({ heldBy: "chain", verdict: "outside", why: r.refusal?.why })
    // The lifetime cap is checked before the rate, so it passed; nothing was charged.
    expect(lineOf(r, "lifetimeCap").verdict).toBe("within")
    expect(lineOf(r, "lifetimeCap").why).toContain("within the 100.00 testUSD cap (the transaction was then refused, so nothing was charged)")
    expect(lineOf(r, "recipients").verdict).toBe("within")
    expect(r.summary).toBe(r.refusal?.why)
  })

  it("EExceedsRateLimit in a later window says the windows are counted from the first charge", async () => {
    const state = allowanceState({ funder: P, spender: A, rate: windowed(testUSD.of(25), ANCHOR, 2n) })
    const chain = mockChain(state, 0n)
    chain.script.push({ kind: "abort", digest: DIGEST(2), timestampMs: ANCHOR + 2 * DAY + 3_600_000, abortName: "EExceedsRateLimit", errorCode: 4 })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: testUSD.of(10), recipient: MERCHANT })
    expect(r.refusal?.why).toBe(
      "Refused by Sui validators (allowance::EExceedsRateLimit): this 10.00 testUSD spend would bring the current window to 35.00 testUSD, over the rate of 30.00 testUSD per day. " +
      "Sui's window is fixed: windows are counted from the first charge (2026-11-06 18:02:00 UTC); the current one opened at 2026-11-08 18:02:00 UTC and resets at 2026-11-09 18:02:00 UTC.")
  })

  it("EExceedsRateLimit on a first charge larger than the whole rate", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    chain.script.push({ kind: "abort", digest: DIGEST(2), timestampMs: ANCHOR, abortName: "EExceedsRateLimit", errorCode: 4 })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: testUSD.of(40), recipient: MERCHANT })
    expect(r.refusal?.why).toBe(
      "Refused by Sui validators (allowance::EExceedsRateLimit): this 40.00 testUSD spend alone is over the rate of 30.00 testUSD per day; no window is open yet, and the first charge opens one, so no window can hold it.")
  })

  it("EExceedsLifetimeCap: what was spent, what is left, and the rate is reported unchecked", async () => {
    const state = allowanceState({ funder: P, spender: A, lifetimeCap: testUSD.of(30), currentSpend: testUSD.of(27), rate: windowed(testUSD.of(2), ANCHOR) })
    const chain = mockChain(state, 0n)
    chain.script.push({ kind: "abort", digest: DIGEST(2), timestampMs: T("2026-11-06T19:00:00Z"), abortName: "EExceedsLifetimeCap", errorCode: 3 })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ lifetimeCap: testUSD.of(30), rate: RATE }), amount: testUSD.of(5), recipient: MERCHANT })
    expect(r.refusal).toMatchObject({ code: "lifetime-cap-exceeded", refusedBy: "chain", native: { abortName: "EExceedsLifetimeCap", abortCode: 3 } })
    expect(r.refusal?.why).toBe(
      "Refused by Sui validators (allowance::EExceedsLifetimeCap): this 5.00 testUSD spend would bring the lifetime total to 32.00 testUSD, over the 30.00 testUSD lifetime cap. " +
      "27.00 testUSD had already been spent, so at most 3.00 testUSD more can ever go out.")
    expect(lineOf(r, "lifetimeCap").verdict).toBe("outside")
    expect(lineOf(r, "rate")).toMatchObject({ verdict: "unchecked" })
    expect(lineOf(r, "rate").why).toContain("stops at the first that fails; the lifetime cap failed first")
  })

  it("ENotStarted: when it starts, when the spend arrived, and how early", async () => {
    const start = T("2026-11-07T18:00:00Z")
    const state = allowanceState({ funder: P, spender: A, lifetimeCap: testUSD.of(30), startMs: BigInt(start), expiryMs: BigInt(start + DAY) })
    const chain = mockChain(state, 0n)
    chain.script.push({ kind: "abort", digest: DIGEST(2), timestampMs: start - 90 * 60_000, abortName: "ENotStarted", errorCode: 8 })
    const r = await adapter(chain).spend({
      signer: agent, allowance: handle({ lifetimeCap: testUSD.of(30), start: new Date(start), expiry: new Date(start + DAY) }), amount: testUSD.of(1), recipient: MERCHANT,
    })
    expect(r.refusal).toMatchObject({ code: "not-started", native: { abortName: "ENotStarted", abortCode: 8 } })
    expect(r.refusal?.why).toBe(
      "Refused by Sui validators (allowance::ENotStarted): the allowance starts at 2026-11-07 18:00:00 UTC, and this spend reached the chain at 2026-11-07 16:30:00 UTC, 1 hour 30 minutes early. " +
      "Sui refuses every spend before the start time.")
    expect(r.limits.map((l) => [l.limit, l.verdict])).toEqual([["lifetimeCap", "unchecked"], ["start", "outside"], ["expiry", "unchecked"]])
  })

  it("EExpired: when it expired and how late the spend was", async () => {
    const expiry = T("2026-11-06T18:00:00Z")
    const chain = mockChain(allowanceState({ funder: P, spender: A, lifetimeCap: testUSD.of(30), expiryMs: BigInt(expiry) }), 0n)
    chain.script.push({ kind: "abort", digest: DIGEST(2), timestampMs: expiry + 42_000, abortName: "EExpired", errorCode: 2 })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ lifetimeCap: testUSD.of(30), expiry: new Date(expiry) }), amount: testUSD.of(1), recipient: MERCHANT })
    expect(r.refusal).toMatchObject({ code: "expired", native: { abortName: "EExpired", abortCode: 2 } })
    expect(r.refusal?.why).toBe(
      "Refused by Sui validators (allowance::EExpired): the allowance expired at 2026-11-06 18:00:00 UTC, and this spend reached the chain at 2026-11-06 18:00:42 UTC, 42 seconds after it. " +
      "The expiry is exclusive: from that instant on, every spend is refused.")
    expect(r.limits.map((l) => [l.limit, l.verdict])).toEqual([["lifetimeCap", "unchecked"], ["expiry", "outside"]])
  })

  it("ENotSpender: names the signer and the spender", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    chain.script.push({ kind: "abort", digest: DIGEST(2), timestampMs: ANCHOR, abortName: "ENotSpender", errorCode: 0 })
    const r = await adapter(chain).spend({ signer: principal, allowance: handle({ rate: RATE }), amount: 1n, recipient: MERCHANT })
    expect(r.refusal).toMatchObject({ code: "not-spender", refusedBy: "chain", native: { abortName: "ENotSpender", abortCode: 0 } })
    expect(r.refusal?.why).toContain(`signed by ${normalizeSuiAddress(P)}, and only the allowance's spender ${A} may spend from it`)
    expect(lineOf(r, "rate").verdict).toBe("unchecked")
  })
})

describe("spend(): the library-held limit", () => {
  it("refuses a payee off the allowed list in-process, sends nothing, and says what that protects", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE, recipients: [MERCHANT] }), amount: testUSD.of(5), recipient: STRANGER })
    expect(chain.executed).toHaveLength(0)
    expect(r).toMatchObject({ verdict: "refused", digest: null, explorer: null, atSource: "local" })
    expect(r.refusal).toMatchObject({ code: "recipient-not-allowed", refusedBy: "library", native: null })
    const why = r.refusal?.why ?? ""
    expect(why).toContain(`Refused in-process by sweetrust-sui; nothing was sent to Sui. ${STRANGER} is not on this allowance's allowed list (1 address: `)
    expect(why).toContain("this protects only spends routed through this library")
    expect(why).toContain("the spender's key can still pay any address through another Sui client, up to the limits Sui holds")
    expect(why).toContain("Sui Agent Payments' allowed services, which is testnet-only with no public package yet")
    expect(lineOf(r, "recipients")).toMatchObject({ heldBy: "library", verdict: "outside", why })
    expect(lineOf(r, "rate")).toMatchObject({ heldBy: "chain", verdict: "unchecked", why: "Not evaluated: nothing was sent to Sui." })
  })

  it("refuses a hand-built handle that carries a limit nobody holds, instead of ignoring it", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE, perSpendMax: 1n }), amount: 5n, recipient: MERCHANT })
    expect(chain.executed).toHaveLength(0)
    expect(r.refusal?.code).toBe("limit-unheld")
    expect(lineOf(r, "perSpendMax")).toMatchObject({ heldBy: "nobody", verdict: "unheld" })
    expect(r.refusal?.why).toContain("Sui Agent Payments' per-payment cap")
  })

  it("refuses an amount outside 1..u64 without sending", async () => {
    const chain = mockChain(null, 0n)
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: 0n, recipient: MERCHANT })
    expect(chain.executed).toHaveLength(0)
    expect(r.refusal?.code).toBe("invalid-amount")
  })
})

describe("spend(): rejected before execution", () => {
  it("nothing signed and the allowance not found is `allowance-not-found`, with no digest", async () => {
    const chain = mockChain(null, 0n)
    chain.breakBuild = true
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: 1n, recipient: MERCHANT })
    expect(chain.executed).toHaveLength(0)
    expect(r).toMatchObject({ verdict: "refused", digest: null })
    expect(r.refusal).toMatchObject({ code: "allowance-not-found", refusedBy: "library", native: null })
    expect(r.refusal?.why).toContain(`Allowance ${ALLOWANCE_ID} was not found on sui:testnet`)
    expect(`${r.summary} ${r.limits.map((l) => l.why).join(" ")}`).not.toMatch(/revoked/i)
  })

  it("an amount past u256 is `invalid-amount` in one fixed sentence, and its digits appear nowhere on the receipt", async () => {
    const U256 = (1n << 256n) - 1n
    const whys = new Set<string | undefined>()
    // The last one never finishes stringifying, so this test answering at all is the proof it is never written out.
    for (const amount of [U256 + 1n, -(U256 + 1n), 1n << 1_073_741_000n]) {
      const chain = mockChain(null, 0n)
      const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount, recipient: MERCHANT })
      expect(chain.executed).toHaveLength(0)
      expect(r).toMatchObject({ verdict: "refused", amount: null, amountText: null, refusal: { code: "invalid-amount", refusedBy: "library" } })
      const json = JSON.stringify(r)
      expect(json.length).toBeLessThan(20_000)
      if (amount < 1n << 300n) expect(json).not.toContain((amount < 0n ? -amount : amount).toString())
      whys.add(r.refusal?.why)
    }
    expect([...whys]).toEqual(["Refused in-process; nothing was sent. A spend must be a whole number of base units from 1 to 18446744073709551615; this one is an amount past u256, the largest integer Sui holds, so it is not written out here."])
    // At u256 itself the amount is still stated, as before.
    const atMax = await adapter(mockChain(null, 0n)).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: U256, recipient: MERCHANT })
    expect(atMax).toMatchObject({ amount: String(U256), amountText: testUSD.format(U256), refusal: { code: "invalid-amount" } })
    expect(atMax.refusal?.why).toContain(`this one is ${U256}.`)
  })
})

// ── revoke() ─────────────────────────────────────────────────────────────────

describe("revoke()", () => {
  it("consumes the AllowanceCap and marks every limit revoked", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(3), timestampMs: ANCHOR, after: null })
    const r = await adapter(chain).revoke({ signer: principal, allowance: handle({ rate: RATE, recipients: [MERCHANT] }) })
    expect(targetsOf(chain.executed[0].bytes)).toEqual(["0x2::allowance::revoke"])
    expect(r).toMatchObject({ verb: "revoke", verdict: "executed", digest: signedDigest(chain), refusal: null })
    expect(r.limits.map((l) => [l.limit, l.heldBy, l.verdict])).toEqual([["rate", "chain", "revoked"], ["recipients", "library", "revoked"]])
    expect(r.summary).toContain("Sui refuses every later spend against it")
  })
})

// ── remaining() ──────────────────────────────────────────────────────────────

describe("remaining(): read from the chain's object and clock", () => {
  it("lifetime cap minus spend, rate minus the current window's spend, and the window's bounds", async () => {
    const now = BigInt(ANCHOR + 3_600_000)
    const chain = mockChain(allowanceState({ funder: P, spender: A, lifetimeCap: testUSD.of(100), currentSpend: testUSD.of(24), rate: windowed(testUSD.of(24), ANCHOR), expiryMs: BigInt(ANCHOR + 7 * DAY) }), now)
    const rem = await adapter(chain).remaining({ allowance: handle({ lifetimeCap: testUSD.of(100), rate: RATE, expiry: new Date(ANCHOR + 7 * DAY) }) })
    expect(rem).toMatchObject({
      exists: true, active: true, at: "2026-11-06T19:02:00.000Z", spendableNow: String(testUSD.of(6)),
      lifetime: { cap: String(testUSD.of(100)), spent: String(testUSD.of(24)), remaining: String(testUSD.of(76)) },
      rate: { limit: String(testUSD.of(30)), windowMs: DAY, spentInWindow: String(testUSD.of(24)), remainingInWindow: String(testUSD.of(6)), windowStart: "2026-11-06T18:02:00.000Z", windowEnd: "2026-11-07T18:02:00.000Z" },
    })
    expect(lineOf(rem, "rate").why).toBe("Read from the chain: 24.00 testUSD spent in the current window, 6.00 testUSD of 30.00 testUSD left. The current window opened at 2026-11-06 18:02:00 UTC and resets at 2026-11-07 18:02:00 UTC.")
    expect(lineOf(rem, "expiry").why).toBe("Expires at 2026-11-13 18:02:00 UTC, in 6 days 23 hours.")
  })

  it("a window that has passed counts as empty, exactly as the chain's charge() resets it", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(testUSD.of(30), ANCHOR) }), BigInt(ANCHOR + DAY + 1))
    const rem = await adapter(chain).remaining({ allowance: handle({ rate: RATE }) })
    expect(rem.rate).toMatchObject({ spentInWindow: "0", remainingInWindow: String(testUSD.of(30)), windowStart: "2026-11-07T18:02:00.000Z" })
  })

  it("an expired allowance can spend nothing; a revoked one does not exist", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, lifetimeCap: 10n, expiryMs: BigInt(ANCHOR) }), BigInt(ANCHOR + 1000))
    const rem = await adapter(chain).remaining({ allowance: handle({ lifetimeCap: 10n, expiry: new Date(ANCHOR) }) })
    expect(rem).toMatchObject({ active: false, spendableNow: "0" })
    expect(lineOf(rem, "expiry")).toMatchObject({ verdict: "outside", why: "Expired at 2026-11-06 18:02:00 UTC, 1 second ago." })
    chain.state = null
    const gone = await adapter(chain).remaining({ allowance: handle({ lifetimeCap: 10n }) })
    expect(gone).toMatchObject({ exists: false, active: false, spendableNow: "0" })
    expect(gone.summary).toContain("was not found on sui:testnet")
    expect(`${gone.summary} ${gone.limits.map((l) => l.why).join(" ")}`).not.toMatch(/revoked/i)
    expect(gone.limits.map((l) => l.verdict)).toEqual(["unchecked"])
  })
})

// ── What a read can and cannot say (audit 2026-11-08: R2, R7, R8, R9) ─────────

describe("absence and unknowns are never read as facts", () => {
  const live = () => mockChain(allowanceState({ funder: P, spender: A, lifetimeCap: 1000n, expiryMs: BigInt(ANCHOR + DAY) }), BigInt(ANCHOR))
  const limits = { lifetimeCap: 1000n, expiry: new Date(ANCHOR + DAY) }
  const core = (chain: MockChain) => chain.client.core as unknown as Record<string, unknown>
  const fails = async () => { throw new Error("rpc down") }

  it("a not-found answer that is not an ObjectError is no absence: remaining says it could not be determined", async () => {
    const chain = live()
    core(chain).getObjects = async () => ({ objects: [new Error("Object not found")] })
    const rem = await adapter(chain).remaining({ allowance: handle(limits) })
    expect(rem).toMatchObject({ exists: null, active: null, spendableNow: null })
    expect(rem.summary).toContain("Could not determine")
    expect(rem.limits.map((l) => l.verdict)).toEqual(["unchecked", "unchecked"])
  })

  it("an empty answer is no absence", async () => {
    const chain = live()
    core(chain).getObjects = async () => ({ objects: [] })
    expect((await adapter(chain).remaining({ allowance: handle(limits) })).exists).toBeNull()
  })

  it("an ObjectError of another reason is no absence", async () => {
    const chain = live()
    core(chain).getObjects = async () => ({ objects: [new ObjectError("unavailable", "try later", { reason: "unknown" })] })
    expect((await adapter(chain).remaining({ allowance: handle(limits) })).exists).toBeNull()
  })

  it("absence takes more than one answer: one stale not-found, then a live read, is live", async () => {
    const chain = live()
    const real = core(chain).getObjects as (a: { objectIds: Array<string> }) => Promise<unknown>
    let calls = 0
    core(chain).getObjects = async (a: { objectIds: Array<string> }) => {
      if (a.objectIds[0] !== ALLOWANCE_ID || ++calls > 1) return real(a)
      return { objects: [new ObjectError("notFound", "not found", { reason: "notFound" })] }
    }
    expect(await adapter(chain).remaining({ allowance: handle(limits) })).toMatchObject({ exists: true, active: true, spendableNow: "1000" })
    expect(calls).toBeGreaterThan(1)
  })

  it("an unreadable clock leaves the time unknown instead of borrowing this machine's", async () => {
    const chain = live()
    const real = core(chain).getObjects as (a: { objectIds: Array<string> }) => Promise<unknown>
    core(chain).getObjects = async (a: { objectIds: Array<string> }) => (a.objectIds[0] === "0x6" ? fails() : real(a))
    const a = suiAllowances({ client: chain.client, network: "sui:testnet", now: () => ANCHOR + 400 * DAY })
    const rem = await a.remaining({ allowance: handle(limits) })
    expect(rem).toMatchObject({ exists: true, at: null, active: null, spendableNow: null, lifetime: { remaining: "1000" } })
    expect(rem.summary).toContain("Could not determine")
    expect(lineOf(rem, "expiry").verdict).toBe("unchecked")
  })

  it("an unreadable clock leaves the rate window unknown, not empty", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), BigInt(ANCHOR))
    const real = core(chain).getObjects as (a: { objectIds: Array<string> }) => Promise<unknown>
    core(chain).getObjects = async (a: { objectIds: Array<string> }) => (a.objectIds[0] === "0x6" ? fails() : real(a))
    const rem = await adapter(chain).remaining({ allowance: handle({ rate: RATE }) })
    expect(rem.rate).toMatchObject({ spentInWindow: null, remainingInWindow: null })
    expect(lineOf(rem, "rate").verdict).toBe("unchecked")
  })

  it.each([["", "empty"], ["0x12", "short"], ["0xnot-hex", "malformed"]])("recipient %j (%s) is refused with a receipt and signs nothing", async (recipient) => {
    const chain = live()
    const r = await adapter(chain).spend({ signer: agent, allowance: handle(limits), amount: 1n, recipient })
    expect(chain.executed).toHaveLength(0)
    expect(r).toMatchObject({ verdict: "refused", digest: null, recipient })
    expect(r.refusal?.code).toBe("invalid-address")
  })

  it("a short spender is refused at open(), since padding it would name a different address", async () => {
    const chain = mockChain(null, 0n)
    const { receipt } = await adapter(chain).open({ signer: principal, allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: "0x12", limits: { rate: { amount: 1n, windowMs: DAY } } } })
    expect(receipt.refusal?.code).toBe("invalid-address")
  })

  it("the receipt carries the digest of the signed bytes when the node answers with another, confirmed on chain", async () => {
    const chain = live()
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: chain.state })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle(limits), amount: 1n, recipient: MERCHANT })
    expect(signedDigest(chain)).not.toBe(DIGEST(1))
    expect(r).toMatchObject({ verdict: "executed", digest: signedDigest(chain) })
  })

  it("a node answering with another digest, and the signed one unconfirmed, is `errored`: its success was not about this transaction", async () => {
    const chain = live()
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: chain.state, unconfirmable: true })
    const a = suiAllowances({ client: chain.client, network: "sui:testnet", scale: testUSD, confirmTimeoutMs: 0 })
    const r = await a.spend({ signer: agent, allowance: handle(limits), amount: 1n, recipient: MERCHANT })
    expect(r).toMatchObject({ verdict: "errored", digest: signedDigest(chain), refusal: null })
    expect(r.summary).toContain("not the digest of the transaction this adapter signed")
  })

  it("a scale reads only its own coin type; another asset reads in base units", async () => {
    const chain = live()
    const usdc = "0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC"
    const a = suiAllowances({ client: chain.client, network: "sui:testnet", scale: testUSD })
    const r = await a.spend({ signer: agent, allowance: { ...handle({ ...limits, recipients: [STRANGER] }), asset: usdc }, amount: 1_000_000n, recipient: MERCHANT })
    expect(r.amountText).toBe(`1,000,000 base units of ${usdc}`)
  })

  it("a scale with no coin type is refused when the adapter is built, so it cannot silently label the wrong coin", () => {
    const unbound = defineScale({ unit: "X", baseUnitsPerUnit: 10n, decimals: 1 })
    expect(unbound.coinType).toBeNull()
    expect(() => suiAllowances({ client: live().client, network: "sui:testnet", scale: unbound })).toThrow(/bound to a coin type/)
  })

  it("defineScale refuses a coin type that is not a Move type", () => {
    expect(() => defineScale({ unit: "X", baseUnitsPerUnit: 10n, decimals: 1, coinType: "nope" })).toThrow(TypeError)
  })

  it("a transport whose ObjectError is another copy's class still counts as absence", async () => {
    const chain = live()
    class ForeignObjectError extends Error { reason = "deleted" }
    core(chain).getObjects = async () => ({ objects: [new ForeignObjectError("deleted")] })
    expect((await adapter(chain).remaining({ allowance: handle(limits) })).exists).toBe(false)
  })

  it("the clock read retries one dropped answer instead of blanking the status", async () => {
    const chain = live()
    const real = core(chain).getObjects as (a: { objectIds: Array<string> }) => Promise<unknown>
    let clockCalls = 0
    core(chain).getObjects = async (a: { objectIds: Array<string> }) => (a.objectIds[0] === "0x6" && ++clockCalls === 1 ? fails() : real(a))
    expect(await adapter(chain).remaining({ allowance: handle(limits) })).toMatchObject({ exists: true, active: true, at: new Date(ANCHOR).toISOString() })
  })
})

// ── The receipt log ──────────────────────────────────────────────────────────

describe("receipts on a SweeTrust SignedReceiptLog", () => {
  it("appends every receipt, refusals included, so verifySignedChain re-checks them", async () => {
    const keys = generateSigningKeypair()
    const signer = makeEd25519ReceiptSigner(keys)
    const log = new SignedReceiptLog(signer)
    const state = allowanceState({ funder: P, spender: A, rate: windowed(testUSD.of(24), ANCHOR) })
    const chain = mockChain(state, 0n)
    chain.script.push({ kind: "abort", digest: DIGEST(2), timestampMs: ANCHOR + 60_000, abortName: "EExceedsRateLimit", errorCode: 4 })
    const sui = adapter(chain, log)
    const refused = await sui.spend({ signer: agent, allowance: handle({ rate: RATE, recipients: [MERCHANT] }), amount: testUSD.of(10), recipient: MERCHANT })
    const offList = await sui.spend({ signer: agent, allowance: handle({ rate: RATE, recipients: [MERCHANT] }), amount: testUSD.of(1), recipient: STRANGER })

    const all = log.all()
    expect(all).toHaveLength(2)
    expect(all[0]).toMatchObject({ sink: "sweetrust-sui.spend", decision: "refused", reason: refused.refusal?.why })
    expect(all[0].args.receipt.value).toBe(refused)
    expect(all[0].args.receipt.tier).toBe("untrusted")
    expect(all[0].args.receipt.provenance).toBe(`sweetrust-sui on sui:testnet, tx ${signedDigest(chain)}`)
    expect(all[1]).toMatchObject({ decision: "refused", reason: offList.refusal?.why })
    expect(all[1].args.receipt.provenance).toBe("sweetrust-sui on sui:testnet, nothing sent")
    const report = verifySignedChain(log.signed(), { trustedSignerPublicKeyHex: signer.publicKeyHex })
    expect(report).toMatchObject({ valid: true, reason: "ok" })
  })
})

// ── A submit that throws after signing ────────────────────────────────────────

describe("a thrown submit is resolved by digest, never guessed to be a refusal", () => {
  it("spend: the response is lost but the transaction finalized → `executed`, not refused (no double-pay)", async () => {
    const after = allowanceState({ funder: P, spender: A, rate: windowed(testUSD.of(10), ANCHOR) })
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, ANCHOR) }), BigInt(ANCHOR + 1000))
    chain.script.push({ kind: "throw", message: "fetch failed: socket hang up", after, finalizes: { kind: "executed", timestampMs: ANCHOR + 1000, after } })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: testUSD.of(10), recipient: MERCHANT })
    expect(r).toMatchObject({ verdict: "executed", refusal: null })
    expect(r.digest).not.toBeNull()
    expect(r.summary).toContain("Sent 10.00 testUSD")
  })

  it("spend: the response is lost and nothing landed → `errored` with the digest, warning against a blind retry", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, ANCHOR) }), BigInt(ANCHOR + 1000))
    chain.script.push({ kind: "throw", message: "fetch failed: ETIMEDOUT" })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: testUSD.of(10), recipient: MERCHANT })
    expect(r).toMatchObject({ verdict: "errored", refusal: null })
    expect(r.digest).not.toBeNull()
    expect(r.summary).toContain("do not retry blindly")
    expect(r.summary).toContain("pay twice")
    expect(lineOf(r, "rate")).toMatchObject({ verdict: "unchecked" })
  })

  it("spend: a build failure sends nothing → refused by the library, never a chain refusal", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, ANCHOR) }), BigInt(ANCHOR))
    chain.breakBuild = true
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: testUSD.of(10), recipient: MERCHANT })
    expect(chain.executed).toHaveLength(0)
    expect(r).toMatchObject({ verdict: "refused", digest: null })
    expect(r.refusal).toMatchObject({ code: "not-submitted", refusedBy: "library", native: null })
  })

  it("spend: signed, unconfirmed, and the allowance is gone → `errored` with its digest, because the spend may have landed before the allowance went", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), BigInt(ANCHOR))
    chain.script.push({ kind: "throw", message: "The following input objects are invalid: deleted", after: null })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: 1n, recipient: MERCHANT })
    expect(chain.state).toBeNull()
    expect(r).toMatchObject({ verdict: "errored", digest: signedDigest(chain), refusal: null })
    expect(r.summary).toContain("MAY or MAY NOT have moved")
    expect(r.limits.map((l) => l.why).join(" ")).not.toMatch(/nothing was spent/i)
  })

  it("revoke: signed, unconfirmed, and the allowance is gone → `errored` with its digest", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), BigInt(ANCHOR))
    chain.script.push({ kind: "throw", message: "fetch failed: socket hang up", after: null })
    const r = await adapter(chain).revoke({ signer: principal, allowance: handle({ rate: RATE }) })
    expect(r).toMatchObject({ verdict: "errored", digest: signedDigest(chain), refusal: null })
    expect(r.summary).toContain("MAY or MAY NOT still be live")
  })

  it("revoke: not sent and not found is never read as done: `allowance-not-found`, and it says it did not run", async () => {
    const chain = mockChain(null, 0n)
    chain.breakBuild = true
    const r = await adapter(chain).revoke({ signer: principal, allowance: handle({ rate: RATE }) })
    expect(r).toMatchObject({ verdict: "refused", digest: null })
    expect(r.refusal?.code).toBe("allowance-not-found")
    expect(r.summary).toContain("it did NOT run")
    expect(r.summary).toContain("was not found on sui:testnet")
    expect(r.summary).not.toMatch(/already revoked/i)
  })

  it("open: the response is lost but the allowance WAS created → the real allowance, not a false refusal (no double-open)", async () => {
    const chain = mockChain(null, 0n)
    chain.script.push({ kind: "throw", message: "fetch failed: socket hang up", finalizes: { kind: "executed", timestampMs: ANCHOR, created: true } })
    const { receipt, allowance } = await adapter(chain).open({
      signer: principal,
      allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits: { rate: { amount: testUSD.of(30), windowMs: DAY } } },
    })
    expect(receipt.verdict).toBe("executed")
    expect(allowance?.allowanceId).toBe(ALLOWANCE_ID)
    expect(receipt.digest).not.toBeNull()
  })

  it("open: the response is lost and nothing landed → `errored`, allowance null, warning against a second allowance", async () => {
    const chain = mockChain(null, 0n)
    chain.script.push({ kind: "throw", message: "fetch failed: ETIMEDOUT" })
    const { receipt, allowance } = await adapter(chain).open({
      signer: principal,
      allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits: { rate: { amount: testUSD.of(30), windowMs: DAY } } },
    })
    expect(receipt.verdict).toBe("errored")
    expect(allowance).toBeNull()
    expect(receipt.digest).not.toBeNull()
    expect(receipt.summary).toContain("double the spender's budget")
  })

  it("revoke: the response is lost and nothing landed → `errored`, not a false 'still live' refusal", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, ANCHOR) }), BigInt(ANCHOR))
    chain.script.push({ kind: "throw", message: "fetch failed: ETIMEDOUT" })
    const r = await adapter(chain).revoke({ signer: principal, allowance: handle({ rate: RATE }) })
    expect(r).toMatchObject({ verdict: "errored", refusal: null })
    expect(r.digest).not.toBeNull()
  })

  it("an errored receipt lands on the SignedReceiptLog as an `errored` decision, and the chain still verifies", async () => {
    const keys = generateSigningKeypair()
    const signer = makeEd25519ReceiptSigner(keys)
    const log = new SignedReceiptLog(signer)
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, ANCHOR) }), BigInt(ANCHOR))
    chain.script.push({ kind: "throw", message: "fetch failed: ETIMEDOUT" })
    const r = await adapter(chain, log).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: testUSD.of(10), recipient: MERCHANT })
    expect(r.verdict).toBe("errored")
    expect(log.all()[0]).toMatchObject({ sink: "sweetrust-sui.spend", decision: "errored" })
    expect(verifySignedChain(log.signed(), { trustedSignerPublicKeyHex: signer.publicKeyHex })).toMatchObject({ valid: true, reason: "ok" })
  })
})

// ── Receipts quote the chain, not the caller's handle ─────────────────────────

describe("a spend receipt takes chain-held values from the chain, never the handle", () => {
  it("shows the chain's lifetime cap (not the handle's), flags the disagreement, and reports the signer as spender", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, lifetimeCap: testUSD.of(100), currentSpend: testUSD.of(10) }), BigInt(ANCHOR))
    chain.script.push({ kind: "executed", digest: DIGEST(0), timestampMs: ANCHOR, after: allowanceState({ funder: P, spender: A, lifetimeCap: testUSD.of(100), currentSpend: testUSD.of(20) }) })
    // The handle lies: it claims a $10 cap where the chain holds $100.
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ lifetimeCap: testUSD.of(10) }), amount: testUSD.of(10), recipient: MERCHANT })
    expect(r.verdict).toBe("executed")
    const cap = lineOf(r, "lifetimeCap")
    expect(cap.value).toBe("100.00 testUSD in total")
    expect(cap.why).toContain("the handle passed to spend() said 10.00 testUSD in total")
    expect(r.spender).toBe(A)
  })
})

// ── Intake ───────────────────────────────────────────────────────────────────

describe("intake: each argument field is read once", () => {
  it("refuses a limits object with an unknown key instead of dropping it (a typo cannot weaken the allowance)", async () => {
    const chain = mockChain(null, 0n)
    const badLimits = { rate: { amount: testUSD.of(30), windowMs: DAY }, recipient: MERCHANT } as unknown as SuiAllowance["limits"]
    await expect(adapter(chain).open({
      signer: principal,
      allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits: badLimits },
    })).rejects.toThrow(/unknown key "recipient"/)
    const spendBad = { rate: RATE, maxPerSpend: testUSD.of(5) } as unknown as SuiAllowance["limits"]
    await expect(adapter(chain).spend({ signer: agent, allowance: handle(spendBad), amount: 1n, recipient: MERCHANT }))
      .rejects.toThrow(/unknown key "maxPerSpend"/)
    expect(chain.executed).toHaveLength(0)
  })

  it("open() reads its limits once (a getter that changes its answer cannot split the check from the send)", async () => {
    let reads = 0
    const limits = {
      get lifetimeCap() {
        reads += 1
        return reads === 1 ? testUSD.of(30) : 0n
      },
      rate: RATE,
    }
    const chain = mockChain(null, 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(0), timestampMs: ANCHOR, created: true })
    const { receipt } = await adapter(chain).open({ signer: principal, allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits } })
    expect(reads).toBe(1)
    expect(receipt.verdict).toBe("executed")
    expect(lineOf(receipt, "lifetimeCap").value).toBe("30.00 testUSD in total")
  })

  it.each(["junk", "vector<u8>"])("a hand-built handle whose asset %s is not a coin type is rejected by spend, revoke and remaining before any chain read", async (asset) => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    const core = chain.client.core as unknown as Record<string, (...a: Array<unknown>) => unknown>
    const spies = Object.keys(core).map((k) => vi.spyOn(core, k))
    const bad = { ...handle({ rate: RATE }), asset }
    const a = adapter(chain)
    for (const call of [
      () => a.spend({ signer: agent, allowance: bad, amount: 1n, recipient: MERCHANT }),
      () => a.revoke({ signer: principal, allowance: bad }),
      () => a.remaining({ allowance: bad }),
    ]) {
      const err = await call().then(() => null, (e: unknown) => e)
      expect(err).toBeInstanceOf(TypeError)
      expect((err as TypeError).message).toContain("allowance.asset is not a coin type")
    }
    expect(spies.reduce((n, s) => n + s.mock.calls.length, 0)).toBe(0)
    expect(chain.executed).toHaveLength(0)
  })

  // The SDK's normalizer rewrites each of these without throwing, and `isValidStructTag` refuses
  // the rewrite. The first two are DAN-1470's cut-time probe; the rest are DAN-1463's security
  // review, three of which used to make nine chain reads and execute a transaction on the mock.
  const NORMALIZES_BUT_INVALID = ["0xzz::a::B", "0x2::sui::SUI<>", "0x2::a::B!", "0x2::sui::SU I", "0x2::s-ui::SUI", " 0x2::sui::SUI ", "0x2::sui::SUI<u8,>"]

  it.each(NORMALIZES_BUT_INVALID)("a hand-built handle whose asset %j normalizes but is not a valid coin type is rejected by spend, revoke and remaining before any chain read", async (asset) => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    const core = chain.client.core as unknown as Record<string, (...a: Array<unknown>) => unknown>
    const spies = Object.keys(core).map((k) => vi.spyOn(core, k))
    const bad = { ...handle({ rate: RATE }), asset }
    const a = adapter(chain)
    for (const call of [
      () => a.spend({ signer: agent, allowance: bad, amount: 1n, recipient: MERCHANT }),
      () => a.revoke({ signer: principal, allowance: bad }),
      () => a.remaining({ allowance: bad }),
    ]) {
      const err = await call().then(() => null, (e: unknown) => e)
      expect(err).toBeInstanceOf(TypeError)
      expect((err as TypeError).message).toContain("allowance.asset is not a coin type")
    }
    expect(spies.reduce((n, s) => n + s.mock.calls.length, 0)).toBe(0)
    expect(chain.executed).toHaveLength(0)
  })

  it.each(NORMALIZES_BUT_INVALID)("open() with asset %j, which normalizes but is not a valid coin type, throws before sending", async (asset) => {
    const chain = mockChain(null, 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(0), timestampMs: ANCHOR, created: true })
    const err = await adapter(chain)
      .open({ signer: principal, allowance: { network: "sui:testnet", asset, spender: A, limits: { rate: RATE } } })
      .then(() => null, (e: unknown) => e)
    expect(err).toBeInstanceOf(TypeError)
    expect((err as TypeError).message).toContain("is not a Move type")
    expect(chain.executed).toHaveLength(0)
  })

  it("a canonical coin type and an MVR name are not refused as malformed at intake", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    const a = adapter(chain)
    const r = await a.spend({ signer: agent, allowance: { ...handle({ rate: RATE }), asset: "0x2::sui::SUI" }, amount: 1n, recipient: MERCHANT })
    expect(r.refusal).toBeNull()
    expect(chain.executed).toHaveLength(1)
    const mvr = await a.remaining({ allowance: { ...handle({ rate: RATE }), asset: "@org/app::coin::COIN" } }).then(() => null, (e: unknown) => e)
    expect(String((mvr as Error | null)?.message ?? "")).not.toContain("is not a coin type")
    const opened = await adapter(mockChain(null, 0n)).open({ signer: principal, allowance: { network: "sui:testnet", asset: "@org/app::coin::COIN", spender: A, limits: { rate: RATE } } }).then(() => null, (e: unknown) => e)
    expect(String((opened as Error | null)?.message ?? "")).not.toContain("is not a Move type")
  })
})

// ── The security review's also-dos (2026-11-07) ──────────────────────────────

describe("the client must be on the network the adapter names, checked before the first send", () => {
  const spendOne = (chain: MockChain, a = adapter(chain)) =>
    a.spend({ signer: agent, allowance: handle({ rate: RATE }), amount: testUSD.of(1), recipient: MERCHANT })

  it("spend: a mainnet client behind a sui:testnet adapter sends nothing → wrong-network, refused by the library", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    chain.chainIdentifier = MAINNET_GENESIS
    const r = await spendOne(chain)
    expect(chain.executed).toHaveLength(0)
    expect(r).toMatchObject({ verdict: "refused", digest: null })
    expect(r.refusal).toMatchObject({ code: "wrong-network", refusedBy: "library", native: null })
    expect(r.refusal?.why).toContain("connected to sui:mainnet")
  })

  it("open and revoke refuse the same way, and a chain with no known name is named by its genesis", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    chain.chainIdentifier = DIGEST(3)
    const a = adapter(chain)
    const { receipt, allowance } = await a.open({ signer: principal, allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits: { rate: RATE } } })
    expect(allowance).toBeNull()
    expect(receipt.refusal).toMatchObject({ code: "wrong-network", refusedBy: "library" })
    expect(receipt.refusal?.why).toContain(`genesis checkpoint ${DIGEST(3)}`)
    const revoked = await a.revoke({ signer: principal, allowance: handle({ rate: RATE }) })
    expect(revoked.refusal).toMatchObject({ code: "wrong-network", refusedBy: "library" })
    expect(chain.executed).toHaveLength(0)
  })

  it("a failed read refuses without sending, and is asked again on the next send, never cached", async () => {
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    chain.chainIdentifier = new Error("fetch failed: ECONNREFUSED")
    const a = adapter(chain)
    const first = await spendOne(chain, a)
    expect(chain.executed).toHaveLength(0)
    expect(first.refusal).toMatchObject({ code: "not-submitted", refusedBy: "library" })
    expect(first.refusal?.why).toContain("could not confirm")
    chain.chainIdentifier = TESTNET_GENESIS
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: { ...before, rate: windowed(testUSD.of(1), ANCHOR) } })
    const second = await spendOne(chain, a)
    expect(second.verdict).toBe("executed")
  })

  it("a refusal that needs no network never waits on one: local rules are checked before the chain is asked", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    chain.chainIdentifier = new Error("fetch failed: ECONNREFUSED")
    const a = adapter(chain)
    const { receipt } = await a.open({ signer: principal, allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits: { lifetimeCap: 1n } } })
    expect(receipt.refusal).toMatchObject({ code: "unbounded-time", native: { abortName: "ENoExpiration" } })
    const r = await a.spend({ signer: agent, allowance: handle({ rate: RATE, recipients: [MERCHANT] }), amount: 1n, recipient: STRANGER })
    expect(r.refusal).toMatchObject({ code: "recipient-not-allowed" })
  })

  it("remaining() will not answer from the wrong chain, where the allowance would come back not found", async () => {
    const chain = mockChain(null, 0n)
    const a = adapter(chain)
    await expect(a.remaining({ allowance: { ...handle({ rate: RATE }), network: "sui:mainnet" } })).rejects.toThrow(/would come back not found/)
    chain.chainIdentifier = MAINNET_GENESIS
    await expect(a.remaining({ allowance: handle({ rate: RATE }) })).rejects.toThrow(/connected to sui:mainnet/)
  })

  it("devnet has no fixed genesis, so a devnet client is taken at its word", async () => {
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    chain.chainIdentifier = DIGEST(3)
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: { ...before, rate: windowed(testUSD.of(1), ANCHOR) } })
    const a = suiAllowances({ client: chain.client, network: "sui:devnet", scale: testUSD, now: () => LOCAL_NOW })
    const r = await a.spend({ signer: agent, allowance: { ...handle({ rate: RATE }), network: "sui:devnet" }, amount: testUSD.of(1), recipient: MERCHANT })
    expect(r.verdict).toBe("executed")
  })
})

describe("nothing that runs after the chain has moved may throw the receipt away", () => {
  it("an explorer function that throws costs the receipt its link, never the receipt", async () => {
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: { ...before, rate: windowed(testUSD.of(1), ANCHOR) } })
    const a = suiAllowances({ client: chain.client, network: "sui:testnet", scale: testUSD, now: () => LOCAL_NOW, explorer: () => { throw new Error("explorer down") } })
    const r = await a.spend({ signer: agent, allowance: handle({ rate: RATE }), amount: testUSD.of(1), recipient: MERCHANT })
    expect(r).toMatchObject({ verdict: "executed", digest: signedDigest(chain), explorer: null })
  })

  it("an explorer or scale of the wrong shape is refused when the adapter is made, not after a send", () => {
    const chain = mockChain(null, 0n)
    expect(() => suiAllowances({ client: chain.client, network: "sui:testnet", explorer: "https://suiscan.xyz" as never })).toThrow(TypeError)
    expect(() => suiAllowances({ client: chain.client, network: "sui:testnet", scale: { unit: "x" } as never })).toThrow(TypeError)
  })

  it("a bad rate window: open() refuses it as a result (Sui's EBadRateLimit); a handle carrying one throws before anything is sent", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    const a = adapter(chain)
    for (const windowMs of [1.5, 0, Number.NaN]) {
      const { receipt, allowance } = await a.open({ signer: principal, allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits: { rate: { amount: 1n, windowMs } } } })
      expect(allowance).toBeNull()
      expect(receipt.refusal).toMatchObject({ code: "invalid-limit", refusedBy: "library", native: { abortName: "EBadRateLimit", rawAbortCode: null } })
    }
    await expect(a.spend({ signer: agent, allowance: handle({ rate: { amount: 1n, windowMs: 0 } }), amount: 1n, recipient: MERCHANT })).rejects.toThrow(/positive whole number/)
    await expect(a.spend({ signer: agent, allowance: handle({ rate: { amount: 1n, windowMs: Number.NaN } }), amount: 1n, recipient: MERCHANT })).rejects.toThrow(/positive whole number/)
    expect(chain.executed).toHaveLength(0)
  })
})

describe("an SDK that stops consulting resolveTransactionPlugin gets nothing sent", () => {
  it("a build that never asked for the transport's resolver → not-submitted by the library, naming the SDK", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    // Stands in for a future @mysten/sui that resolves without the lookup the bypass relies on.
    const build = vi.spyOn(Transaction.prototype, "build").mockResolvedValueOnce(new Uint8Array([1, 2, 3]))
    const submit = vi.spyOn(chain.client.core, "signAndExecuteTransaction")
    try {
      const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: testUSD.of(1), recipient: MERCHANT })
      expect(submit).not.toHaveBeenCalled()
      expect(r).toMatchObject({ verdict: "refused", digest: null })
      expect(r.refusal).toMatchObject({ code: "not-submitted", refusedBy: "library", native: null })
      expect(r.refusal?.why).toContain("sweetrust-sui stopped before signing")
      expect(r.refusal?.why).toContain("resolveTransactionPlugin")
      expect(r.refusal?.why).not.toContain("The Sui client said")
    } finally {
      build.mockRestore()
      submit.mockRestore()
    }
  })
})

// ── The blind review of the also-dos (2026-11-07) ────────────────────────────

describe("no host-supplied or chain-supplied oddity can lose a receipt after a send", () => {
  it("a host clock that returns a fraction, or throws, still yields the `errored` receipt", async () => {
    for (const now of [() => LOCAL_NOW + 0.5, () => { throw new Error("clock broke") }]) {
      const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, ANCHOR) }), BigInt(ANCHOR + 1000))
      chain.script.push({ kind: "throw", message: "fetch failed: ETIMEDOUT" })
      const a = suiAllowances({ client: chain.client, network: "sui:testnet", scale: testUSD, now })
      const r = await a.spend({ signer: agent, allowance: handle({ rate: RATE }), amount: testUSD.of(10), recipient: MERCHANT })
      expect(r.verdict).toBe("errored")
      expect(r.digest).not.toBeNull()
    }
  })

  it("`now` that is not a function (Date.now() instead of Date.now) is refused when the adapter is made", () => {
    const chain = mockChain(null, 0n)
    expect(() => suiAllowances({ client: chain.client, network: "sui:testnet", now: Date.now() as never })).toThrow(/not Date\.now\(\)/)
  })

  it("open(): an executed transaction whose effects name no allowance is `errored` with its digest, never a throw", async () => {
    const chain = mockChain(null, 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(0), timestampMs: ANCHOR })
    const { receipt, allowance } = await adapter(chain).open({
      signer: principal,
      allowance: { network: "sui:testnet", asset: "0x2::sui::SUI", spender: A, limits: { rate: RATE } },
    })
    expect(allowance).toBeNull()
    expect(receipt).toMatchObject({ verdict: "errored", digest: signedDigest(chain), refusal: null })
    expect(receipt.summary).toContain("SECOND allowance")
  })

  it("the chain check survives a client that answers nothing or throws synchronously, and asks again next time", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    chain.chainIdentifier = undefined as never
    const a = adapter(chain)
    const first = await a.revoke({ signer: principal, allowance: handle({ rate: RATE }) })
    expect(first.refusal).toMatchObject({ code: "not-submitted", refusedBy: "library" })
    expect(first.refusal?.why).toContain("no chain identifier")
    const core = chain.client.core as unknown as { getChainIdentifier: () => unknown }
    const original = core.getChainIdentifier
    core.getChainIdentifier = () => { throw new Error("sync boom") }
    const second = await a.revoke({ signer: principal, allowance: handle({ rate: RATE }) })
    expect(second.refusal).toMatchObject({ code: "not-submitted" })
    expect(second.refusal?.why).toContain("sync boom")
    core.getChainIdentifier = original
    chain.chainIdentifier = MAINNET_GENESIS
    const third = await a.revoke({ signer: principal, allowance: handle({ rate: RATE }) })
    expect(third.refusal).toMatchObject({ code: "wrong-network" })
    expect(chain.executed).toHaveLength(0)
  })

  it("a cap the handle claims but the chain does not hold is shown as unchecked, never as a zero cap Sui checked", async () => {
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: { ...before, currentSpend: testUSD.of(1), rate: windowed(testUSD.of(1), ANCHOR) } })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ lifetimeCap: testUSD.of(100), rate: RATE }), amount: testUSD.of(1), recipient: MERCHANT })
    expect(r.verdict).toBe("executed")
    expect(lineOf(r, "lifetimeCap")).toMatchObject({ value: "none on chain", heldBy: "chain", verdict: "unchecked" })
    expect(lineOf(r, "lifetimeCap").why).toContain("holds no")
    expect(lineOf(r, "lifetimeCap").why).not.toContain("0.00 testUSD cap")
  })
})

// ── authorizedBy: each spend names the verdict that approved it ──────────────

describe("spend(): authorizedBy binds a payment to the verdict that approved it", () => {
  const ASSET = normalizeStructTag("0x2::sui::SUI")
  const VERDICT = "d".repeat(64)
  const AMOUNT = testUSD.of(30)
  const digestOf = (over: Partial<{ network: string; asset: string; recipient: string; amount: bigint }> = {}): string =>
    paymentDigest({ network: "sui:testnet", asset: ASSET, recipient: MERCHANT, amount: AMOUNT, ...over })
  const proof = (over: Partial<Parameters<typeof digestOf>[0]> = {}) => ({ verdictDigest: VERDICT, paymentDigest: digestOf(over) })

  /** A real sink's one-shot token for one payment, the only way to get one. */
  const tokenFor = async (over: { recipient?: string; asset?: string; network?: string; amount?: bigint; verdict?: unknown; noPayment?: boolean } = {}): Promise<SpendAuthorization> => {
    let token: SpendAuthorization | undefined
    const sink = makeSink<any, unknown>({
      name: "pay",
      requires: { to: "verified", amount: "verified" },
      mode: "enforce",
      log: new ReceiptLog(),
      judgment: {
        provider: { name: "j", model: "j@1", assess: async () => ({ assessment: "match", confidence: 0.95, rationale: "ok" }) },
        floor: 0.7,
        granted: { purpose: { statement: "pay" }, grantHash: "a".repeat(64) },
        ...(over.noPayment ? {} : { purposeArgs: { payee: "to", amount: "amount" }, network: over.network ?? "sui:testnet", asset: over.asset ?? ASSET }),
      } as never,
      execute: (_args: unknown, ctx: { authorization: SpendAuthorization } | undefined) => {
        token = ctx?.authorization
        return "issued"
      },
    })
    await sink({ to: Sourced.fromAuthority(over.recipient ?? MERCHANT, "t"), amount: Sourced.fromAuthority(String(over.amount ?? AMOUNT), "t") })
    if (token === undefined) throw new Error("the sink issued no token")
    return token
  }
  const judged = (chain: MockChain, requireAuthorization = true, log?: SignedReceiptLog) =>
    suiAllowances({ client: chain.client, network: "sui:testnet", scale: testUSD, now: () => LOCAL_NOW, confirmTimeoutMs: 0, requireAuthorization, ...(log ? { log } : {}) })
  const live = (): MockChain => mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
  const pay = (chain: MockChain, authorizedBy?: unknown, over: Record<string, unknown> = {}, requireAuthorization = true) =>
    judged(chain, requireAuthorization).spend({
      signer: agent, allowance: handle({ rate: RATE }), amount: AMOUNT, recipient: MERCHANT,
      ...(authorizedBy === undefined ? {} : SpendAuthorization.is(authorizedBy) ? { authorization: authorizedBy } : { authorizedBy }), ...over,
    } as never)

  /** Every read and write the adapter could make on the chain, counted. */
  const watchChain = (chain: MockChain): (() => number) => {
    const core = chain.client.core as unknown as Record<string, (...a: Array<unknown>) => unknown>
    const spies = Object.keys(core).map((k) => vi.spyOn(core, k))
    return () => spies.reduce((n, s) => n + s.mock.calls.length, 0)
  }

  const expectRefused = (r: AllowanceReceipt, chain: MockChain): void => {
    expect(chain.executed).toHaveLength(0)
    expect(r).toMatchObject({ schema: "sweetrust-sui/receipt@2", verb: "spend", verdict: "refused", digest: null, atSource: "local" })
    expect(r.refusal).toMatchObject({ code: "not-authorized", refusedBy: "library", native: null })
    expect(r.refusal?.why).toContain("binds only spends routed through this library")
    expect(r.summary).toBe(r.refusal?.why)
  }

  it("requireAuthorization with no authorizedBy refuses, signs nothing, and says why", async () => {
    const chain = live()
    const r = await pay(chain)
    expectRefused(r, chain)
    expect(r.authorizedBy).toBeNull()
    expect(r.refusal?.why).toContain("Refused in-process; nothing was sent.")
    expect(r.refusal?.why).toContain("named none")
    expect(lineOf(r, "rate")).toMatchObject({ verdict: "unchecked" })
  })

  it("a token for $3 used on a $30 spend refuses, and the receipt quotes both digests and names the token's verdict", async () => {
    const chain = live()
    const wrong = await tokenFor({ amount: testUSD.of(3) })
    const r = await pay(chain, wrong)
    expectRefused(r, chain)
    expect(r.authorizedBy).toEqual(wrong.authorizedBy)
    expect(r.refusal?.why).toContain(wrong.authorizedBy.paymentDigest)
    expect(r.refusal?.why).toContain(digestOf())
    expect(r.refusal?.why).toContain("30.00 testUSD")
    expect(r.refusal?.why).toContain(MERCHANT)
  })

  it.each([
    ["recipient", { recipient: STRANGER }],
    ["asset", { asset: normalizeStructTag("0x2::coin::COIN") }],
    ["network", { network: "sui:mainnet" }],
  ])("a token over a different %s refuses", async (_name, over) => {
    const chain = live()
    expectRefused(await pay(chain, await tokenFor(over)), chain)
  })

  it("a live token for this payment passes the check, the spend executes, and the receipt carries it", async () => {
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: { ...before, currentSpend: AMOUNT, rate: windowed(AMOUNT, ANCHOR) } })
    const token = await tokenFor()
    const r = await pay(chain, token)
    expect(targetsOf(chain.executed[0].bytes)).toEqual(["0x2::allowance::balance_spend", "0x2::coin::from_balance", "TransferObjects"])
    expect(r).toMatchObject({ schema: "sweetrust-sui/receipt@2", verdict: "executed", digest: signedDigest(chain), refusal: null, authorizedBy: token.authorizedBy })
  })

  it("a full-length mixed-case payee is refused and named in its canonical form", async () => {
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    const token = await tokenFor()
    const r = await pay(chain, token, { recipient: `0x${MERCHANT.slice(2).toUpperCase()}` })
    expect(chain.executed).toHaveLength(0)
    expect(r.refusal?.code).toBe("invalid-address")
    expect(r.refusal?.why).toContain(`spell it ${MERCHANT}`)
    // The refusal is local, so the token is still good for the payment it approved.
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: before })
    expect(await pay(chain, token)).toMatchObject({ verdict: "executed", recipient: MERCHANT })
  })

  it("refuses a mixed-case payee with no authorization and no requireAuthorization", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    const r = await pay(chain, undefined, { recipient: `0x${MERCHANT.slice(2).toUpperCase()}` }, false)
    expect(chain.executed).toHaveLength(0)
    expect(r.refusal?.code).toBe("invalid-address")
  })

  it("a short-form payee is refused even when the token's payment matches its padded form", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    const r = await pay(chain, await tokenFor(), { recipient: "0x5E11E5" })
    expect(chain.executed).toHaveLength(0)
    expect(r.refusal?.code).toBe("invalid-address")
  })

  it("a token judged over a non-canonical recipient or asset fails closed", async () => {
    for (const over of [{ recipient: "0x5e11e5" }, { asset: "0x2::sui::SUI" }]) {
      const chain = live()
      expectRefused(await pay(chain, await tokenFor(over)), chain)
    }
  })

  it("a token whose sink named no payment authorizes no payment", async () => {
    const chain = live()
    expectRefused(await pay(chain, await tokenFor({ noPayment: true })), chain)
  })

  it("a forged token is refused: a digest object, the prototype, a Proxy over the class", async () => {
    for (const authorization of [proof(), Object.create(SpendAuthorization.prototype), new Proxy({}, {})]) {
      const chain = live()
      const r = await pay(chain, undefined, { authorization })
      expectRefused(r, chain)
      expect(r.refusal?.why).toContain("no sink issued")
    }
  })

  it("a reused token is refused at spend: the second spend sends nothing", async () => {
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: before })
    const token = await tokenFor()
    expect(await pay(chain, token)).toMatchObject({ verdict: "executed", authorizedBy: token.authorizedBy })
    expect(chain.executed).toHaveLength(1)
    const again = await pay(chain, token)
    expect(again).toMatchObject({ verdict: "refused", digest: null, atSource: "local" })
    expect(again.refusal).toMatchObject({ code: "not-authorized", refusedBy: "library" })
    expect(again.refusal?.why).toContain("already been spent")
    expect(chain.executed).toHaveLength(1)
  })

  it("a token presented without requireAuthorization still spends once, and a forged one is still refused", async () => {
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: before })
    const token = await tokenFor()
    expect(await pay(chain, token, {}, false)).toMatchObject({ verdict: "executed", authorizedBy: token.authorizedBy })
    expect((await pay(chain, token, {}, false)).refusal?.code).toBe("not-authorized")
    expect((await pay(chain, undefined, { authorization: proof() }, false)).refusal?.code).toBe("not-authorized")
    expect(chain.executed).toHaveLength(1)
  })

  it.each([
    ["short", "abc123"],
    ["empty", ""],
    ["uppercase", "D".repeat(64)],
    ["trailing newline", `${"d".repeat(64)}\n`],
    ["one char long", "d".repeat(65)],
    ["not hex", "g".repeat(64)],
  ])("a digest object is not an authorization, whatever its verdictDigest (%s), even beside the right payment digest", async (_name, verdictDigest) => {
    const chain = live()
    const r = await pay(chain, { verdictDigest, paymentDigest: digestOf() })
    expectRefused(r, chain)
    expect(r.authorizedBy).toEqual({ verdictDigest, paymentDigest: digestOf() })
    expect(r.refusal?.why).toContain("presents no authorization")
  })

  it("a null paymentDigest (a sink that named no purposeArgs) or an uppercase one never matches", async () => {
    for (const paymentDigest of [null, digestOf().toUpperCase()]) {
      const chain = live()
      const r = await pay(chain, { verdictDigest: VERDICT, paymentDigest })
      expectRefused(r, chain)
      expect(r.authorizedBy).toEqual({ verdictDigest: VERDICT, paymentDigest })
    }
  })

  it("an amount the digest cannot take is a refusal, and an asset that is not a coin type is rejected at intake", async () => {
    const negative = live()
    expectRefused(await pay(negative, await tokenFor(), { amount: -1n }), negative)
    const badAsset = live()
    await expect(pay(badAsset, await tokenFor(), { allowance: { ...handle({ rate: RATE }), asset: "not a type" } })).rejects.toThrow(/is not a coin type/)
  })

  it("an amount past u256 is `not-authorized` without digesting it, and a genuine token presented with it stays unspent", async () => {
    const U256 = (1n << 256n) - 1n
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    const token = await tokenFor()
    // The last amount never finishes stringifying, so answering at all shows it is never digested.
    for (const amount of [U256 + 1n, -(U256 + 1n), 1n << 1_073_741_000n]) {
      for (const over of [{ amount }, { amount, recipient: "nope" }, { amount, recipient: `0x${MERCHANT.slice(2).toUpperCase()}` }]) {
        const genuine = await pay(chain, token, over)
        expectRefused(genuine, chain)
        expect(genuine).toMatchObject({ amount: null, amountText: null })
        expect(genuine.refusal?.why).toContain("no payment digest")
        expect(JSON.stringify(genuine).length).toBeLessThan(20_000)
        // A forged authorization, with requireAuthorization off: refused as a forgery, never digested either.
        const forged = await pay(chain, undefined, { ...over, authorization: {} }, false)
        expectRefused(forged, chain)
        expect(forged.refusal?.why).toContain("no sink issued")
        expect(forged.refusal?.why).not.toContain("no payment digest")
      }
      // requireAuthorization with none presented stays `not-authorized`, as before.
      expectRefused(await pay(chain, undefined, { amount }), chain)
    }
    // Every refusal above was local, so the token still pays the one payment it approved.
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: { ...before, currentSpend: AMOUNT, rate: windowed(AMOUNT, ANCHOR) } })
    expect(await pay(chain, token)).toMatchObject({ verdict: "executed", authorizedBy: token.authorizedBy })
  })

  it("runs before every other check and before any chain read", async () => {
    const chain = live()
    const calls = watchChain(chain)
    // Each of these would otherwise refuse for its own reason, one of them only after a chain read.
    const onMainnet = await pay(chain, undefined, { allowance: { ...handle({ rate: RATE }), network: "sui:mainnet" } })
    const zero = await pay(chain, undefined, { amount: 0n })
    const badPayee = await pay(chain, undefined, { recipient: "nope" })
    const offList = await pay(chain, undefined, { allowance: handle({ rate: RATE, recipients: [STRANGER] }) })
    const wrong = await pay(chain, await tokenFor({ amount: 1n }))
    for (const r of [onMainnet, zero, badPayee, offList, wrong]) expect(r.refusal?.code).toBe("not-authorized")
    expect(calls()).toBe(0)
  })

  it("passing the check leaves the other refusals in place", async () => {
    const chain = live()
    const token = await tokenFor({ recipient: STRANGER })
    const r = await pay(chain, token, { recipient: STRANGER, allowance: handle({ rate: RATE, recipients: [MERCHANT] }) })
    expect(r.refusal?.code).toBe("recipient-not-allowed")
    expect(r.authorizedBy).toEqual(token.authorizedBy)
  })

  it("every spend receipt carries authorizedBy: chain refusal, build failure, gone, errored", async () => {
    const abort = live()
    abort.script.push({ kind: "abort", digest: DIGEST(2), timestampMs: ANCHOR, abortName: "EExceedsRateLimit", errorCode: 4 })
    const one = await tokenFor()
    const refused = await pay(abort, one)
    expect(refused).toMatchObject({ verdict: "refused", digest: signedDigest(abort), authorizedBy: one.authorizedBy })
    expect(refused.refusal).toMatchObject({ code: "rate-exceeded", refusedBy: "chain" })

    const broken = live()
    broken.breakBuild = true
    const two = await tokenFor()
    const notSubmitted = await pay(broken, two)
    expect(notSubmitted.refusal?.code).toBe("not-submitted")
    expect(notSubmitted.authorizedBy).toEqual(two.authorizedBy)

    const gone = mockChain(null, 0n)
    gone.breakBuild = true
    const three = await tokenFor()
    const goneReceipt = await pay(gone, three)
    expect(goneReceipt.refusal?.code).toBe("allowance-not-found")
    expect(goneReceipt.authorizedBy).toEqual(three.authorizedBy)

    const lost = live()
    lost.script.push({ kind: "throw", message: "fetch failed: ETIMEDOUT" })
    const four = await tokenFor()
    const errored = await pay(lost, four)
    expect(errored.verdict).toBe("errored")
    expect(errored.authorizedBy).toEqual(four.authorizedBy)
  })

  it("without requireAuthorization nothing is checked: none is fine, and one supplied is repeated as given", async () => {
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const none = mockChain(before, 0n)
    none.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: before })
    expect(await pay(none, undefined, {}, false)).toMatchObject({ verdict: "executed", authorizedBy: null })

    const supplied = mockChain(before, 0n)
    supplied.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: before })
    const unchecked = proof({ amount: 1n })
    expect(await pay(supplied, unchecked, {}, false)).toMatchObject({ verdict: "executed", authorizedBy: unchecked })
  })

  it("reads each field once: a getter that changes its answer cannot split the check from the receipt", async () => {
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: before })
    let verdictReads = 0
    let paymentReads = 0
    const shifty = {
      get verdictDigest() { verdictReads += 1; return verdictReads === 1 ? VERDICT : "e".repeat(64) },
      get paymentDigest() { paymentReads += 1; return paymentReads === 1 ? digestOf() : digestOf({ amount: 1n }) },
    }
    let argReads = 0
    const args = {
      signer: agent, allowance: handle({ rate: RATE }), amount: AMOUNT, recipient: MERCHANT,
      get authorizedBy() { argReads += 1; return shifty },
    }
    const r = await judged(chain, false).spend(args as never)
    expect([argReads, verdictReads, paymentReads]).toEqual([1, 1, 1])
    expect(r).toMatchObject({ verdict: "executed", authorizedBy: proof() })
  })

  it("reads the authorization once: a getter cannot show the check one token and the spend another", async () => {
    const before = allowanceState({ funder: P, spender: A, rate: windowed(0n, null) })
    const chain = mockChain(before, 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(1), timestampMs: ANCHOR, after: before })
    const token = await tokenFor()
    let reads = 0
    const args = {
      signer: agent, allowance: handle({ rate: RATE }), amount: AMOUNT, recipient: MERCHANT,
      get authorization() { reads += 1; return token },
    }
    expect(await judged(chain).spend(args as never)).toMatchObject({ verdict: "executed", authorizedBy: token.authorizedBy })
    expect(reads).toBe(1)
  })

  it("the receipt holds its own frozen copy of exactly the two digests; extra keys do not reach it", async () => {
    const chain = live()
    const given = { ...proof({ amount: 1n }), note: "smuggled", amount: 30n }
    const r = await pay(chain, given)
    expectRefused(r, chain)
    expect(Object.keys(r.authorizedBy ?? {})).toEqual(["verdictDigest", "paymentDigest"])
    expect(r.authorizedBy).not.toBe(given)
    expect(Object.isFrozen(r.authorizedBy)).toBe(true)
    expect(Object.isFrozen(given)).toBe(false)
  })

  it.each([
    ["a string", "abc"],
    ["null", null],
    ["an array", []],
    ["a number verdictDigest", { verdictDigest: 1, paymentDigest: "a" }],
    ["no paymentDigest", { verdictDigest: "a".repeat(64) }],
    ["a number paymentDigest", { verdictDigest: "a".repeat(64), paymentDigest: 7 }],
  ])("%s is a programmer error, thrown at intake with or without the option, and nothing is sent", async (_name, bad) => {
    for (const required of [true, false]) {
      const chain = live()
      await expect(pay(chain, bad, {}, required)).rejects.toThrow(TypeError)
      expect(chain.executed).toHaveLength(0)
    }
  })

  it("requireAuthorization must be a boolean: a truthy string cannot pass for the option", () => {
    const chain = live()
    expect(() => suiAllowances({ client: chain.client, network: "sui:testnet", requireAuthorization: "false" as never })).toThrow(TypeError)
  })

  it("open and revoke receipts are receipt@2 with authorizedBy null", async () => {
    const chain = live()
    const a = judged(chain)
    const { receipt: opened } = await a.open({ signer: principal, allowance: { network: "sui:mainnet", asset: "0x2::sui::SUI", spender: A, limits: { rate: RATE } } })
    const revoked = await a.revoke({ signer: principal, allowance: { ...handle({ rate: RATE }), network: "sui:mainnet" } })
    for (const r of [opened, revoked]) expect(r).toMatchObject({ schema: "sweetrust-sui/receipt@2", authorizedBy: null })
  })

  it("the ReceiptLog entry is the receipt@2 with its authorizedBy, refusals included, and the chain still verifies", async () => {
    const signer = makeEd25519ReceiptSigner(generateSigningKeypair())
    const log = new SignedReceiptLog(signer)
    const chain = live()
    const wrong = proof({ amount: 1n })
    const r = await judged(chain, true, log).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: AMOUNT, recipient: MERCHANT, authorizedBy: wrong })
    const [entry] = log.all()
    expect(entry).toMatchObject({ sink: "sweetrust-sui.spend", decision: "refused", reason: r.refusal?.why })
    expect(entry.args.receipt.value).toBe(r)
    expect(entry.args.receipt.value).toMatchObject({ schema: "sweetrust-sui/receipt@2", authorizedBy: wrong })
    expect(verifySignedChain(log.signed(), { trustedSignerPublicKeyHex: signer.publicKeyHex })).toMatchObject({ valid: true, reason: "ok" })
  })
})
