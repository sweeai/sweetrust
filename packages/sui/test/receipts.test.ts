/**
 * Receipts: shape and WHY text for every verdict, against a mocked fullnode.
 *
 * The bar (Danny, 2026-11-06): "be very communicative on the receipt about WHY
 * SweeTrust judged something outside a limit." So the refusal texts are pinned
 * here word for word where the numbers decide them, and by their load-bearing
 * phrases elsewhere.
 */
import { describe, expect, it } from "vitest"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"
import { normalizeSuiAddress } from "@mysten/sui/utils"
import { SignedReceiptLog, generateSigningKeypair, makeEd25519ReceiptSigner, verifySignedChain } from "sweetrust/verify"
import { defineScale, enforces, suiAllowances, type AllowanceReceipt, type SuiAllowance } from "../src/index.ts"
import { ALLOWANCE_ID, CAP_ID, DIGEST, allowanceState, mockChain, targetsOf, type MockChain } from "./helpers/mock-chain.ts"

const principal = Ed25519Keypair.generate()
const agent = Ed25519Keypair.generate()
const P = principal.toSuiAddress()
const A = agent.toSuiAddress()
const MERCHANT = normalizeSuiAddress("0x5e11e5")
const STRANGER = normalizeSuiAddress("0xbad")

/** Basecamp's scale: 1 cent = 1,000 MIST, so 1.00 testUSD = 100,000 MIST. */
const testUSD = defineScale({ unit: "testUSD", baseUnitsPerUnit: 100_000n, decimals: 2 })
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
    expect(receipt).toMatchObject({ schema: "sweetrust-sui/receipt@1", verb: "open", verdict: "refused", network: "sui:testnet", digest: null, allowanceId: null, explorer: null, atSource: "local", at: "2026-11-06T17:00:00.000Z" })
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
      verb: "open", verdict: "executed", digest: DIGEST(0), allowanceId: ALLOWANCE_ID, at: "2026-11-06T18:00:00.000Z", atSource: "chain",
      explorer: `https://suiscan.xyz/testnet/tx/${DIGEST(0)}`, refusal: null,
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
    expect(r).toMatchObject({ verb: "spend", verdict: "executed", digest: DIGEST(1), amount: "2400000", amountText: "24.00 testUSD", recipient: MERCHANT, refusal: null, atSource: "chain" })
    expect(lineOf(r, "lifetimeCap")).toMatchObject({ heldBy: "chain", verdict: "within", why: "Sui checked it: 24.00 testUSD of the 100.00 testUSD cap is now spent, 76.00 testUSD left." })
    expect(lineOf(r, "rate").why).toBe(
      "Sui checked it: the current window now holds 24.00 testUSD of 30.00 testUSD. " +
      "This spend opened the first window (Sui anchors windows at the first charge, 2026-11-06 18:02:00 UTC). The window resets at 2026-11-07 18:02:00 UTC.")
    expect(lineOf(r, "recipients")).toMatchObject({ heldBy: "library", verdict: "within" })
    expect(lineOf(r, "recipients").why).toContain("was checked against the allowed list before sending")
    expect(r.summary).toBe(`Sent 24.00 testUSD to ${MERCHANT} under allowance ${ALLOWANCE_ID} on sui:testnet (tx ${DIGEST(1)}).`)
  })
})

describe("spend(): refused by Sui validators, a result with a digest", () => {
  it("EExceedsRateLimit: the WHY gives the window's numbers and its fixed bounds", async () => {
    const state = allowanceState({ funder: P, spender: A, lifetimeCap: testUSD.of(100), currentSpend: testUSD.of(24), rate: windowed(testUSD.of(24), ANCHOR) })
    const chain = mockChain(state, 0n)
    chain.script.push({ kind: "abort", digest: DIGEST(2), timestampMs: T("2026-11-06T19:00:00Z"), abortName: "EExceedsRateLimit", errorCode: 4 })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ lifetimeCap: testUSD.of(100), rate: RATE, recipients: [MERCHANT] }), amount: testUSD.of(10), recipient: MERCHANT })
    expect(chain.simulated).toHaveLength(0)
    expect(r).toMatchObject({ verdict: "refused", digest: DIGEST(2), explorer: `https://suiscan.xyz/testnet/tx/${DIGEST(2)}`, at: "2026-11-06T19:00:00.000Z", atSource: "chain" })
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
  it("a revoked allowance is `allowance-gone`, with no digest", async () => {
    const chain = mockChain(null, 0n)
    chain.script.push({ kind: "throw", message: "The following input objects are invalid: deleted" })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: 1n, recipient: MERCHANT })
    expect(r).toMatchObject({ verdict: "refused", digest: null })
    expect(r.refusal).toMatchObject({ code: "allowance-gone", refusedBy: "chain", native: null })
    expect(r.refusal?.why).toContain(`allowance ${ALLOWANCE_ID} no longer exists on sui:testnet`)
  })
})

// ── revoke() ─────────────────────────────────────────────────────────────────

describe("revoke()", () => {
  it("consumes the AllowanceCap and marks every limit revoked", async () => {
    const chain = mockChain(allowanceState({ funder: P, spender: A, rate: windowed(0n, null) }), 0n)
    chain.script.push({ kind: "executed", digest: DIGEST(3), timestampMs: ANCHOR, after: null })
    const r = await adapter(chain).revoke({ signer: principal, allowance: handle({ rate: RATE, recipients: [MERCHANT] }) })
    expect(targetsOf(chain.executed[0].bytes)).toEqual(["0x2::allowance::revoke"])
    expect(r).toMatchObject({ verb: "revoke", verdict: "executed", digest: DIGEST(3), refusal: null })
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
    expect(all[0].args.receipt.provenance).toBe(`sweetrust-sui on sui:testnet, tx ${DIGEST(2)}`)
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

  it("spend: the response is lost and the allowance is gone → `allowance-gone`, because a spend cannot execute against a deleted object", async () => {
    const chain = mockChain(null, 0n)
    chain.script.push({ kind: "throw", message: "The following input objects are invalid: deleted" })
    const r = await adapter(chain).spend({ signer: agent, allowance: handle({ rate: RATE }), amount: 1n, recipient: MERCHANT })
    expect(r).toMatchObject({ verdict: "refused", digest: null })
    expect(r.refusal).toMatchObject({ code: "allowance-gone", refusedBy: "chain" })
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
})
