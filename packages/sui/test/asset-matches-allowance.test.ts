/**
 * A handle's coin type must be the one its allowance holds on chain (DAN-1480,
 * DAN-1473 item 1). `spend` passes `funder`, so the SDK skips its own type check,
 * and before this a handle naming another coin built, signed and sent a
 * transaction. The library reads the object and refuses in-process instead.
 */
import { describe, expect, it } from "vitest"
import { ObjectError } from "@mysten/sui/client"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"
import { normalizeStructTag, normalizeSuiAddress } from "@mysten/sui/utils"
import { defineScale, suiAllowances, type AllowanceReceipt, type SuiAllowance } from "../src/index.ts"
import { ALLOWANCE_ID, CAP_ID, DIGEST, allowanceState, mockChain, type MockChain } from "./helpers/mock-chain.ts"

const principal = Ed25519Keypair.generate()
const agent = Ed25519Keypair.generate()
const P = principal.toSuiAddress()
const A = agent.toSuiAddress()
const MERCHANT = normalizeSuiAddress("0x5e11e5")
const SUI = normalizeStructTag("0x2::sui::SUI")
const testUSD = defineScale({ unit: "testUSD", baseUnitsPerUnit: 100_000n, decimals: 2, coinType: "0x2::sui::SUI" })
const ANCHOR = Date.parse("2026-11-06T18:02:00Z")

/** A live SUI allowance; the mock serves its type in short form, `0x2::allowance::Allowance<0x2::balance::Balance<0x2::sui::SUI>>`. */
const live = (): MockChain => mockChain(allowanceState({ funder: P, spender: A, lifetimeCap: 1000n }), BigInt(ANCHOR))
const adapter = (chain: MockChain) => suiAllowances({ client: chain.client, network: "sui:testnet", scale: testUSD, now: () => ANCHOR })
const handle = (asset: string): SuiAllowance => ({ network: "sui:testnet", asset, allowanceId: ALLOWANCE_ID, capId: CAP_ID, funder: P, spender: A, limits: { lifetimeCap: 1000n } })
const pay = (chain: MockChain, asset: string, amount = 5n) => adapter(chain).spend({ signer: agent, allowance: handle(asset), amount, recipient: MERCHANT })
const revoke = (chain: MockChain, asset: string) => adapter(chain).revoke({ signer: principal, allowance: handle(asset) })

type GetObjects = (a: { objectIds: Array<string> }) => Promise<{ objects: Array<unknown> }>
/** Replace the fullnode's answer for the allowance only; every other read (the clock, the build's) is the mock's. */
const answerForAllowance = (chain: MockChain, answer: (real: () => Promise<{ objects: Array<unknown> }>) => Promise<{ objects: Array<unknown> }>): void => {
  const core = chain.client.core as unknown as { getObjects: GetObjects }
  const real = core.getObjects.bind(core)
  core.getObjects = async (a) => (a.objectIds.some((id) => normalizeSuiAddress(id) === ALLOWANCE_ID) ? answer(() => real(a)) : real(a))
}
/** The allowance object as the mock serves it, with its type replaced. */
const typed = (type: string) => async (real: () => Promise<{ objects: Array<unknown> }>) => {
  const { objects } = await real()
  return { objects: objects.map((o) => (o instanceof Error ? o : { ...(o as object), type })) }
}

const refusedInProcess = (r: AllowanceReceipt, chain: MockChain, code: string): void => {
  expect(chain.executed).toHaveLength(0)
  expect(r).toMatchObject({ verdict: "refused", digest: null })
  expect(r.refusal).toMatchObject({ code, refusedBy: "library", native: null })
  expect(r.summary).toBe(r.refusal?.why)
}

describe("a handle naming another coin than its allowance holds is refused before anything is built", () => {
  for (const asset of ["0x3::evil::EVIL", "0x2::coin::COIN"]) {
    it(`spend with ${asset} on a SUI allowance → asset-mismatch, nothing sent`, async () => {
      const chain = live()
      const r = await pay(chain, asset)
      refusedInProcess(r, chain, "asset-mismatch")
      expect(r.refusal?.why).toContain(`names the coin type ${normalizeStructTag(asset)}`)
      expect(r.refusal?.why).toContain(`allowance ${ALLOWANCE_ID} on sui:testnet holds ${SUI}.`)
      expect(r.limits.map((l) => l.verdict)).toEqual(["unchecked"])
    })

    it(`revoke with ${asset} on a SUI allowance → asset-mismatch, the revoke did NOT run`, async () => {
      const chain = live()
      const r = await revoke(chain, asset)
      refusedInProcess(r, chain, "asset-mismatch")
      expect(r.refusal?.why).toContain(`names the coin type ${normalizeStructTag(asset)}`)
      expect(r.refusal?.why).toContain(`holds ${SUI}.`)
      expect(r.summary).toContain("it did NOT run")
      expect(r.summary).not.toMatch(/already revoked/i)
    })
  }

  it("the spend refusal, word for word", async () => {
    const r = await pay(live(), "0x3::evil::EVIL")
    expect(r.refusal?.why).toBe(
      "Refused in-process; nothing was sent to Sui, so nothing was spent. " +
        `The handle passed to spend() names the coin type ${normalizeStructTag("0x3::evil::EVIL")}, but allowance ${ALLOWANCE_ID} on sui:testnet holds ${SUI}. ` +
        "A transaction under the handle's coin type would fail on chain after gas was spent, and its receipt would name a coin that never moved.",
    )
  })

  it("an object that is not an allowance at all is refused, and the refusal says so", async () => {
    for (const verb of ["spend", "revoke"] as const) {
      const chain = live()
      answerForAllowance(chain, typed("0x2::clock::Clock"))
      const r = verb === "spend" ? await pay(chain, "0x2::sui::SUI") : await revoke(chain, "0x2::sui::SUI")
      refusedInProcess(r, chain, "asset-mismatch")
      expect(r.refusal?.why).toContain(`is an object of type "0x2::clock::Clock", not an allowance over a coin's Balance`)
    }
  })

  it("a fullnode's oversized type is never parsed whole: refused as a mismatch, quoted short", async () => {
    const chain = live()
    const huge = "0x2::a::B<".repeat(60_000) + "u8" + ">".repeat(60_000)
    answerForAllowance(chain, typed(huge))
    const started = performance.now()
    const r = await pay(chain, "0x2::sui::SUI")
    expect(performance.now() - started).toBeLessThan(2000)
    refusedInProcess(r, chain, "asset-mismatch")
    expect(r.refusal!.why.length).toBeLessThan(1000)
  })

  it("an asset nested inside an MVR-free generic is compared too, and only its own allowance matches", async () => {
    const asset = "0x7::wrap::W<0x2::sui::SUI>"
    const chain = live()
    const r = await pay(chain, asset)
    refusedInProcess(r, chain, "asset-mismatch")
    expect(r.refusal?.why).toContain(`holds ${SUI}.`)
  })

  it("local rules still come first: an invalid amount with a mismatched coin is `invalid-amount`, and the allowance is not read", async () => {
    const chain = live()
    let reads = 0
    answerForAllowance(chain, (real) => { reads++; return real() })
    const r = await pay(chain, "0x3::evil::EVIL", 0n)
    expect(r.refusal?.code).toBe("invalid-amount")
    expect(reads).toBe(0)
  })
})

describe("a handle whose coin matches still reaches the chain", () => {
  it("spend: the short form and the long form of SUI both pay against the mock's short-form type", async () => {
    for (const asset of ["0x2::sui::SUI", SUI]) {
      const chain = live()
      chain.script.push({ kind: "executed", digest: DIGEST(0), timestampMs: ANCHOR, after: allowanceState({ funder: P, spender: A, lifetimeCap: 1000n, currentSpend: 5n }) })
      const r = await pay(chain, asset)
      expect(chain.executed).toHaveLength(1)
      expect(r).toMatchObject({ verdict: "executed", refusal: null })
    }
  })

  it("a coin type that is valid at intake but long once normalized still matches its own allowance (code review)", async () => {
    // ~1 KB as written, ~7 KB normalized: every 0x2 is written out to 64 hex digits.
    const asset = `0x2::m::T<${Array(100).fill("0x2::a::B").join(",")}>`
    expect(asset.length).toBeLessThanOrEqual(1024)
    const wrapper = normalizeStructTag(`0x2::allowance::Allowance<0x2::balance::Balance<${asset}>>`)
    expect(wrapper.length).toBeGreaterThan(4 * 1024)
    for (const served of [wrapper, `0x2::allowance::Allowance<0x2::balance::Balance<${asset}>>`]) {
      const chain = live()
      answerForAllowance(chain, typed(served))
      chain.script.push({ kind: "executed", digest: DIGEST(0), timestampMs: ANCHOR, after: allowanceState({ funder: P, spender: A, lifetimeCap: 1000n, currentSpend: 5n }) })
      const r = await pay(chain, asset)
      expect(r.refusal).toBeNull()
      expect(chain.executed).toHaveLength(1)
    }
  })

  it("spend: a fullnode that answers in the long form matches too", async () => {
    const chain = live()
    answerForAllowance(chain, typed(normalizeStructTag("0x2::allowance::Allowance<0x2::balance::Balance<0x2::sui::SUI>>")))
    chain.script.push({ kind: "executed", digest: DIGEST(0), timestampMs: ANCHOR, after: allowanceState({ funder: P, spender: A, lifetimeCap: 1000n, currentSpend: 5n }) })
    const r = await pay(chain, "0x2::sui::SUI")
    expect(chain.executed).toHaveLength(1)
    expect(r).toMatchObject({ verdict: "executed", refusal: null })
  })

  it("revoke: a matching revoke executes", async () => {
    const chain = live()
    chain.script.push({ kind: "executed", digest: DIGEST(3), timestampMs: ANCHOR, after: null })
    const r = await revoke(chain, "0x2::sui::SUI")
    expect(chain.executed).toHaveLength(1)
    expect(r).toMatchObject({ verb: "revoke", verdict: "executed", refusal: null })
  })
})

describe("an allowance whose type cannot be read never leads to a send", () => {
  const unreadable: Array<[string, (real: () => Promise<{ objects: Array<unknown> }>) => Promise<{ objects: Array<unknown> }>]> = [
    ["a read that throws", async () => { throw new Error("rpc down") }],
    ["an empty answer", async () => ({ objects: [] })],
    ["an ObjectError that is not absence", async () => ({ objects: [new ObjectError("unavailable", "try later", { reason: "unknown" })] })],
  ]
  // Each takes the read's full retry budget (~2.8 s), so revoke runs the first kind only.
  for (const [what, answer] of unreadable) {
    for (const verb of what === "a read that throws" ? ["spend", "revoke"] as const : ["spend"] as const) {
      it(`${verb}: ${what} → not-submitted, nothing sent`, async () => {
        const chain = live()
        answerForAllowance(chain, answer)
        const r = verb === "spend" ? await pay(chain, "0x2::sui::SUI") : await revoke(chain, "0x2::sui::SUI")
        refusedInProcess(r, chain, "not-submitted")
        expect(r.refusal?.why).toContain(`could not read allowance ${ALLOWANCE_ID} on sui:testnet to confirm that it holds ${SUI}`)
      }, 10_000)
    }
  }

  it("the check's own read failing is enough: a build whose read would succeed sends nothing", async () => {
    // The SDK's build reads the object too (with no `include`), so a node that fails every read is
    // caught twice. This one fails only the check's read (`include: { content: true }`), as a flaky
    // or load-balanced node can, so only the library's fail-closed branch stands between it and a send.
    for (const verb of ["spend", "revoke"] as const) {
      const chain = live()
      chain.script.push({ kind: "executed", digest: DIGEST(0), timestampMs: ANCHOR, after: verb === "spend" ? allowanceState({ funder: P, spender: A, lifetimeCap: 1000n, currentSpend: 5n }) : null })
      const core = chain.client.core as unknown as { getObjects: (a: { objectIds: Array<string>; include?: { content?: boolean } }) => Promise<unknown> }
      const real = core.getObjects.bind(core)
      core.getObjects = async (a) => (a.include?.content === true && a.objectIds.includes(ALLOWANCE_ID) ? { objects: [] } : real(a))
      const r = verb === "spend" ? await pay(chain, "0x2::sui::SUI") : await revoke(chain, "0x2::sui::SUI")
      refusedInProcess(r, chain, "not-submitted")
    }
  }, 10_000)

  it("a missing allowance keeps the not-found wording, and is never read as revoked", async () => {
    for (const verb of ["spend", "revoke"] as const) {
      const chain = mockChain(null, 0n)
      const r = verb === "spend" ? await pay(chain, "0x2::sui::SUI") : await revoke(chain, "0x2::sui::SUI")
      refusedInProcess(r, chain, "allowance-not-found")
      expect(r.refusal?.why).toContain(`Allowance ${ALLOWANCE_ID} was not found on sui:testnet after 3 reads`)
      expect(`${r.summary} ${r.limits.map((l) => l.why).join(" ")}`).not.toMatch(/revoked/i)
    }
  }, 10_000)

  it("an allowance gone between the check and the build still refuses as not found (the post-build branch)", async () => {
    for (const verb of ["spend", "revoke"] as const) {
      const chain = live()
      chain.breakBuild = true
      let reads = 0
      answerForAllowance(chain, async (real) => (++reads === 1 ? real() : { objects: [new ObjectError("notFound", "not found", { reason: "notFound" })] }))
      const r = verb === "spend" ? await pay(chain, "0x2::sui::SUI") : await revoke(chain, "0x2::sui::SUI")
      refusedInProcess(r, chain, "allowance-not-found")
      // The post-build branch: the build failed, then the read found nothing.
      expect(r.refusal?.why).toContain("breakBuild")
      expect(r.refusal?.why).toContain(`Allowance ${ALLOWANCE_ID} was not found`)
    }
  }, 10_000)
})

describe("an MVR-named coin skips the comparison and keeps its earlier behavior (DAN-1473 item 2)", () => {
  it("spend and revoke with @org/app::coin::COIN are never refused as asset-mismatch", async () => {
    for (const verb of ["spend", "revoke"] as const) {
      const chain = live()
      let typeReads = 0
      answerForAllowance(chain, (real) => { typeReads++; return real() })
      const r = verb === "spend" ? await pay(chain, "@org/app::coin::COIN") : await revoke(chain, "@org/app::coin::COIN")
      expect(r.refusal?.code).not.toBe("asset-mismatch")
      expect(chain.executed).toHaveLength(0)
      // No read before the build: the only reads are the not-sent branch's own, after the build failed.
      expect(r.refusal?.why).toContain("could not be built or signed")
      expect(typeReads).toBeLessThanOrEqual(1)
    }
  })
})
