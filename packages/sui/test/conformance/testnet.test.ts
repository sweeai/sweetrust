/**
 * Testnet conformance (ADR 0003): every limit `enforces` labels `chain` is
 * refused by Sui itself, in a transaction with a digest, abort code quoted.
 *
 * Runs only with funded testnet keys:
 *
 *   SWEETRUST_SUI_TESTNET_KEYS=/path/to/keys.json pnpm -C packages/sui test:testnet
 *
 * keys.json holds three Sui secret keys (`suiprivkey…`): `principal` (the
 * funder; needs SUI in its ADDRESS BALANCE, which allowances draw from, plus
 * gas), `agent` (the spender; needs gas) and `merchant` (only its address is
 * used). The keys are read by path and never copied into this tree.
 *
 * Add SWEETRUST_SUI_RECORD=1 to rewrite test/conformance/testnet-digests.json
 * with this run's digests. Each refusal is also re-read from the chain, by
 * digest, independently of the adapter's own receipt.
 */
import { readFileSync, writeFileSync } from "node:fs"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import { SuiGrpcClient } from "@mysten/sui/grpc"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"
import { SUI_ALLOWANCE_ABORTS, enforces, suiAllowances, type AllowanceReceipt, type LimitName, type SuiAllowance, type SuiAllowances } from "../../src/index.ts"

const KEYS = process.env.SWEETRUST_SUI_TESTNET_KEYS
const RECORD = process.env.SWEETRUST_SUI_RECORD === "1"
const FIXTURE = new URL("./testnet-digests.json", import.meta.url)
const DAY = 86_400_000
const ASSET = "0x2::sui::SUI"

if (!KEYS) {
  console.warn([
    "",
    "⚠️  ─────────────────────────────────────────────────────────────────────────",
    "⚠️  sweetrust-sui TESTNET CONFORMANCE SKIPPED: SWEETRUST_SUI_TESTNET_KEYS is not set.",
    "⚠️  Nothing about the chain was checked in this run. The unit tests ran against",
    "⚠️  a mocked fullnode; the recorded refusals in test/conformance/testnet-digests.json",
    "⚠️  are from the last real run. To run it: SWEETRUST_SUI_TESTNET_KEYS=/path/keys.json",
    "⚠️  ─────────────────────────────────────────────────────────────────────────",
    "",
  ].join("\n"))
}

type Case = { limit: LimitName; abortName: string; receipt: AllowanceReceipt; allowanceId: string }

describe.skipIf(!KEYS)("testnet conformance: Sui refuses every limit labeled `chain`", { timeout: 240_000 }, () => {
  const recorded: Array<Case> = []
  let client: SuiGrpcClient
  let sui: SuiAllowances
  let principal: Ed25519Keypair
  let agent: Ed25519Keypair
  let merchant: string

  beforeAll(async () => {
    const keys = JSON.parse(readFileSync(KEYS as string, "utf8")) as Record<string, string>
    principal = Ed25519Keypair.fromSecretKey(keys.principal)
    agent = Ed25519Keypair.fromSecretKey(keys.agent)
    merchant = Ed25519Keypair.fromSecretKey(keys.merchant).toSuiAddress()
    client = new SuiGrpcClient({ network: "testnet", baseUrl: "https://fullnode.testnet.sui.io:443" })
    sui = suiAllowances({ client, network: "sui:testnet" })
    const funder = await client.getBalance({ owner: principal.toSuiAddress() })
    const spender = await client.getBalance({ owner: agent.toSuiAddress() })
    if (BigInt(funder.balance.addressBalance) < 5_000_000n || BigInt(spender.balance.balance) < 20_000_000n) {
      throw new Error(
        `testnet conformance needs a funded principal address balance (has ${funder.balance.addressBalance} MIST, wants 5,000,000) ` +
        `and agent gas (has ${spender.balance.balance} MIST, wants 20,000,000). Fund them from the testnet faucet.`,
      )
    }
  })

  const open = async (limits: SuiAllowance["limits"], name: string): Promise<SuiAllowance> => {
    const { receipt, allowance } = await sui.open({ signer: principal, allowance: { network: "sui:testnet", asset: ASSET, spender: agent.toSuiAddress(), limits }, name })
    expect(receipt.verdict, receipt.summary).toBe("executed")
    expect(allowance).not.toBeNull()
    return allowance as SuiAllowance
  }

  /** Re-read the refusal from the chain by digest: the stranger's check, not the adapter's word. */
  const onChain = async (digest: string) => {
    const res = await client.core.waitForTransaction({ digest, include: { effects: true } })
    const tx = res.Transaction ?? res.FailedTransaction
    return { success: tx?.status.success, error: tx?.status.error }
  }

  const expectChainRefusal = async (limit: LimitName, abortName: string, r: AllowanceReceipt, allowanceId: string) => {
    expect(r.verdict, r.summary).toBe("refused")
    expect(r.digest).toMatch(/^[1-9A-HJ-NP-Za-km-z]{43,44}$/)
    expect(r.refusal).toMatchObject({ refusedBy: "chain", native: { module: "0x2::allowance", abortName, abortCode: SUI_ALLOWANCE_ABORTS[abortName] } })
    expect(r.refusal?.why).toContain(`Refused by Sui validators (allowance::${abortName})`)
    expect(r.limits.find((l) => l.limit === limit)).toMatchObject({ heldBy: "chain", verdict: "outside" })
    const seen = await onChain(r.digest as string)
    expect(seen.success).toBe(false)
    expect(seen.error).toMatchObject({ $kind: "MoveAbort", MoveAbort: { cleverError: { constantName: abortName } } })
    recorded.push({ limit, abortName, receipt: r, allowanceId })
    console.log(`  ${limit}: ${abortName} → ${r.explorer}\n    ${r.refusal?.why}`)
  }

  it("lifetimeCap: a spend past the cap aborts with EExceedsLifetimeCap", async () => {
    const a = await open({ lifetimeCap: 1_000n, expiry: new Date(Date.now() + 3_600_000) }, "sweetrust-sui conformance: lifetime cap")
    const ok = await sui.spend({ signer: agent, allowance: a, amount: 600n, recipient: merchant })
    expect(ok.verdict, ok.summary).toBe("executed")
    const no = await sui.spend({ signer: agent, allowance: a, amount: 600n, recipient: merchant })
    await expectChainRefusal("lifetimeCap", "EExceedsLifetimeCap", no, a.allowanceId)
    expect((await sui.revoke({ signer: principal, allowance: a })).verdict).toBe("executed")
  })

  it("rate: a spend past the window aborts with EExceedsRateLimit", async () => {
    const a = await open({ rate: { amount: 1_000n, windowMs: DAY } }, "sweetrust-sui conformance: rate")
    const ok = await sui.spend({ signer: agent, allowance: a, amount: 800n, recipient: merchant })
    expect(ok.verdict, ok.summary).toBe("executed")
    const no = await sui.spend({ signer: agent, allowance: a, amount: 300n, recipient: merchant })
    await expectChainRefusal("rate", "EExceedsRateLimit", no, a.allowanceId)
    expect((await sui.revoke({ signer: principal, allowance: a })).verdict).toBe("executed")
  })

  it("start: a spend before the start aborts with ENotStarted", async () => {
    const start = Date.now() + DAY
    const a = await open({ lifetimeCap: 1_000n, start: new Date(start), expiry: new Date(start + DAY) }, "sweetrust-sui conformance: start")
    const no = await sui.spend({ signer: agent, allowance: a, amount: 100n, recipient: merchant })
    await expectChainRefusal("start", "ENotStarted", no, a.allowanceId)
    expect((await sui.revoke({ signer: principal, allowance: a })).verdict).toBe("executed")
  })

  it("expiry: a spend after the expiry aborts with EExpired", async () => {
    const a = await open({ lifetimeCap: 1_000n, expiry: new Date(Date.now() + 25_000) }, "sweetrust-sui conformance: expiry")
    // Wait on the CHAIN's clock, not this machine's: remaining() reads 0x6.
    for (let i = 0; i < 40 && (await sui.remaining({ allowance: a })).active !== false; i++) await new Promise((r) => setTimeout(r, 3_000))
    const no = await sui.spend({ signer: agent, allowance: a, amount: 100n, recipient: merchant })
    await expectChainRefusal("expiry", "EExpired", no, a.allowanceId)
    expect((await sui.revoke({ signer: principal, allowance: a })).verdict).toBe("executed")
  })

  afterAll(() => {
    const chainHeld = (Object.keys(enforces) as Array<LimitName>).filter((l) => enforces[l] === "chain")
    if (!RECORD) return
    if (recorded.length !== chainHeld.length) {
      console.warn(`⚠️  not rewriting ${FIXTURE.pathname}: ${recorded.length} of ${chainHeld.length} refusals recorded`)
      return
    }
    const fixture = {
      what: "One recorded Sui refusal per limit sweetrust-sui labels `chain`. Each digest is a failed testnet transaction whose effects carry the quoted 0x2::allowance abort. Re-check: open the explorer link, or fetch the digest from any testnet fullnode.",
      network: "sui:testnet",
      recordedAt: new Date().toISOString(),
      sdk: "@mysten/sui 2.35.0",
      cases: chainHeld.map((limit) => {
        const c = recorded.find((x) => x.limit === limit) as Case
        return {
          limit,
          date: c.receipt.at,
          digest: c.receipt.digest,
          explorer: c.receipt.explorer,
          allowanceId: c.allowanceId,
          abort: c.receipt.refusal?.native,
          why: c.receipt.refusal?.why,
        }
      }),
    }
    writeFileSync(FIXTURE, `${JSON.stringify(fixture, null, 2)}\n`)
    console.log(`recorded ${recorded.length} refusals → ${FIXTURE.pathname}`)
  })
})
