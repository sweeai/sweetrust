/**
 * One judged payment, end to end, on Sui testnet (spec § 6, D3).
 *
 *   SWEETRUST_SUI_TESTNET_KEYS=/path/keys.json \
 *     node --experimental-strip-types --no-warnings packages/sui/scripts/intent-e2e.ts
 *
 * A mandate carries the owner's purpose. A judged sink decides the payment. The
 * mandate's invoke event, the gate receipt and receipt@2 each record the verdict
 * digest. `reconcile` then compares those records with what the chain's indexer
 * says moved. The record is written only when all of it agrees, to
 * `test/conformance/intent-e2e.json`.
 *
 * The judge here is `mockJudgmentProvider`. This run proves the plumbing, not a
 * judge's quality. Keys are read by path and never printed; digests are public.
 */
import { readFileSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { SuiGrpcClient } from "@mysten/sui/grpc"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"
import { normalizeStructTag } from "@mysten/sui/utils"
import { makeSink, mockJudgmentProvider, ReceiptLog, Sourced, verdictDigest } from "sweetrust/gate"
import { createTrust, defineCapability, makeInMemoryAuditLive, type GrantorId } from "sweetrust/mandate"
import { reconcile } from "sweetrust/verify"
import { chainSpends, suiAllowances } from "../src/index.ts"

const NETWORK = "sui:testnet" as const
/** Hashed as written, so the gate and the adapter must both hold the normalized form. */
const ASSET = normalizeStructTag("0x2::sui::SUI")
const AMOUNT = 1n
const INDEXER_WAIT_MS = 120_000
const OUT = join(dirname(fileURLToPath(import.meta.url)), "../test/conformance/intent-e2e.json")

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const must = (ok: unknown, what: string): void => {
  if (!ok) throw new Error(`intent-e2e: ${what}`)
}

const keysPath = process.env.SWEETRUST_SUI_TESTNET_KEYS
must(keysPath, "SWEETRUST_SUI_TESTNET_KEYS is not set")
const keys = JSON.parse(readFileSync(keysPath as string, "utf8")) as Record<string, string>
const principal = Ed25519Keypair.fromSecretKey(keys.principal as string)
const agent = Ed25519Keypair.fromSecretKey(keys.agent as string)
const merchant = Ed25519Keypair.fromSecretKey(keys.merchant as string).toSuiAddress()

const client = new SuiGrpcClient({ network: "testnet", baseUrl: "https://fullnode.testnet.sui.io:443" })
const sui = suiAllowances({ client, network: NETWORK, requireAuthorization: true })

// The owner's purpose, on the mandate's grant.
const Pay = defineCapability("pay")
const trust = createTrust({ store: makeInMemoryAuditLive() })
const mandate = trust.issueOrgMandate({
  grantor: "owner" as GrantorId,
  capabilities: [Pay] as const,
  rationale: "intent-e2e: one judged testnet payment",
  purpose: { statement: "Pay the research API merchant on testnet", fields: { payees: [merchant], maxPerAction: "1000" } },
})

const opened = await sui.open({
  signer: principal,
  allowance: { network: NETWORK, asset: ASSET, spender: agent.toSuiAddress(), limits: { lifetimeCap: 1_000n, expiry: new Date(Date.now() + 3_600_000) } },
  name: "sweetrust-sui intent e2e",
})
must(opened.receipt.verdict === "executed" && opened.allowance, `open failed: ${opened.receipt.summary}`)
const allowance = opened.allowance as NonNullable<typeof opened.allowance>

try {
  const log = new ReceiptLog()
  const pay = makeSink<{ to: Sourced<string>; amount: Sourced<string> }, Promise<Awaited<ReturnType<typeof sui.spend>>>>({
    name: "pay",
    requires: { to: "verified", amount: "verified" },
    mode: "enforce",
    log,
    judgment: {
      provider: mockJudgmentProvider({ intendedPayees: new Set([merchant]), maxAmount: 1_000 }),
      floor: 0.7,
      granted: trust.grantedPurpose(mandate),
      purposeArgs: { payee: "to", amount: "amount" },
      network: NETWORK,
      asset: ASSET,
    },
    execute: async (args, context) => {
      must(context, "a judged sink must pass authorizedBy and an authorization to execute")
      const { authorizedBy } = context as NonNullable<typeof context>
      trust.useCapability({ mandate, capability: Pay, verdictDigest: authorizedBy.verdictDigest })
      return sui.spend({ signer: agent, allowance, amount: BigInt(args.amount.value), recipient: args.to.value, authorization: (context as NonNullable<typeof context>).authorization })
    },
  })

  const judged = await pay({ to: Sourced.fromAuthority(merchant, "owner"), amount: Sourced.fromAuthority(AMOUNT.toString(), "owner") })
  must(judged.ok, `the sink did not execute: ${judged.ok ? "" : judged.refusal}`)
  if (!judged.ok) throw new Error("unreachable")
  const spend = judged.result
  must(spend.verdict === "executed" && spend.digest, `the spend did not execute: ${spend.summary}`)
  must(judged.receipt.verdict, "the gate receipt carries no verdict")

  const digest = spend.digest as string
  const gateReceiptVerdictDigest = verdictDigest(judged.receipt.verdict as NonNullable<typeof judged.receipt.verdict>)
  const invokes = trust.audit.query(mandate.id).filter((e) => e.type === "invoke")
  must(invokes.length === 1, `expected one invoke event, found ${invokes.length}`)
  const invokeVerdictDigest = (invokes[0] as { readonly verdictDigest?: string }).verdictDigest
  const suiAuthorizedByVerdictDigest = spend.authorizedBy?.verdictDigest

  // The indexer trails the chain, and an allowance it has not seen yet throws.
  const deadline = Date.now() + INDEXER_WAIT_MS
  let chain: Awaited<ReturnType<typeof chainSpends>> = []
  for (;;) {
    let lastError: unknown = null
    try {
      chain = await chainSpends({ allowanceId: allowance.allowanceId, network: NETWORK })
      if (chain.some((s) => s.digest === digest)) break
    } catch (e) {
      lastError = e
    }
    if (Date.now() > deadline) throw new Error(`intent-e2e: the indexer never showed ${digest}: ${String(lastError ?? "absent from a readable list")}`)
    await sleep(3_000)
  }

  const { orphans } = reconcile({ gate: [judged.receipt], sui: [spend], chain })
  const record = { network: NETWORK, judge: "mockJudgmentProvider", digest, verdictDigest: gateReceiptVerdictDigest, invokeVerdictDigest, gateReceiptVerdictDigest, suiAuthorizedByVerdictDigest, orphans }
  must(invokeVerdictDigest === gateReceiptVerdictDigest && suiAuthorizedByVerdictDigest === gateReceiptVerdictDigest, `the three records disagree: ${JSON.stringify(record)}`)
  must(orphans.length === 0, `reconcile reported orphans: ${JSON.stringify(orphans)}`)

  writeFileSync(OUT, `${JSON.stringify(record, null, 2)}\n`)
  console.log(`executed ${spend.explorer}`)
  console.log(JSON.stringify(record, null, 2))
} finally {
  const revoked = await sui.revoke({ signer: principal, allowance })
  console.log(`revoke: ${revoked.verdict}`)
}
process.exit(0)
