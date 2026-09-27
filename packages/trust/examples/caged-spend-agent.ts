/**
 * The cage, live on Sui testnet: one spend inside the cap goes through, one
 * above it is refused ON-CHAIN, then the owner revokes and the rest comes home.
 *
 *   SUI_TESTNET_PRIVATE_KEY=$(security find-generic-password -s a-retired-package -w) \
 *   node examples/caged-spend-agent.ts
 *
 * Exits non-zero if any beat does not behave as stated.
 */
import { SuiGrpcClient } from "@mysten/sui/grpc"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"
import { Transaction } from "@mysten/sui/transactions"
import { SuiChainCage, TESTNET_FULLNODE } from "../src/sui/index.ts"

const mist = (sui: number): bigint => BigInt(Math.round(sui * 1e9))
const scan = (d: string) => `https://suiscan.xyz/testnet/tx/${d}`

const key = process.env.SUI_TESTNET_PRIVATE_KEY
if (!key) {
  console.error("Set SUI_TESTNET_PRIVATE_KEY to a funded testnet key (see the header).")
  process.exit(2)
}

const client = new SuiGrpcClient({ network: "testnet", baseUrl: TESTNET_FULLNODE })
const owner = Ed25519Keypair.fromSecretKey(key)
const agent = Ed25519Keypair.generate()
const seller = Ed25519Keypair.generate()

// Gas only: the agent never holds the budget.
const gas = new Transaction()
gas.setSender(owner.toSuiAddress())
gas.transferObjects([gas.splitCoins(gas.gas, [mist(0.05)])], agent.toSuiAddress())
const gasRes = await client.signAndExecuteTransaction({ transaction: gas, signer: owner })
await client.waitForTransaction({ digest: (gasRes.Transaction ?? gasRes.FailedTransaction)!.digest })

const cages = new SuiChainCage({ client, owner, agent })
const cage = await cages.open({
  agent: agent.toSuiAddress(),
  funding: mist(0.01),
  perSpendMax: mist(0.01),
  totalMax: mist(0.01),
  expiresAtMs: BigInt(Date.now() + 24 * 60 * 60 * 1000), // "today's cap": a one-day cage
  allowedRecipients: [seller.toSuiAddress()],
})
console.log(`cage ${cage.cageId}: cap 0.01 SUI for the day, remaining ${await cages.remaining(cage)} mist`)

let failed = false
const inside = await cages.spend(cage, { to: seller.toSuiAddress(), amount: mist(0.006), memo: "inside the cap" })
if (inside.ok) console.log(`✓ inside the cap, settled: ${scan(inside.txId)}`)
else { failed = true; console.log(`✗ the in-cap spend was refused: ${inside.refusal} ${inside.detail}`) }

const over = await cages.spend(cage, { to: seller.toSuiAddress(), amount: mist(0.006), memo: "over the cap" })
if (!over.ok && over.refusal === "over-total-cap" && over.txId) {
  console.log(`✓ over the cap, refused ON-CHAIN (${over.refusal}): ${scan(over.txId)}`)
} else { failed = true; console.log(`✗ expected an on-chain over-total-cap refusal, got ${JSON.stringify(over)}`) }

console.log(`remaining after both: ${await cages.remaining(cage)} mist`)
await cages.revoke(cage)
console.log("✓ revoked; the remainder returned to the owner")
process.exit(failed ? 1 : 0)
