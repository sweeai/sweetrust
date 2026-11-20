// Makes the three testnet keys the example needs, and prints the two addresses to fund. Run: node make-keys.ts
// The keys are written to keys.json next to this file (plain text, mode 0600, ignored by git inside this repository). They are TESTNET keys: never reuse one anywhere real.
import { existsSync, writeFileSync } from "node:fs"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"

const FILE = `${import.meta.dirname}/keys.json`
if (existsSync(FILE)) { console.log(`${FILE} already exists, so nothing was written. Delete it first if you want new keys.`); process.exit(0) }
const [principal, agent, merchant] = [Ed25519Keypair.generate(), Ed25519Keypair.generate(), Ed25519Keypair.generate()]
writeFileSync(FILE, JSON.stringify({ principal: principal.getSecretKey(), agent: agent.getSecretKey(), merchant: merchant.getSecretKey() }, null, 2), { mode: 0o600, flag: "wx" })
console.log("Wrote keys.json: testnet keys in plain text. Never commit or share it, and never point this example at a key that holds real funds.")
console.log("Fund BOTH addresses with testnet SUI (sui client faucet --address <address>, or https://faucet.sui.io with Testnet chosen), then run: node drain.ts --rehearse")
console.log(`  owner wallet: ${principal.toSuiAddress()}   (opens the allowance; the cap is spent from here)`)
console.log(`  agent wallet: ${agent.toSuiAddress()}   (pays gas for the agent's spends)`)
