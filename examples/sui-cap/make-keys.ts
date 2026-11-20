// Makes the three testnet keys the example needs, and prints the address to fund. Run: node make-keys.ts
// The keys are written to keys.json next to this file (mode 0600, ignored by git). They are TESTNET keys: never reuse one anywhere real.
import { existsSync, writeFileSync } from "node:fs"
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"

const FILE = `${import.meta.dirname}/keys.json`
if (existsSync(FILE)) { console.log(`${FILE} already exists, so nothing was written. Delete it first if you want new keys.`); process.exit(0) }
const [principal, agent, merchant] = [Ed25519Keypair.generate(), Ed25519Keypair.generate(), Ed25519Keypair.generate()]
writeFileSync(FILE, JSON.stringify({ principal: principal.getSecretKey(), agent: agent.getSecretKey(), merchant: merchant.getSecretKey() }, null, 2), { mode: 0o600 })
console.log("Wrote keys.json (testnet only).")
console.log(`Fund this address with testnet SUI at https://faucet.sui.io (choose Testnet), then run: node drain.ts`)
console.log(`  owner wallet: ${principal.toSuiAddress()}`)
