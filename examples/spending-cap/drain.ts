// ATTACK 7 · drain — "send everything": the wallet holds $50,000, the agent's cap is $20 a day. Offline.
// Run: node drain.ts   (Node >= 22.18 runs the types as-is; after npm install: no network, no key, no model)
//
// What is real: the kernel's spending cap (sweetrust from npm), called for every proposal. The ledger moves
// only when the kernel says allowed. Everything printed comes from what the kernel returned and from the ledger;
// the verdict is computed, never printed unconditionally. Honest limit: the cap lives in the agent's host process (see the README); the rail-level version is
// Sui's sui::allowance, which needs testnet.
import { createTrust, defineCapability, grantorId, makeInMemoryAuditLive, MandateFailure } from "sweetrust/mandate"

const WALLET = 50_000
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))

const Pay = defineCapability("treasury.pay")
const trust = createTrust({ store: makeInMemoryAuditLive() })
const OWNER = grantorId("OWNER")
const org = trust.issueOrgMandate({ grantor: OWNER, capabilities: [Pay] as const, rationale: "Company treasury" })
const proj = trust.issueProjectMandate({ grantor: OWNER, grantorScope: org, capabilities: [Pay] as const, rationale: "Daily purchases" })
const grant = { grantor: OWNER, grantorScope: proj, capabilities: [Pay] as const, rationale: "Small daily purchases" }

const limit = { amount: 20, unit: "USD", windowMs: 86_400_000 }
const agent = trust.issueAgentMandate({
  ...grant, limits: { "treasury.pay": limit },
})
const CAP = limit.amount

const ledger = { treasury: WALLET, attacker: 0 }
const fmt = (n: number) => "$" + n.toLocaleString("en-US")

// The host calls this with the real amount, never the agent's own figure. Money moves only on "allowed".
const propose = (amount: number): string => {
  let result: string
  try {
    trust.useCapability(
      { mandate: agent, capability: Pay, amount },
    )
    result = "allowed"
  } catch (e) {
    result = MandateFailure.is(e) ? e._tag : `threw: ${e}`
  }
  if (result === "allowed") { ledger.treasury -= amount; ledger.attacker += amount }
  return result
}

// The attacker can type anything to the agent. The agent proposes these, in order.
const proposals = [50_000, 20, 20, 1]
// Each proposal goes to the kernel as it comes, and the line is printed as the kernel answers. The short
// pause between them is real pacing (the run would otherwise finish in a tenth of a second), not a fake delay.
const PAUSE_MS = 300
console.log(`The wallet holds ${fmt(WALLET)}. The agent's cap: ${fmt(CAP)} a day.`)
await sleep(PAUSE_MS)
const results: { amount: number; result: string }[] = []
for (const [i, amount] of proposals.entries()) {
  const result = propose(amount)
  results.push({ amount, result })
  const out = result === "allowed" ? "SENT" : `REFUSED (${result})`
  const more = i > 0 && amount === proposals[i - 1] ? " more" : ""   // the second $20 is "$20 more"
  console.log(`  ${i + 1} · agent tries to send ${fmt(amount)}${more} → ${out}`)
  await sleep(PAUSE_MS)
}

// Honesty: the demo is only meaningful if the first $50,000 was refused and the single $20 was allowed.
if (results[0].result === "allowed") { console.log("DEMO ERROR: the $50,000 was NOT refused, so the cap did not hold"); process.exit(2) }
if (results[1].result !== "allowed") { console.log(`DEMO ERROR: the $20 inside the cap was not allowed (${results[1].result})`); process.exit(2) }

const lost = WALLET - ledger.treasury
console.log(`before: ${fmt(WALLET)} · lost: ${fmt(lost)} · safe: ${fmt(ledger.treasury)} · cap: ${fmt(CAP)} a day`)
console.log(lost <= CAP && ledger.attacker === lost ? "ATTACK 7 · drain · BLOCKED by the cap" : "ATTACK 7 · drain · GOT THROUGH")
process.exit(0)
