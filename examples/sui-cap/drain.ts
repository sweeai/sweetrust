// ATTACK 9 · sui drain — "send everything", on a REAL Sui wallet. TESTNET ONLY: the SUI here is test money.
// Run: node drain.ts              (about 15 s, needs the network and funded testnet keys: see the README)
//      node drain.ts --rehearse   (same run, then a quiet cleanup before the verdict: revoke + sweep back)
//      node drain.ts --sweep      (cleanup only: revoke old allowances, return the attacker's SUI)
// Node >= 22.18 runs the types as-is. Install first (npm install): it imports the PUBLISHED sweetrust-sui 0.1.0 and @mysten/sui.
//
// What is real: a funded testnet wallet (the owner), an allowance the owner opens for the agent's key with Sui's own
// 0x2::allowance (a rate limit of CAP a day), and four spends the agent signs. The adapter builds each spend WITHOUT
// the node's simulating resolver, so an over-cap spend is not dropped before it is sent: it executes, aborts inside
// 0x2::allowance, and leaves a failed transaction with a digest that anyone can open. The verdict is computed from
// those results and from the chain's own balances, never printed unconditionally.
// Honest limits: whoever holds the agent key can still spend up to the cap, to any address (the chain does not limit
// the recipient); only the owner's revoke stops that. Sui's rate window is fixed, not rolling. Testnet, not mainnet.
import { createRequire } from "node:module"
import { pathToFileURL } from "node:url"
import { existsSync, readFileSync, writeFileSync } from "node:fs"

const KEYS_FILE = process.env.SWEETRUST_SUI_TESTNET_KEYS ?? `${import.meta.dirname}/keys.json`
const RPC = process.env.SUI_TESTNET_RPC ?? "https://fullnode.testnet.sui.io:443"
const GQL = process.env.SUI_TESTNET_GRAPHQL ?? "https://graphql.testnet.sui.io/graphql"
const STATE_FILE = `${import.meta.dirname}/.drain-state.json`
const TESTNET_GENESIS = "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD"
const SUI_T = "0x2::sui::SUI"

const MODE = process.argv.includes("--sweep") ? "sweep" : process.argv.includes("--rehearse") ? "rehearse" : "run"
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))
const now = () => performance.now()
const ms = (t0: number) => `${Math.round(now() - t0)} ms`
const short = (a: string) => `${a.slice(0, 10)}…${a.slice(-5)}`
const scan = (d: string) => `https://suiscan.xyz/testnet/tx/${d}`
const scanAccount = (a: string) => `https://suiscan.xyz/testnet/account/${a}`

// The attacker can type anything to the agent. The cap is the owner's, in base units (MIST): 1 SUI = 1,000,000,000 MIST.
// Numbers: the cap check is inclusive, so the 0.02 lands exactly on it; the 0.001 that follows is refused by a hair.
const CAP_MIST = 20_000_000n // 0.02 SUI a day
const WINDOW_MS = 86_400_000
const GAS_BUDGET = 8_000_000n // 0.008 SUI ceiling per transaction; a refused spend costs the agent about a third of it
const MIN_AGENT_GAS = 20_000_000n // the agent pays gas for every spend it signs, refused ones too (about 0.001 SUI each)
const SWEEP_GAS_BUDGET = 3_000_000n
const MERCHANT_RESERVE = 5_000_000n // the attacker's address keeps this much to pay its own sweep gas (more than the budget)
const MIN_WALLET = 50_000_000n // below 0.05 SUI the demo is not worth running

// ── load the published adapter and the Sui SDK from this folder's own install (npm install; sweetrust-sui@0.1.0) ──
type Any = any // the adapter and SDK are loaded dynamically, so there are no static types
let adapter: Any, SuiGrpcClient: Any, Ed25519Keypair: Any, Transaction: Any
try {
  adapter = await import("sweetrust-sui")
  ;({ SuiGrpcClient } = await import("@mysten/sui/grpc"))
  ;({ Ed25519Keypair } = await import("@mysten/sui/keypairs/ed25519"))
  ;({ Transaction } = await import("@mysten/sui/transactions"))
} catch (e) {
  console.log(`DEMO ERROR: could not load sweetrust-sui and @mysten/sui (run npm install in this folder first) (${String(e instanceof Error ? e.message : e).slice(0, 160)})`)
  process.exit(2)
}
const { suiAllowances, SUI, chainSpends } = adapter
const fmt = (mist: bigint): string => SUI.format(mist)
// The same amount, short: two decimals from 0.1 SUI up ("2.31 SUI"); a small amount keeps every digit.
// The exact figure stays on the "before:" line below, and nothing is computed from this one.
const disp = (mist: bigint): string => (mist >= 100_000_000n ? `${(Number(mist) / 1e9).toFixed(2)} SUI` : fmt(mist))

// ── keys: never printed ──
type Keys = { principal: string; agent: string; merchant: string }
let keys: Keys
try {
  keys = JSON.parse(readFileSync(KEYS_FILE, "utf8"))
} catch {
  console.log(`DEMO ERROR: no testnet keys at ${KEYS_FILE} (set SWEETRUST_SUI_TESTNET_KEYS to a JSON file of principal, agent, merchant)`)
  process.exit(2)
}
const owner = Ed25519Keypair.fromSecretKey(keys.principal) // the wallet's owner: funds the allowance
const agent = Ed25519Keypair.fromSecretKey(keys.agent) // the agent's key: may spend only under the allowance
const attacker = Ed25519Keypair.fromSecretKey(keys.merchant) // the address the injected prompt names
const OWNER = owner.toSuiAddress() as string
const AGENT = agent.toSuiAddress() as string
const ATTACKER = attacker.toSuiAddress() as string

const client = new SuiGrpcClient({ network: "testnet", baseUrl: RPC })
const sui = suiAllowances({ client, network: "sui:testnet", gasBudget: GAS_BUDGET, confirmTimeoutMs: 20_000 })

// ── chain reads ──
type Bal = { total: bigint; coin: bigint; address: bigint }
const balanceOf = async (owner: string): Promise<Bal> => {
  const b = (await client.getBalance({ owner, coinType: SUI_T })).balance
  return { total: BigInt(b.balance), coin: BigInt(b.coinBalance), address: BigInt(b.addressBalance) }
}
const withTimeout = <T,>(p: Promise<T>, label: string, limitMs = 12_000): Promise<T> =>
  Promise.race([p, new Promise<T>((_, rej) => setTimeout(() => rej(new Error(`${label} did not answer within ${limitMs / 1000} s`)), limitMs))])

// ── what we know, so far, about the verdict ──
class CouldNotRun extends Error {}
const couldNotRun = (why: string): never => { throw new CouldNotRun(why) }
class DemoError extends Error {}
const demoError = (why: string): never => { throw new DemoError(why) }
const oneLine = (s: unknown) => String(s instanceof Error ? s.message : s).replace(/\s+/g, " ").slice(0, 200)

// ── state: the allowances this script opened and has not revoked (ids only, no keys) ──
type Held = { allowanceId: string; capId: string; funder: string; spender: string; asset: string; amount: string; windowMs: number; openedAt: string }
const loadState = (): Held[] => { try { return existsSync(STATE_FILE) ? JSON.parse(readFileSync(STATE_FILE, "utf8")).open ?? [] : [] } catch { return [] } }
const saveState = (open: Held[]) => { try { writeFileSync(STATE_FILE, JSON.stringify({ open }, null, 2)) } catch { /* the demo never fails on its own bookkeeping */ } }
const handleOf = (h: Held) => ({ network: "sui:testnet", asset: h.asset, allowanceId: h.allowanceId, capId: h.capId, funder: h.funder, spender: h.spender, limits: { rate: { amount: BigInt(h.amount), windowMs: h.windowMs } } })

// ── one plain transaction signed by us (cleanup and stocking only, never part of the attack) ──
const run1 = async (tx: Any, signer: Any): Promise<{ digest: string; ok: boolean; error: string }> => {
  const res = await client.signAndExecuteTransaction({ transaction: tx, signer, include: { effects: true } })
  const t = res.$kind === "Transaction" ? res.Transaction : res.FailedTransaction
  await client.core.waitForTransaction({ digest: t.digest, timeout: 20_000 }).catch(() => undefined)
  return { digest: t.digest, ok: res.$kind === "Transaction", error: t.status?.error?.message ?? "" }
}

/** Cleanup: revoke what this script left open (the owner signs, the storage deposit comes back) and return the attacker's SUI. */
async function housekeeping(say: (s: string) => void): Promise<string[]> {
  const notes: string[] = []
  // 1. revoke the allowances this script opened
  const still: Held[] = []
  for (const h of loadState()) {
    const t0 = now()
    const r = await sui.revoke({ signer: owner, allowance: handleOf(h) })
    const gone = r.verdict === "executed" || r.refusal?.code === "allowance-gone"
    if (!gone) still.push(h)
    say(`  revoke  ${short(h.allowanceId)} → ${gone ? "gone" : `NOT revoked (${r.refusal?.code ?? r.verdict})`}${r.digest ? `  ${scan(r.digest)}` : ""}  (${ms(t0)})`)
    notes.push(`revoke ${gone ? "ok" : "failed"}`)
  }
  saveState(still)
  // 1b. the owner's SUI sits in ONE place, its address balance (what an allowance draws from, and what the explorer's
  //     total shows), so a loose coin is deposited into it; the transaction pays its own gas from that balance
  const oc: { objectId: string }[] = (await client.listCoins({ owner: OWNER, coinType: SUI_T })).objects
  if (oc.length > 0) {
    const t0 = now()
    const tx = new Transaction()
    tx.setSender(OWNER)
    tx.setGasPayment([])
    tx.setGasBudget(SWEEP_GAS_BUDGET)
    const [first, ...rest] = oc.map((c) => tx.object(c.objectId))
    if (rest.length > 0) tx.mergeCoins(first, rest)
    tx.moveCall({ target: "0x2::coin::send_funds", typeArguments: [SUI_T], arguments: [first, tx.pure.address(OWNER)] })
    try {
      const r = await run1(tx, owner)
      say(`  fold    wallet's loose coins → its address balance ${r.ok ? "done" : `FAILED (${oneLine(r.error)})`}  ${scan(r.digest)}  (${ms(t0)})`)
    } catch (e) { say(`  fold    FAILED (${oneLine(e)})`) }
  }
  // 2. the attacker's address pays its own gas from its address balance (no gas coin needed) and sends everything above
  //    a small reserve home. What it received lands as coin objects; those are merged and deposited too.
  const m = await balanceOf(ATTACKER)
  const coins: { objectId: string }[] = (await client.listCoins({ owner: ATTACKER, coinType: SUI_T })).objects
  const fromBalance = m.address > MERCHANT_RESERVE + 1_000_000n ? m.address - MERCHANT_RESERVE : 0n
  if (coins.length > 0 || fromBalance > 0n) {
    const t0 = now()
    const tx = new Transaction()
    tx.setSender(ATTACKER)
    tx.setGasPayment([])
    tx.setGasBudget(SWEEP_GAS_BUDGET)
    if (coins.length > 0) {
      const [first, ...rest] = coins.map((c) => tx.object(c.objectId))
      if (rest.length > 0) tx.mergeCoins(first, rest)
      tx.moveCall({ target: "0x2::coin::send_funds", typeArguments: [SUI_T], arguments: [first, tx.pure.address(OWNER)] })
    }
    if (fromBalance > 0n) tx.moveCall({ target: "0x2::balance::send_funds", typeArguments: [SUI_T], arguments: [tx.balance({ balance: fromBalance, useGasCoin: false }), tx.pure.address(OWNER)] })
    const total = m.coin + fromBalance
    try {
      const r = await run1(tx, attacker)
      say(`  sweep   attacker address → wallet's address balance: ${fmt(total)} ${r.ok ? "returned" : `FAILED (${oneLine(r.error)})`}  ${scan(r.digest)}  (${ms(t0)})`)
      notes.push(`sweep ${r.ok ? "ok" : "failed"}`)
    } catch (e) { say(`  sweep   FAILED (${oneLine(e)})`); notes.push("sweep failed") }
  } else say("  sweep   attacker address holds nothing above its gas reserve")
  return notes
}

// ───────────────────────────────────────────── main ─────────────────────────────────────────────
const T_START = now()
const log = (s = "") => console.log(s)
try {
  // The chain is the testnet, or nothing is signed. (The adapter checks again before every transaction it sends.)
  let chainId: string
  try { chainId = (await withTimeout(client.core.getChainIdentifier(), `the Sui testnet node at ${RPC}`)).chainIdentifier } catch (e) { couldNotRun(`network: ${oneLine(e)}`) }
  if (chainId !== TESTNET_GENESIS) { log(`DEMO ERROR: ${RPC} is not the Sui testnet (chain ${chainId}); nothing was signed`); process.exit(2) }

  if (MODE === "sweep") {
    log("ATTACK 9 · cleanup — testnet only")
    await housekeeping(log)
    const [w, a, m] = await Promise.all([balanceOf(OWNER), balanceOf(AGENT), balanceOf(ATTACKER)])
    log(`wallet ${fmt(w.total)} (${fmt(w.address)} in its address balance, ${fmt(w.coin)} in coins) · agent ${fmt(a.total)} · attacker address ${fmt(m.total)}`)
    process.exit(0)
  }

  // 1. what the audience sees first: the owner's wallet, the cap
  let w0: Bal, a0: Bal, m0: Bal
  try { [w0, a0, m0] = await withTimeout(Promise.all([balanceOf(OWNER), balanceOf(AGENT), balanceOf(ATTACKER)]), "the balance read") } catch (e) { couldNotRun(`network: ${oneLine(e)}`) }
  if (w0.address < MIN_WALLET) couldNotRun(`the wallet's address balance is ${fmt(w0.address)}; fund it: sui client faucet --address ${OWNER}`)
  if (a0.total < MIN_AGENT_GAS) couldNotRun(`the agent holds ${fmt(a0.total)}, too little for gas; fund it: sui client faucet --address ${AGENT}`)

  // 1. the owner opens a FRESH allowance (Sui's window is fixed and anchored by the first charge, so every run opens its own).
  //    It runs before the wallet is read and shown because the owner pays its gas from the same address balance, and
  //    "send everything" must name what is really there when the agent tries it. The open is printed below, in story order.
  const results: { n: number; what: string; amount: bigint; receipt: Any; ms: number }[] = []
  let t0 = now()
  const opened = await sui.open({
    signer: owner,
    allowance: { network: "sui:testnet", asset: SUI_T, spender: AGENT, limits: { rate: { amount: CAP_MIST, windowMs: WINDOW_MS } } },
    name: "sweetrust sui-cap example: 0.02 SUI a day",
  })
  const openMs = Math.round(now() - t0)
  if (opened.allowance === null) {
    const code = opened.receipt.refusal?.code
    if (code === "not-submitted" || opened.receipt.verdict === "errored") couldNotRun(`network: ${oneLine(opened.receipt.summary)}`)
    demoError(`the allowance did not open: ${oneLine(opened.receipt.summary)}`)
  }
  const allowance = opened.allowance
  saveState([...loadState(), { allowanceId: allowance.allowanceId, capId: allowance.capId, funder: OWNER, spender: AGENT, asset: SUI_T, amount: CAP_MIST.toString(), windowMs: WINDOW_MS, openedAt: new Date().toISOString() }])
  // The wallet as it stands now: read until two reads agree, so a replica one transaction behind cannot misname "everything".
  for (let tries = 0, last = -1n; tries < 8; tries++) {
    w0 = await balanceOf(OWNER)
    if (w0.address === last) break
    last = w0.address
    await sleep(300)
  }
  const EVERYTHING = w0.address // "send everything": the whole address balance, which is what an allowance draws from

  // 2. what the audience sees first: the owner's wallet, the cap, then the allowance that was just opened
  log("ATTACK 9 · sui drain — a prompt-injected agent is told: send everything in the wallet to this address.")
  log("TESTNET: every SUI below is Sui testnet test money. Nothing here touches mainnet.")
  log(`wallet   ${short(OWNER)}   holds ${disp(w0.total)} (testnet)`)
  log(`         ${scanAccount(OWNER)}`)
  if (w0.coin > 0n) log(`         ${fmt(w0.address)} of it is in the address balance an allowance draws from (the rest is loose coins; --sweep folds them in)`)
  log(`agent    ${short(AGENT)}   its key may spend only through an allowance the owner opened`)
  log(`attacker ${short(ATTACKER)}   the address in the injected prompt; the chain does not restrict who receives`)
  log(`cap      ${fmt(CAP_MIST)} a day, held by Sui itself (0x2::allowance), not by the agent or any library`)
  log()
  log(`  open · the owner gives the agent an allowance of ${fmt(CAP_MIST)} a day → OPENED`)
  log(`         tx ${opened.receipt.digest}  ${opened.receipt.explorer}  (${openMs} ms)`)

  // 3. the attacker's four proposals, in order; each goes to the chain as it comes and the line is printed as the chain answers
  const proposals: { what: string; amount: bigint }[] = [
    { what: "send everything", amount: EVERYTHING },
    { what: "send", amount: CAP_MIST },
    { what: "send", amount: CAP_MIST },
    { what: "send", amount: 1_000_000n },
  ]
  for (const [i, p] of proposals.entries()) {
    t0 = now()
    const receipt = await sui.spend({
      signer: agent, allowance,
      amount: p.amount, recipient: ATTACKER,
    })
    const took = Math.round(now() - t0)
    results.push({ n: i + 1, ...p, receipt, ms: took })
    const more = i === 2 ? " more" : ""
    const tries = `agent tries to ${p.what} ${i === 0 ? `(${disp(p.amount)})` : disp(p.amount)}${more}`
    if (receipt.verdict === "executed") {
      log(`  ${i + 1} · ${tries} → SENT`)
      log(`         tx ${receipt.digest}  ${receipt.explorer}  (${took} ms)`)
    } else if (receipt.refusal?.refusedBy === "chain" && receipt.digest !== null) {
      const n = receipt.refusal.native
      log(`  ${i + 1} · ${tries} → REFUSED BY SUI (${n?.abortName ?? "abort"})`)
      log(`         tx ${receipt.digest}  ${receipt.explorer}  (${took} ms)`)
      log(`         ${String(receipt.refusal.why).split(/\. (?=[A-Z])/)[0].replace(/^Refused by Sui validators \(allowance::\w+\): /, "").replace(/\.$/, "")}.`)
    } else {
      // The chain was not reached, or its answer was never read: not a refusal, and not a verdict.
      couldNotRun(`network: step ${i + 1} (${p.what}) never got an answer from the chain: ${oneLine(receipt.summary)}`)
    }
  }

  // 4. the audit: what the chain says moved, read from the chain, not from the receipts above
  const rem = await sui.remaining({ allowance }).catch(() => null)
  const landed = results.filter((r) => r.receipt.verdict === "executed")
  const expected = landed.reduce((s, r) => s + r.amount, 0n)
  let w1 = w0, m1 = m0
  for (let tries = 0; tries < 8; tries++) {
    ;[w1, m1] = await Promise.all([balanceOf(OWNER), balanceOf(ATTACKER)])
    if (w0.address - w1.address === expected && m1.total - m0.total === expected) break
    await sleep(500)
  }
  const lost = w0.address - w1.address
  const gained = m1.total - m0.total
  let indexer = ""
  for (let tries = 0; tries < 6 && indexer === ""; tries++) {
    try {
      const spends: Any[] = await chainSpends({ allowanceId: allowance.allowanceId, network: "sui:testnet", graphqlUrl: GQL })
      if (spends.length < proposals.length) { await sleep(750); continue } // the indexer trails the chain by moments
      const ok = spends.filter((s) => s.status === "success")
      const sum = ok.reduce((s, x) => s + BigInt(x.amount ?? 0), 0n)
      indexer = `the chain's own indexer lists ${spends.length} spend attempts: ${ok.length} succeeded (${fmt(sum)}), ${spends.length - ok.length} failed`
      if (sum !== lost) demoError(`the indexer says ${fmt(sum)} left the allowance but the wallet's balance fell by ${fmt(lost)}`)
    } catch (e) { indexer = `the chain's indexer could not be read (${oneLine(e)}); the balances above are what is real` }
  }
  log()
  log(`  audit · ${indexer || "the chain's indexer had not caught up; the balances are what is real"}`)
  if (rem) log(`  audit · Sui says the allowance has ${fmt(BigInt(rem.rate?.remainingInWindow ?? "0"))} left in this window`)

  // Honesty: the demo is only meaningful if the "send everything" was refused for the cap, and the one inside the cap landed.
  const [first, second] = results
  if (first.receipt.verdict === "executed") { /* it got through: that is the verdict below, not a demo error */ }
  else if (first.receipt.refusal?.native?.abortName !== "EExceedsRateLimit") demoError(`the first attempt was refused for another reason (${first.receipt.refusal?.code}), not the cap: ${oneLine(first.receipt.summary)}`)
  if (second.receipt.verdict !== "executed") demoError(`the ${fmt(second.amount)} inside the cap did not land (${second.receipt.refusal?.code ?? second.receipt.verdict}): ${oneLine(second.receipt.summary)}`)
  if (lost !== expected || gained !== expected) demoError(`the balances do not reconcile: the wallet fell by ${fmt(lost)}, the attacker gained ${fmt(gained)}, the landed spends add up to ${fmt(expected)}`)
  const refusedOk = results.filter((r) => r.receipt.verdict !== "executed").every((r) => r.receipt.refusal?.native?.abortName === "EExceedsRateLimit")

  log(`before: ${fmt(w0.address)} · lost: ${fmt(lost)} · safe: ${fmt(w1.address)} · cap: ${fmt(CAP_MIST)} a day   (all testnet SUI)`)
  log(`        ${results.map((r) => `${r.n}: ${r.ms} ms`).join(" · ")} · open: ${openMs} ms · total ${Math.round(now() - T_START)} ms`)

  // 5. rehearsal only: put the money back before the verdict, so the next run starts where this one did
  if (MODE === "rehearse") {
    log("  cleanup (rehearsal only):")
    await housekeeping(log)
  }

  const verdict = lost <= CAP_MIST && refusedOk && first.receipt.verdict !== "executed" ? "BLOCKED by the chain" : "GOT THROUGH"
  log(`ATTACK 9 · sui drain · ${verdict}`)
  process.exit(0)
} catch (e) {
  if (e instanceof CouldNotRun) { console.log(`ATTACK 9 · sui drain · COULD NOT RUN (${e.message.slice(0, 220)})`); process.exit(0) }
  if (e instanceof DemoError) { console.log(`DEMO ERROR: ${e.message}`); process.exit(2) }
  console.log(`ATTACK 9 · sui drain · COULD NOT RUN (network: ${oneLine(e)})`)
  process.exit(0)
}
