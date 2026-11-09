/**
 * chainSpends against a stubbed indexer: which transactions count as spends,
 * how amount and recipient are read from balance changes, and every way an
 * indexer can stay silent without that reading as "no spends".
 */
import { afterEach, describe, expect, it, vi } from "vitest"
import { reconcile } from "sweetrust/verify"
import { chainSpends } from "../src/index.ts"

const ALLOWANCE = `0x${"a1".repeat(32)}`
const FUNDER = `0x${"f0".repeat(32)}`
const SENDER = `0x${"5e".repeat(32)}`
const RECIPIENT = `0x${"7c".repeat(32)}`
const OTHER = `0x${"33".repeat(32)}`
const SPONSOR = `0x${"99".repeat(32)}`
const SUI = `0x${"0".repeat(63)}2::sui::SUI`
const USDC = `0x${"db".repeat(32)}::usdc::USDC`
const TWO = `0x${"0".repeat(63)}2`

const call = (fn: string, module = "allowance", pkg = TWO, typeArguments = [SUI]) => ({
  moveCall: { package: pkg, module, function: fn, typeArguments, arguments: [] },
})
const change = (address: string, amount: string, coinType = SUI) => ({ address, coinType, amount })

interface TxOpts {
  digest?: string
  sender?: string | null
  status?: string | null
  changes?: unknown
  commands?: unknown
  inputs?: unknown
  transactionJson?: unknown
  /** Who paid gas, when it is not the sender (a sponsored transaction). */
  gasOwner?: string
}

/**
 * One node in the shape the real indexer returns (recorded from testnet 2026-11-07),
 * except that `inputs` is empty unless a test names them. Those bodies reach the
 * no-inputs path; `a spend is what moved` below uses the real input list.
 */
function tx({ digest = "D1", sender = SENDER, status = "SUCCESS", changes = [], commands, inputs, transactionJson, gasOwner }: TxOpts) {
  return {
    digest,
    sender: sender === null ? null : { address: sender },
    effects: status === null ? null : { status, balanceChangesJson: changes },
    transactionJson: transactionJson !== undefined ? transactionJson : {
      sender,
      gasPayment: { owner: gasOwner ?? sender },
      kind: { kind: "PROGRAMMABLE_TRANSACTION", programmableTransaction: { inputs: inputs ?? [], commands: commands ?? [call("balance_spend")] } },
    },
  }
}

interface Page { nodes: unknown[]; hasNextPage?: boolean; endCursor?: string | null }
const body = ({ nodes, hasNextPage = false, endCursor = null }: Page) => ({
  data: { transactions: { nodes, pageInfo: { hasNextPage, endCursor } } },
})
const respond = (json: unknown, status = 200) =>
  new Response(typeof json === "string" ? json : JSON.stringify(json), { status })

/** Serves pages in order and records every request. The last page repeats if asked again. */
function stub(...pages: Page[]) {
  const calls: { url: string; query: string; variables: Record<string, unknown> }[] = []
  vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
    const parsed = JSON.parse(String(init.body))
    calls.push({ url: String(url), query: parsed.query, variables: parsed.variables })
    return respond(body(pages[Math.min(calls.length - 1, pages.length - 1)]!))
  }))
  return calls
}
const args = { allowanceId: ALLOWANCE, network: "sui:testnet" as const }
/** One spend's reading of a single transaction. */
async function read(node: ReturnType<typeof tx>) {
  stub({ nodes: [node] })
  const spends = await chainSpends(args)
  expect(spends).toHaveLength(1)
  return spends[0]!
}

afterEach(() => vi.unstubAllGlobals())

describe("which transactions are spends", () => {
  it("lists the spend and the refused spend, never the open or the revoke", async () => {
    stub({
      nodes: [
        tx({ digest: "OPEN", sender: FUNDER, commands: [call("none", "option", "0x1"), call("new")], changes: [change(FUNDER, "-6707600")] }),
        tx({ digest: "SPEND", changes: [change(RECIPIENT, "600"), change(FUNDER, "-600"), change(SENDER, "-1988440")] }),
        tx({ digest: "REFUSED", status: "FAILURE", changes: [change(SENDER, "-1000440")] }),
        tx({ digest: "REVOKE", sender: FUNDER, commands: [call("revoke")], changes: [change(FUNDER, "4707029")] }),
      ],
    })
    expect(await chainSpends(args)).toEqual([
      { digest: "SPEND", status: "success", sender: SENDER, network: "sui:testnet", asset: SUI, recipient: RECIPIENT, amount: "600" },
      { digest: "REFUSED", status: "failure", sender: SENDER, network: "sui:testnet", asset: SUI, recipient: null, amount: null },
    ])
  })

  it("matches the package however its address is written, and only 0x2::allowance", async () => {
    stub({
      nodes: [
        tx({ digest: "SHORT", commands: [call("balance_spend", "allowance", "0x2")], changes: [change(FUNDER, "-1"), change(RECIPIENT, "1")] }),
        tx({ digest: "LOOKALIKE", commands: [call("balance_spend", "allowance", `0x${"ab".repeat(32)}`)] }),
        tx({ digest: "OTHER-MODULE", commands: [call("balance_spend", "wallet")] }),
      ],
    })
    expect((await chainSpends(args)).map((s) => s.digest)).toEqual(["SHORT"])
  })

  it("skips a system transaction, which has no commands to read", async () => {
    stub({ nodes: [tx({ transactionJson: { kind: { kind: "CONSENSUS_COMMIT_PROLOGUE_V4" } } })] })
    expect(await chainSpends(args)).toEqual([])
  })

  it("reads a spend past the 50th command: commands are not a capped connection", async () => {
    const commands = [...Array.from({ length: 80 }, () => ({ splitCoins: {} })), call("balance_spend")]
    const s = await read(tx({ commands, changes: [change(FUNDER, "-5"), change(RECIPIENT, "5")] }))
    expect(s.amount).toBe("5")
  })

  it("takes the asset from the Move call's type argument, so a failure still names it", async () => {
    const s = await read(tx({ status: "FAILURE", commands: [call("balance_spend", "allowance", TWO, [USDC])], changes: [change(SENDER, "-1000")] }))
    expect(s).toMatchObject({ status: "failure", asset: USDC, amount: null, recipient: null })
  })
})

describe("a spend is what moved, not which command ran", () => {
  const PACKAGE = `0x${"ab".repeat(32)}`
  const STRANGER = `0x${"cc".repeat(32)}`
  const OTHER_ALLOWANCE = `0x${"dd".repeat(32)}`
  const CLOCK = { kind: "SHARED", objectId: `0x${"0".repeat(63)}6`, version: "1", mutable: false, mutability: "IMMUTABLE" }
  const shared = (objectId: string) => ({ kind: "SHARED", objectId, version: "1", mutable: true, mutability: "MUTABLE" })
  const withdrawal = (allowance = ALLOWANCE, coinType = SUI, source = "SENDER_ALLOWANCE") => ({
    kind: "FUNDS_WITHDRAWAL",
    fundsWithdrawal: { amount: "500", coinType, source, funder: FUNDER, allowance },
  })
  const paid = [change(RECIPIENT, "500"), change(FUNDER, "-500"), change(SENDER, "-1988429")]
  /** The input list a real spend carries: recorded from testnet 8yqHCsi6Ns9pKUE2sHr6iu4s5eLB4MndtVTWub2ZC6gV. */
  const realInputs = [shared(ALLOWANCE), CLOCK, { kind: "PURE", pure: "NwSW7xgu" }, withdrawal()]
  const noRecords = { gate: [], sui: [] }

  it("lists a library-built spend exactly as before", async () => {
    stub({ nodes: [tx({ digest: "HONEST", inputs: realInputs, changes: paid })] })
    expect(await chainSpends(args)).toEqual([
      { digest: "HONEST", status: "success", sender: SENDER, network: "sui:testnet", asset: SUI, recipient: RECIPIENT, amount: "500" },
    ])
  })

  it("lists a spend through the spender's own module, and reconcile calls it no-receipt", async () => {
    stub({ nodes: [tx({ digest: "WRAPPED", inputs: [shared(ALLOWANCE), CLOCK, withdrawal()], commands: [call("forward", "drain", PACKAGE)], changes: paid })] })
    const chain = await chainSpends(args)
    expect(chain).toEqual([
      { digest: "WRAPPED", status: "success", sender: SENDER, network: "sui:testnet", asset: SUI, recipient: RECIPIENT, amount: "500" },
    ])
    const report = reconcile({ ...noRecords, chain })
    expect(report.ok).toBe(false)
    expect(report.orphans).toEqual([{ digest: "WRAPPED", reason: "no-receipt" }])
  })

  it("takes the asset from the input, because a wrapper's type arguments say nothing", async () => {
    const s = await read(tx({
      inputs: [withdrawal(ALLOWANCE, USDC)],
      commands: [call("forward", "drain", PACKAGE, [SUI])],
      changes: [change(FUNDER, "-100", USDC), change(RECIPIENT, "100", USDC), change(SENDER, "-777")],
    }))
    expect(s).toMatchObject({ asset: USDC, amount: "100", recipient: RECIPIENT })
  })

  it("a stranger touching the allowance plants no orphan, even while spending its own", async () => {
    stub({
      nodes: [
        tx({ digest: "OPEN", sender: FUNDER, commands: [call("new")] }),
        tx({ digest: "TOUCH", sender: STRANGER, inputs: [shared(ALLOWANCE)], commands: [call("touch", "drain", PACKAGE)], changes: [change(STRANGER, "-1988429")] }),
        tx({
          digest: "GRIEF",
          sender: STRANGER,
          inputs: [shared(OTHER_ALLOWANCE), shared(ALLOWANCE), withdrawal(OTHER_ALLOWANCE)],
          commands: [call("balance_spend"), call("touch", "drain", PACKAGE)],
          changes: [change(STRANGER, "-1988429")],
        }),
      ],
    })
    const chain = await chainSpends(args)
    expect(chain).toEqual([])
    expect(reconcile({ ...noRecords, chain }).ok).toBe(true)
  })

  it("a withdrawal from someone's own balance is not an allowance spend", async () => {
    stub({ nodes: [
      tx({ commands: [call("new")] }),
      tx({ digest: "SELF", inputs: [shared(ALLOWANCE), withdrawal(ALLOWANCE, SUI, "SENDER")] }),
      tx({ digest: "GAS", inputs: [shared(ALLOWANCE), withdrawal(ALLOWANCE, SUI, "SPONSOR")] }),
    ] })
    expect(await chainSpends(args)).toEqual([])
  })

  it("matches the allowance however its id is written", async () => {
    const upper = `0x${"A1".repeat(32)}`
    stub({ nodes: [tx({ digest: "CASED", inputs: [withdrawal(upper)], commands: [call("forward", "drain", PACKAGE)], changes: paid })] })
    expect(await chainSpends({ ...args, allowanceId: upper })).toHaveLength(1)
    const short = `0x${"0".repeat(61)}abc`
    stub({ nodes: [tx({ digest: "SHORT", inputs: [withdrawal("0xabc")], commands: [call("forward", "drain", PACKAGE)], changes: paid })] })
    expect((await chainSpends({ ...args, allowanceId: short })).map((c) => c.digest)).toEqual(["SHORT"])
  })

  it("lists an app_balance_spend, with an input and in a body that has none", async () => {
    const appCall = call("app_balance_spend", "allowance", TWO, [SUI, `${PACKAGE}::a::A`])
    const withInput = await read(tx({ inputs: realInputs, commands: [appCall], changes: paid }))
    expect(withInput).toMatchObject({ amount: "500", recipient: RECIPIENT })
    const bare = await read(tx({ inputs: [], commands: [appCall], changes: paid }))
    expect(bare).toMatchObject({ asset: SUI, amount: "500", recipient: RECIPIENT })
  })

  it("counts withdrawals, not calls: two inside one wrapper call are unreadable", async () => {
    const s = await read(tx({ inputs: [withdrawal(), withdrawal()], commands: [call("forward", "drain", PACKAGE)], changes: paid }))
    expect(s).toMatchObject({ status: "success", amount: null, recipient: null })
  })

  it("a second allowance's withdrawal mixes the changes, so the payment is unreadable", async () => {
    const s = await read(tx({ inputs: [withdrawal(), withdrawal(OTHER_ALLOWANCE)], commands: [call("forward", "drain", PACKAGE)], changes: paid }))
    expect(s).toMatchObject({ status: "success", amount: null, recipient: null })
  })

  it("a refused wrapper spend is listed as a failure, and reconcile calls it a refusal", async () => {
    stub({ nodes: [tx({ digest: "REFUSED", status: "FAILURE", inputs: [withdrawal()], commands: [call("forward", "drain", PACKAGE)], changes: [change(SENDER, "-1000")] })] })
    const chain = await chainSpends(args)
    expect(chain).toMatchObject([{ digest: "REFUSED", status: "failure", asset: SUI, amount: null, recipient: null }])
    expect(reconcile({ ...noRecords, chain }).ok).toBe(true)
  })

  it("over-reports a withdrawal the spender named and dropped, and that fails closed", async () => {
    stub({ nodes: [tx({ digest: "DROPPED", inputs: [shared(ALLOWANCE), withdrawal()], commands: [call("touch", "drain", PACKAGE)], changes: [change(SENDER, "-1988429")] })] })
    const chain = await chainSpends(args)
    expect(chain).toMatchObject([{ digest: "DROPPED", status: "success", amount: null, recipient: null }])
    expect(reconcile({ ...noRecords, chain }).orphans).toEqual([{ digest: "DROPPED", reason: "no-receipt" }])
  })

  it("a withdrawal named and dropped beside a payment from the sender's own coin is unreadable", async () => {
    const s = await read(tx({
      inputs: [shared(ALLOWANCE), withdrawal(ALLOWANCE, USDC)],
      commands: [call("touch", "drain", PACKAGE)],
      changes: [change(SENDER, "-500", USDC), change(RECIPIENT, "500", USDC), change(SENDER, "-777")],
    }))
    expect(s).toMatchObject({ status: "success", amount: null, recipient: null })
  })

  it("a debit from anyone but the declared funder is unreadable", async () => {
    const s = await read(tx({
      inputs: [withdrawal(ALLOWANCE, USDC)],
      commands: [call("forward", "drain", PACKAGE)],
      changes: [change(OTHER, "-100", USDC), change(RECIPIENT, "100", USDC), change(SENDER, "-777")],
    }))
    expect(s).toMatchObject({ status: "success", amount: null, recipient: null })
  })

  it("throws on an input it cannot read, rather than ruling a spend out", async () => {
    const bad = [
      null,
      "x",
      {},
      { kind: "FUNDS_WITHDRAWAL" },
      { kind: "FUNDS_WITHDRAWAL", fundsWithdrawal: {} },
      { kind: "FUNDS_WITHDRAWAL", fundsWithdrawal: { source: "SENDER_ALLOWANCE" } },
      { kind: "FUNDS_WITHDRAWAL", fundsWithdrawal: { source: "SENDER_ALLOWANCE", allowance: "nope" } },
      { kind: "FUNDS_WITHDRAWAL", fundsWithdrawal: { source: "SENDER_ALLOWANCE", allowance: ALLOWANCE, coinType: SUI } },
      { kind: "FUNDS_WITHDRAWAL", fundsWithdrawal: { source: "SPONSOR_ALLOWANCE", allowance: ALLOWANCE, coinType: SUI } },
    ]
    for (const input of bad) {
      stub({ nodes: [tx({ inputs: [input] })] })
      await expect(chainSpends(args)).rejects.toThrow(/ruled out/)
    }
  })

  it("throws when a transaction comes back without its inputs", async () => {
    stub({ nodes: [tx({ transactionJson: { kind: { kind: "PROGRAMMABLE_TRANSACTION", programmableTransaction: { commands: [] } } } })] })
    await expect(chainSpends(args)).rejects.toThrow(/inputs/)
  })

  it("throws when a withdrawal does not say which coin it spent", async () => {
    const noCoin = { kind: "FUNDS_WITHDRAWAL", fundsWithdrawal: { source: "SENDER_ALLOWANCE", allowance: ALLOWANCE, funder: FUNDER } }
    stub({ nodes: [tx({ inputs: [noCoin], changes: paid })] })
    await expect(chainSpends(args)).rejects.toThrow(/which coin/)
  })
})

describe("amount and recipient, from balance changes", () => {
  const usdc = [call("balance_spend", "allowance", TWO, [USDC])]

  it("ignores the agent's gas: only the funder's debit is the amount", async () => {
    const s = await read(tx({ changes: [change(RECIPIENT, "600"), change(FUNDER, "-600"), change(SENDER, "-1988440")] }))
    expect(s).toMatchObject({ amount: "600", recipient: RECIPIENT })
  })

  it("reads a non-SUI spend in its own coin; the SUI gas line is another coin", async () => {
    const s = await read(tx({ commands: usdc, changes: [change(FUNDER, "-100", USDC), change(RECIPIENT, "100", USDC), change(SENDER, "-777")] }))
    expect(s).toMatchObject({ asset: USDC, amount: "100", recipient: RECIPIENT })
  })

  it("does not mistake a sponsor's gas for the funder on a non-SUI spend", async () => {
    const s = await read(tx({ commands: usdc, changes: [change(FUNDER, "-100", USDC), change(RECIPIENT, "100", USDC), change(SPONSOR, "-777")] }))
    expect(s).toMatchObject({ amount: "100", recipient: RECIPIENT })
  })

  it("a SUI credit to the gas-paying sender is unreadable: that line is the credit minus the gas", async () => {
    const s = await read(tx({ changes: [change(FUNDER, "-5000000"), change(SENDER, "3000000")] }))
    expect(s).toMatchObject({ status: "success", amount: null, recipient: null })
  })

  it("a SUI debit with no credit is unreadable: gas alone cannot show the sender received it", async () => {
    const s = await read(tx({ changes: [change(FUNDER, "-600"), change(SENDER, "-1987840")] }))
    expect(s).toMatchObject({ status: "success", amount: null, recipient: null })
  })

  it("a non-SUI debit nobody received is unreadable: gas cannot hide a credit there", async () => {
    const s = await read(tx({ commands: usdc, changes: [change(FUNDER, "-100", USDC), change(SENDER, "-777")] }))
    expect(s).toMatchObject({ status: "success", amount: null, recipient: null })
  })

  it("a sender who is the funder, non-SUI: the sender's debit is the amount", async () => {
    const s = await read(tx({ commands: usdc, changes: [change(SENDER, "-10000", USDC), change(RECIPIENT, "10000", USDC), change(SENDER, "-100324")] }))
    expect(s).toMatchObject({ amount: "10000", recipient: RECIPIENT })
  })

  it("a sender who is the funder, SUI: the debit includes gas, so the amount is what arrived", async () => {
    const s = await read(tx({ changes: [change(SENDER, "-1988998"), change(RECIPIENT, "600")] }))
    expect(s).toMatchObject({ amount: "600", recipient: RECIPIENT })
  })

  it("a sender who is the funder paying itself moved nothing readable", async () => {
    const s = await read(tx({ commands: usdc, changes: [change(SENDER, "-100324")] }))
    expect(s).toMatchObject({ status: "success", amount: null, recipient: null })
  })

  it("a sender-funder SUI spend with no credit cannot be separated from gas", async () => {
    const s = await read(tx({ changes: [change(SENDER, "-1988998")] }))
    expect(s).toMatchObject({ amount: null, recipient: null })
  })

  it("several recipients: the debit is still the amount, the recipient is unreadable", async () => {
    const s = await read(tx({ commands: usdc, changes: [change(FUNDER, "-20", USDC), change(RECIPIENT, "10", USDC), change(OTHER, "10", USDC), change(SPONSOR, "-5")] }))
    expect(s).toMatchObject({ amount: "20", recipient: null })
  })

  it("a sponsored SUI spend: the sponsor's gas is not the funder's debit", async () => {
    const s = await read(tx({ gasOwner: SPONSOR, changes: [change(FUNDER, "-600"), change(SPONSOR, "-1092112"), change(RECIPIENT, "600")] }))
    expect(s).toMatchObject({ amount: "600", recipient: RECIPIENT })
  })

  it("a sponsored SUI spend by its own funder: the sponsor is never read as the funder", async () => {
    const s = await read(tx({ gasOwner: SPONSOR, changes: [change(SENDER, "-600"), change(SPONSOR, "-1092112"), change(RECIPIENT, "600")] }))
    expect(s).toMatchObject({ amount: "600", recipient: RECIPIENT })
  })

  it("a sponsored SUI spend with no credit is unreadable: the sender paid no gas, so nothing hides one", async () => {
    const s = await read(tx({ gasOwner: SPONSOR, changes: [change(FUNDER, "-600"), change(SPONSOR, "-1092112")] }))
    expect(s).toMatchObject({ status: "success", amount: null, recipient: null })
  })

  it("a skim is unreadable: the funder lost more than the one recipient gained", async () => {
    const s = await read(tx({ commands: usdc, changes: [change(FUNDER, "-1000", USDC), change(RECIPIENT, "600", USDC), change(SENDER, "-777")] }))
    expect(s).toMatchObject({ status: "success", amount: null, recipient: null })
  })

  it("a skim on SUI is unreadable: the difference can hide in the sender's gas line", async () => {
    const s = await read(tx({ changes: [change(FUNDER, "-1000"), change(RECIPIENT, "600"), change(SENDER, "-1988029")] }))
    expect(s).toMatchObject({ amount: null, recipient: null })
  })

  it("a skim the sender keeps beside another credit is unreadable", async () => {
    const s = await read(tx({ changes: [change(FUNDER, "-1000"), change(RECIPIENT, "600"), change(SENDER, "300")] }))
    expect(s).toMatchObject({ amount: null, recipient: null })
  })

  it("a recipient paid more than the funder lost is unreadable", async () => {
    const s = await read(tx({ commands: usdc, changes: [change(FUNDER, "-5", USDC), change(SENDER, "-3", USDC), change(RECIPIENT, "8", USDC)] }))
    expect(s).toMatchObject({ amount: null, recipient: null })
  })

  it("a sender who funds a non-SUI spend and credits less than it lost is unreadable", async () => {
    const s = await read(tx({ commands: usdc, changes: [change(SENDER, "-1000", USDC), change(RECIPIENT, "600", USDC)] }))
    expect(s).toMatchObject({ amount: null, recipient: null })
  })

  it("a sponsor who also funds a non-SUI spend is still the funder", async () => {
    const s = await read(tx({ gasOwner: FUNDER, commands: usdc, changes: [change(FUNDER, "-100", USDC), change(FUNDER, "-777"), change(RECIPIENT, "100", USDC)] }))
    expect(s).toMatchObject({ amount: "100", recipient: RECIPIENT })
  })

  it("two possible funders: neither amount nor recipient is readable", async () => {
    const s = await read(tx({ changes: [change(FUNDER, "-600"), change(SPONSOR, "-1000"), change(RECIPIENT, "600")] }))
    expect(s).toMatchObject({ amount: null, recipient: null })
  })

  it("two balance_spend commands: the changes cannot be split between them", async () => {
    const s = await read(tx({ commands: [call("balance_spend"), call("balance_spend")], changes: [change(FUNDER, "-600"), change(RECIPIENT, "600")] }))
    expect(s).toMatchObject({ amount: null, recipient: null })
  })

  it("a success with no readable balance changes is listed, not dropped", async () => {
    for (const changes of [null, undefined, "nope", [{ address: FUNDER }], [change(FUNDER, "1.5")]]) {
      const s = await read(tx({ changes: changes as unknown }))
      expect(s).toMatchObject({ status: "success", amount: null, recipient: null })
    }
  })
})

describe("paging", () => {
  const spend = (digest: string) => tx({ digest, changes: [change(FUNDER, "-1"), change(RECIPIENT, "1")] })

  it("follows endCursor to the end and keeps chain order", async () => {
    const calls = stub(
      { nodes: [spend("A"), spend("B")], hasNextPage: true, endCursor: "c1" },
      { nodes: [spend("C")], hasNextPage: true, endCursor: "c2" },
      { nodes: [spend("D")] },
    )
    expect((await chainSpends(args)).map((s) => s.digest)).toEqual(["A", "B", "C", "D"])
    expect(calls.map((c) => c.variables.after ?? null)).toEqual([null, "c1", "c2"])
    expect(calls.every((c) => c.variables.id === ALLOWANCE)).toBe(true)
  })

  it("throws on hasNextPage with no cursor rather than reporting a truncated list", async () => {
    stub({ nodes: [spend("A")], hasNextPage: true, endCursor: null })
    await expect(chainSpends(args)).rejects.toThrow(/cursor/i)
  })

  it("throws when the indexer repeats a cursor", async () => {
    const calls = stub({ nodes: [spend("A")], hasNextPage: true, endCursor: "same" })
    await expect(chainSpends(args)).rejects.toThrow(/cursor/i)
    expect(calls).toHaveLength(2)
  })

  it("throws, not loops, when the indexer never stops paging", async () => {
    let n = 0
    vi.stubGlobal("fetch", vi.fn(async () => respond(body({ nodes: [spend("X")], hasNextPage: true, endCursor: `c${n++}` }))))
    await expect(chainSpends(args)).rejects.toThrow(/pages/i)
  })

  it("an allowance with history but no spends is an empty list", async () => {
    stub({ nodes: [tx({ commands: [call("new")] })] })
    expect(await chainSpends(args)).toEqual([])
  })
})

describe("silence never reads as no spends", () => {
  const fails = (json: unknown, status = 200) => {
    vi.stubGlobal("fetch", vi.fn(async () => respond(json, status)))
    return expect(chainSpends(args)).rejects.toThrow()
  }

  it("throws on a GraphQL errors array, even with HTTP 200 and data", async () => {
    await fails({ errors: [{ message: "boom" }] })
    await fails({ ...body({ nodes: [] }), errors: [{ message: "partial" }] })
    await fails({ ...body({ nodes: [] }), errors: { message: "not even a list" } })
  })
  it("throws on a non-OK response", async () => { await fails(body({ nodes: [] }), 503) })
  it("throws on a body that is not JSON", async () => { await fails("<html>gateway</html>") })
  it("throws when the transactions connection is missing", async () => {
    await fails({ data: { transactions: null } })
    await fails({ data: null })
    await fails({ data: { transactions: { nodes: null, pageInfo: {} } } })
  })
  it("throws when the indexer is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("fetch failed") }))
    await expect(chainSpends(args)).rejects.toThrow(/fetch failed/)
  })
  it("throws when the indexer knows nothing about the allowance", async () => {
    stub({ nodes: [] })
    await expect(chainSpends(args)).rejects.toThrow(/no transactions/i)
  })
  it("throws when a transaction cannot be classified", async () => {
    stub({ nodes: [tx({ transactionJson: null })] })
    await expect(chainSpends(args)).rejects.toThrow(/transactionJson|read/i)
    stub({ nodes: [tx({ transactionJson: { kind: { kind: "PROGRAMMABLE_TRANSACTION", programmableTransaction: {} } } })] })
    await expect(chainSpends(args)).rejects.toThrow()
    for (const command of [null, "x", { moveCall: null }, { moveCall: { module: "allowance" } }]) {
      stub({ nodes: [tx({ commands: [command] })] })
      await expect(chainSpends(args)).rejects.toThrow(/ruled out/)
    }
  })
  it("throws when a spend has no status or sender", async () => {
    stub({ nodes: [tx({ status: null })] })
    await expect(chainSpends(args)).rejects.toThrow(/status/i)
    stub({ nodes: [tx({ status: "PENDING" })] })
    await expect(chainSpends(args)).rejects.toThrow(/status/i)
    stub({ nodes: [tx({ sender: null })] })
    await expect(chainSpends(args)).rejects.toThrow(/sender/i)
  })
})

describe("a custom indexer that may keep only part of the history", () => {
  const custom = { ...args, graphqlUrl: "http://127.0.0.1:9125/graphql" }
  const touch = tx({ digest: "TOUCH", inputs: [{ kind: "SHARED", objectId: ALLOWANCE, mutable: true }], commands: [{ moveCall: { package: `0x${"ab".repeat(32)}`, module: "drain", function: "touch", typeArguments: [], arguments: [] } }] })

  it("throws when it shows neither a spend nor the allowance's creation", async () => {
    stub({ nodes: [touch] })
    await expect(chainSpends(custom)).rejects.toThrow(/part of the history/)
  })
  it("reads as no spends once the creation is in view", async () => {
    stub({ nodes: [tx({ digest: "OPEN", commands: [call("new")] }), touch] })
    expect(await chainSpends(custom)).toEqual([])
  })
  it("a stranger's own allowance::new beside the target does not count as its creation", async () => {
    stub({ nodes: [tx({ digest: "FAKE-OPEN", inputs: [{ kind: "SHARED", objectId: ALLOWANCE, mutable: true }], commands: [call("new")] })] })
    await expect(chainSpends(custom)).rejects.toThrow(/part of the history/)
  })
  it("recognizes a creation with no allowance command, as an app-bound open has", async () => {
    stub({ nodes: [tx({ digest: "APP-OPEN", commands: [{ moveCall: { package: `0x${"ab".repeat(32)}`, module: "app", function: "issue_it", typeArguments: [], arguments: [] } }] })] })
    expect(await chainSpends(custom)).toEqual([])
  })
  it("returns a partial answer that does contain spends as it stands", async () => {
    const withdrawal = { kind: "FUNDS_WITHDRAWAL", fundsWithdrawal: { amount: "1", coinType: SUI, source: "SENDER_ALLOWANCE", funder: FUNDER, allowance: ALLOWANCE } }
    stub({ nodes: [tx({ digest: "SPEND", inputs: [withdrawal], changes: [change(FUNDER, "-1"), change(RECIPIENT, "1")] })] })
    expect((await chainSpends(custom)).map((s) => s.digest)).toEqual(["SPEND"])
  })
  it("the public endpoint is not held to it", async () => {
    stub({ nodes: [touch] })
    expect(await chainSpends(args)).toEqual([])
  })
})

describe("arguments", () => {
  it("uses the network's public endpoint by default", async () => {
    const calls = stub({ nodes: [tx({ commands: [call("new")] })] })
    await chainSpends({ allowanceId: ALLOWANCE, network: "sui:mainnet" })
    expect(calls[0]!.url).toBe("https://graphql.mainnet.sui.io/graphql")
  })
  it("graphqlUrl overrides it, and a custom network needs one", async () => {
    const calls = stub({ nodes: [tx({ commands: [call("new")] })] })
    await chainSpends({ allowanceId: ALLOWANCE, network: "sui:localnet", graphqlUrl: "http://127.0.0.1:9125/graphql" })
    expect(calls[0]!.url).toBe("http://127.0.0.1:9125/graphql")
  })
  it("refuses a network with no known URL, and never fetches", async () => {
    const calls = stub({ nodes: [] })
    for (const network of ["sui:localnet", "sui:constructor"]) {
      await expect(chainSpends({ allowanceId: ALLOWANCE, network: network as "sui:testnet" })).rejects.toThrow(TypeError)
    }
    expect(calls).toHaveLength(0)
  })
  it("refuses bad arguments with a TypeError", async () => {
    stub({ nodes: [] })
    const bad = [
      { allowanceId: "nope", network: "sui:testnet" },
      { allowanceId: `${ALLOWANCE}"){}`, network: "sui:testnet" },
      { allowanceId: ALLOWANCE, network: "eip155:1" },
      { allowanceId: ALLOWANCE, network: "testnet" },
      { allowanceId: ALLOWANCE, network: "sui:testnet", graphqlUrl: "not a url" },
      { allowanceId: ALLOWANCE, network: "sui:testnet", graphqlUrl: "file:///etc/passwd" },
      null,
    ]
    for (const b of bad) await expect(chainSpends(b as never)).rejects.toThrow(TypeError)
  })
  it("sends the id as a variable and normalizes a short one", async () => {
    const calls = stub({ nodes: [tx({ commands: [call("new")] })] })
    await chainSpends({ allowanceId: "0xABC", network: "sui:testnet" })
    expect(calls[0]!.variables.id).toBe(`0x${"0".repeat(61)}abc`)
    expect(calls[0]!.query).not.toContain("abc")
  })
})
