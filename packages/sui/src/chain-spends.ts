/**
 * What actually left an allowance, read from the chain's own indexer and owing
 * nothing to any receipt or log of ours.
 *
 * One paged GraphQL query, `transactions(filter: { affectedObject })`. A
 * transaction is a spend of this allowance when one of its inputs is a
 * `FUNDS_WITHDRAWAL` with `source: SENDER_ALLOWANCE` naming this allowance. The
 * input is what the chain charges, so it holds whichever Move module the commands
 * call: a spend routed through the spender's own module shows no `0x2::allowance`
 * command at all. Touching the allowance is not enough, because its open and
 * revoke do too, and so can anyone by passing the shared object to their own module.
 *
 * Over-reporting is accepted, and it fails closed. `AllowanceWithdrawal` has
 * `drop`, so the spender can name a withdrawal and never redeem it: the row lists
 * with an unreadable payment and reconcile calls it an orphan, though nothing
 * moved. Only the spender can do this, because a validator refuses at signing a
 * withdrawal whose sender is not the allowance's spender.
 *
 * Inputs, commands and balance changes come from `transactionJson` and
 * `balanceChangesJson`, not from the `commands` and `balanceChanges`
 * connections. Those connections cap at 50 nodes a page, and a capped list would
 * misread a transaction; the JSON fields carry the whole list.
 *
 * Silence never reads as "no spends". An unreachable or erroring indexer throws,
 * and so does a page that claims more without a way to reach it. So does an id
 * with no history at all: every opened allowance has at least its open, so an
 * empty answer means the indexer does not know the object (a wrong id, or
 * history it no longer keeps). A custom indexer that answers with neither a spend
 * nor the allowance's creation throws too, because it may keep only part of the
 * history. A partial answer that does contain spends is returned as it stands.
 *
 * The list is as current as the indexer, which trails the chain by moments, and
 * as honest: nothing here authenticates the indexer's answer (SECURITY.md).
 */
import { normalizeStructTag, normalizeSuiAddress } from "@mysten/sui/utils"
import type { Caip2 } from "./interface.ts"

export interface ChainSpendsArgs {
  readonly allowanceId: string
  /** A CAIP-2 Sui chain id, e.g. `sui:testnet`. */
  readonly network: Caip2
  /** Required for a network with no public endpoint, such as a localnet. */
  readonly graphqlUrl?: string
}

/** One transaction that drew on the allowance, as the chain recorded it. */
export interface ChainSpend {
  readonly digest: string
  readonly status: "success" | "failure"
  /**
   * The address that signed. A validator refuses a withdrawal whose sender is
   * not the allowance's spender, so on a row read from a withdrawal input this
   * was the spender at that moment. A row read from a body with no inputs
   * comes with no such check.
   */
  readonly sender: string
  readonly network: Caip2
  /** The coin type spent, from the withdrawal input, so a failure names it too. */
  readonly asset: string
  /** Null on a failure, and when the balance changes name no single recipient. */
  readonly recipient: string | null
  /** Base units. Null on a failure, and when the balance changes cannot show what moved. */
  readonly amount: string | null
}

const PAGE_SIZE = 50
/** A ceiling for an indexer that never stops paging: hitting it throws, never truncates. */
const MAX_PAGES = 10_000
const REQUEST_TIMEOUT_MS = 30_000

const PUBLIC_NETWORKS = new Set(["sui:mainnet", "sui:testnet", "sui:devnet"])
const FRAMEWORK = normalizeSuiAddress("0x2")
const SUI_COIN = normalizeStructTag("0x2::sui::SUI")
const SPEND_FUNCTIONS = new Set(["balance_spend", "app_balance_spend"])

const QUERY = `query ChainSpends($id: SuiAddress!, $after: String) {
  transactions(first: ${PAGE_SIZE}, after: $after, filter: { affectedObject: $id }) {
    nodes { digest sender { address } effects { status balanceChangesJson } transactionJson }
    pageInfo { hasNextPage endCursor }
  }
}`

const typeErr = (m: string) => new TypeError(`chainSpends: ${m}`)
const unread = (m: string) => new Error(`chainSpends: ${m}`)
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null

function endpoint(network: string, graphqlUrl: unknown): string {
  if (graphqlUrl === undefined) {
    if (!PUBLIC_NETWORKS.has(network)) throw typeErr(`no public GraphQL endpoint is known for ${network}; pass graphqlUrl`)
    return `https://graphql.${network.slice("sui:".length)}.sui.io/graphql`
  }
  const parsed = typeof graphqlUrl === "string" && URL.canParse(graphqlUrl) ? new URL(graphqlUrl) : null
  if (parsed === null || (parsed.protocol !== "http:" && parsed.protocol !== "https:")) {
    throw typeErr(`graphqlUrl must be an http(s) URL, got ${JSON.stringify(graphqlUrl)}`)
  }
  return graphqlUrl as string
}

interface Connection {
  readonly nodes: ReadonlyArray<unknown>
  readonly hasNextPage: boolean
  readonly endCursor: unknown
}

async function fetchPage(url: string, id: string, after: string | null): Promise<Connection> {
  let res: Response
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query: QUERY, variables: { id, after } }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
  } catch (cause) {
    throw new Error(`chainSpends: could not reach ${url}: ${cause instanceof Error ? cause.message : String(cause)}`, { cause })
  }
  if (!res.ok) throw unread(`${url} answered HTTP ${res.status}`)

  let json: unknown
  try {
    json = JSON.parse(await res.text())
  } catch (cause) {
    throw new Error(`chainSpends: ${url} did not answer with JSON`, { cause })
  }
  if (!isObject(json)) throw unread(`${url} answered with no result`)
  // A GraphQL error arrives with HTTP 200, and can sit beside partial data.
  if (json.errors !== undefined && json.errors !== null && !(Array.isArray(json.errors) && json.errors.length === 0)) {
    throw unread(`the indexer returned an error: ${JSON.stringify(json.errors)}`)
  }
  const connection = isObject(json.data) ? json.data.transactions : undefined
  if (!isObject(connection) || !Array.isArray(connection.nodes) || !isObject(connection.pageInfo) || typeof connection.pageInfo.hasNextPage !== "boolean") {
    throw unread(`${url} answered without a readable transactions page`)
  }
  return { nodes: connection.nodes, hasNextPage: connection.pageInfo.hasNextPage, endCursor: connection.pageInfo.endCursor }
}

/** The command's Move call if it spends through `0x2::allowance` directly, else null. */
function directSpendCall(command: unknown): Record<string, unknown> | null {
  const unreadable = () => unread("a command in a transaction could not be read, so it cannot be ruled out as a spend")
  if (!isObject(command)) throw unreadable()
  if (command.moveCall === undefined) return null
  const call = command.moveCall
  if (!isObject(call) || typeof call.package !== "string" || typeof call.module !== "string" || typeof call.function !== "string") throw unreadable()
  return normalizeSuiAddress(call.package) === FRAMEWORK && call.module === "allowance" && SPEND_FUNCTIONS.has(call.function) ? call : null
}

/** The `SENDER_ALLOWANCE` withdrawals among a transaction's inputs, with the allowance each names. */
interface Withdrawal {
  readonly allowance: string
  readonly funder: string
  readonly coinType: unknown
}

function readWithdrawals(inputs: ReadonlyArray<unknown>): Withdrawal[] {
  const unreadable = () => unread("an input in a transaction could not be read, so it cannot be ruled out as a spend")
  const withdrawals: Withdrawal[] = []
  for (const input of inputs) {
    if (!isObject(input) || typeof input.kind !== "string") throw unreadable()
    if (input.kind !== "FUNDS_WITHDRAWAL") continue
    const w = input.fundsWithdrawal
    if (!isObject(w) || typeof w.source !== "string") throw unreadable()
    if (w.source === "SENDER" || w.source === "SPONSOR") continue // an address's own balance, no allowance
    if (w.source !== "SENDER_ALLOWANCE") throw unreadable() // a source this code has never seen may draw on an allowance
    if (typeof w.allowance !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(w.allowance)) throw unreadable()
    if (typeof w.funder !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(w.funder)) throw unreadable()
    withdrawals.push({ allowance: normalizeSuiAddress(w.allowance), funder: normalizeSuiAddress(w.funder), coinType: w.coinType })
  }
  return withdrawals
}

interface Change {
  readonly address: string
  readonly coinType: string
  readonly amount: bigint
}

/** The balance changes, or null if any line of them cannot be read. */
function readChanges(raw: unknown): Change[] | null {
  if (!Array.isArray(raw)) return null
  const changes: Change[] = []
  for (const c of raw) {
    if (!isObject(c) || typeof c.address !== "string" || typeof c.coinType !== "string" || typeof c.amount !== "string" || !/^-?\d+$/.test(c.amount)) return null
    try {
      changes.push({ address: normalizeSuiAddress(c.address), coinType: normalizeStructTag(c.coinType), amount: BigInt(c.amount) })
    } catch {
      return null
    }
  }
  return changes
}

type Payment = Pick<ChainSpend, "amount" | "recipient">
const UNREADABLE: Payment = { amount: null, recipient: null }

const total = (lines: ReadonlyArray<Change>): bigint => lines.reduce((sum, c) => sum + c.amount, 0n)

/**
 * Amount and recipient from one successful spend's balance changes.
 *
 * The chain nets every owner's changes to one line per coin, so on a SUI spend
 * whoever paid gas has it folded into their line. The funder is the one debit
 * that is neither the sender's nor a gas sponsor's; more than one such debit
 * leaves the funder unknown.
 *
 * What the funder lost must equal what the recipients gained, or the amount is
 * unreadable: reporting the debit as the amount received would read a skim as
 * clean. A sender's credit on a SUI spend it paid gas for is that credit minus
 * the gas, so it never equals the debit and such a spend reads as unreadable.
 *
 * `declaredFunder` is the funder a withdrawal input names, when there is one:
 * money debited from anyone else did not come out of this allowance.
 */
function readPayment(raw: unknown, sender: string, asset: string, gasOwner: string, declaredFunder: string | null): Payment {
  const changes = readChanges(raw)
  if (changes === null) return UNREADABLE
  const inAsset = changes.filter((c) => c.coinType === asset)
  const debits = inAsset.filter((c) => c.amount < 0n)
  const credits = inAsset.filter((c) => c.amount > 0n)
  const isSui = asset === SUI_COIN
  const senderLineHasGas = isSui && gasOwner === sender

  const candidates = debits.filter((c) => c.address !== sender && !(isSui && c.address === gasOwner))
  if (candidates.length > 1) return UNREADABLE
  if (declaredFunder !== null && (candidates.length === 1 ? candidates[0]!.address : sender) !== declaredFunder) return UNREADABLE

  if (candidates.length === 1) {
    const funder = candidates[0]!
    const debit = -funder.amount
    const recipients = credits.filter((c) => c.address !== funder.address)
    if (total(recipients) !== debit) return UNREADABLE
    return { amount: debit.toString(), recipient: recipients.length === 1 ? recipients[0]!.address : null }
  }

  // No one else was debited, so the sender is the funder, or nothing moved.
  const own = debits.filter((c) => c.address === sender).reduce<Change | null>((largest, c) => (largest === null || c.amount < largest.amount ? c : largest), null)
  if (own === null) return UNREADABLE // paid itself: the coin nets to no change
  const recipients = credits.filter((c) => c.address !== sender)
  if (senderLineHasGas) {
    // The sender's one line is the payment plus gas, so only the credit shows
    // the payment. With no single credit, the two cannot be separated.
    return recipients.length === 1 ? { amount: recipients[0]!.amount.toString(), recipient: recipients[0]!.address } : UNREADABLE
  }
  const debit = -own.amount
  if (total(recipients) !== debit) return UNREADABLE
  return { amount: debit.toString(), recipient: recipients.length === 1 ? recipients[0]!.address : null }
}

interface Classified {
  readonly spend: ChainSpend | null
  /**
   * The transaction affected the allowance without taking it as an input, which
   * only its creation can do: it is shared, so every later use must name it. The
   * indexer's history therefore reaches back that far.
   */
  readonly opens: boolean
}

function readTransaction(node: unknown, id: string, network: Caip2): Classified {
  if (!isObject(node) || !isObject(node.transactionJson) || !isObject(node.transactionJson.kind) || typeof node.transactionJson.kind.kind !== "string") {
    throw unread("a transaction's body could not be read, so it cannot be ruled out as a spend")
  }
  const body = node.transactionJson
  const kind = body.kind as Record<string, unknown>
  if (kind.kind !== "PROGRAMMABLE_TRANSACTION") return { spend: null, opens: false } // system transactions have no commands
  const ptb = isObject(kind.programmableTransaction) ? kind.programmableTransaction : undefined
  if (ptb === undefined || !Array.isArray(ptb.commands)) throw unread("a programmable transaction came back without its commands")
  if (!Array.isArray(ptb.inputs)) throw unread("a programmable transaction came back without its inputs")
  const directSpends = (ptb.commands as unknown[]).map(directSpendCall).filter((c) => c !== null)
  const inputs = ptb.inputs as unknown[]
  const opens = !inputs.some((i) => isObject(i) && typeof i.objectId === "string" && normalizeSuiAddress(i.objectId) === id)
  const withdrawals = readWithdrawals(inputs)
  const ofThisAllowance = withdrawals.filter((w) => w.allowance === id)
  // Every real spend has inputs, since the allowance itself is one. A spend
  // command over an empty input list is an incomplete body, and an incomplete
  // body cannot rule a spend out, so it lists.
  const isSpendWithNoInputs = inputs.length === 0 && directSpends.length > 0
  if (ofThisAllowance.length === 0 && !isSpendWithNoInputs) return { spend: null, opens }

  const digest = node.digest
  if (typeof digest !== "string") throw unread("a spend came back without its digest")
  const effects = node.effects
  const status = isObject(effects) ? effects.status : undefined
  if (status !== "SUCCESS" && status !== "FAILURE") throw unread(`spend ${digest} has an unreadable status: ${JSON.stringify(status)}`)
  const senderRaw = isObject(node.sender) ? node.sender.address : undefined
  if (typeof senderRaw !== "string") throw unread(`spend ${digest} came back without its sender`)
  const sender = normalizeSuiAddress(senderRaw)

  let asset: string
  try {
    const coinType = ofThisAllowance.length > 0 ? ofThisAllowance[0]!.coinType : (directSpends[0]!.typeArguments as string[])[0]
    asset = normalizeStructTag(coinType as string)
  } catch (cause) {
    throw new Error(`chainSpends: spend ${digest} does not say which coin it spent`, { cause })
  }

  // A second withdrawal in the transaction mixes its movement into these
  // changes, and nothing here says which part belongs to this allowance. The
  // count is of withdrawals, not calls: one wrapper call can redeem several.
  const gasOwner = isObject(body.gasPayment) && typeof body.gasPayment.owner === "string" ? normalizeSuiAddress(body.gasPayment.owner) : sender
  const mixed = withdrawals.length > 1 || directSpends.length > 1
  const payment = status === "FAILURE" || mixed ? UNREADABLE : readPayment((effects as Record<string, unknown>).balanceChangesJson, sender, asset, gasOwner, ofThisAllowance[0]?.funder ?? null)
  return { spend: { digest, status: status === "SUCCESS" ? "success" : "failure", sender, network, asset, ...payment }, opens }
}

/**
 * Every transaction that withdrew from this allowance, one row each, in chain
 * order, refused ones included. Throws when the indexer cannot be read.
 */
export async function chainSpends(args: ChainSpendsArgs): Promise<ChainSpend[]> {
  if (!isObject(args)) throw typeErr("expected { allowanceId, network, graphqlUrl? }")
  const { allowanceId, network, graphqlUrl } = args as unknown as Record<string, unknown>
  if (typeof allowanceId !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(allowanceId)) {
    throw typeErr(`allowanceId must be a Sui object id, got ${JSON.stringify(allowanceId)}`)
  }
  if (typeof network !== "string" || !/^sui:[-a-z0-9]{1,32}$/.test(network)) {
    throw typeErr(`network must be a CAIP-2 Sui chain id such as "sui:testnet", got ${JSON.stringify(network)}`)
  }
  const url = endpoint(network, graphqlUrl)
  const id = normalizeSuiAddress(allowanceId)

  const spends: ChainSpend[] = []
  let seen = 0
  let opened = false
  let after: string | null = null
  for (let page = 0; page < MAX_PAGES; page++) {
    const connection: Connection = await fetchPage(url, id, after)
    seen += connection.nodes.length
    for (const node of connection.nodes) {
      const { spend, opens } = readTransaction(node, id, network as Caip2)
      if (spend !== null) spends.push(spend)
      if (opens) opened = true
    }
    if (!connection.hasNextPage) {
      if (seen === 0) throw unread(`the indexer has no transactions for ${id}: a wrong id, or history it no longer keeps`)
      if (spends.length === 0 && !opened && graphqlUrl !== undefined) {
        throw unread(`${url} shows no spend and not the allowance's creation either, so it may keep only part of the history`)
      }
      return spends
    }
    const next = connection.endCursor
    if (typeof next !== "string" || next === "" || next === after) {
      throw unread(`the indexer says more transactions follow but gave no new cursor (got ${JSON.stringify(next)}), so the list would be truncated`)
    }
    after = next
  }
  throw unread(`the indexer was still paging after ${MAX_PAGES} pages; stopping rather than returning a partial list`)
}
