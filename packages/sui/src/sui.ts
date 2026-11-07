/**
 * The Sui adapter: delegated spending on Sui's native allowance (ADR 0003).
 *
 * open    → `0x2::allowance::new`, signed by the funder (the plain path, no app module)
 * spend   → `0x2::allowance::balance_spend`, signed by the spender, through the SDK's allowance coin intent
 * revoke  → `0x2::allowance::revoke`, signed by the funder with the soulbound `AllowanceCap`
 * remaining → a read of the shared `Allowance` object and the chain's `Clock`
 *
 * Danny's rulings (2026-11-06), which this file implements:
 *  1. Degrade with labels. The chain holds what it can, the library holds what it
 *     can of the rest, and every receipt labels each limit `chain` or `library`.
 *     A limit nobody can hold is refused at open(), never silently dropped.
 *  2. Plain path only: `allowance::new` + `balance_spend`. No Move of our own.
 *  3. Receipts say WHY, in plain English (./explain.ts).
 *  4. Receipts carry the CAIP-2 network and the digest, and can be appended to
 *     a SweeTrust ReceiptLog / SignedReceiptLog.
 *
 * A refusal is a RESULT, never a thrown error. A spend executes for real: a
 * spend Sui refuses is a failed transaction with a digest, which costs the
 * spender gas and is exactly what makes it a record a stranger can look up.
 * Errors are thrown only for programmer errors (a wrong JS type).
 */
import { Transaction, TransactionDataBuilder } from "@mysten/sui/transactions"
import type { Signer } from "@mysten/sui/cryptography"
import type { ClientWithCoreApi, SuiClientTypes } from "@mysten/sui/client"
import { isValidSuiAddress, normalizeStructTag, normalizeSuiAddress } from "@mysten/sui/utils"
import type { ReceiptLog } from "sweetrust/gate"
import {
  ABORTS, ALLOWANCE_MODULE, CLOCK_OBJECT_ID, decodeClockMs, MAX_NAME_BYTES, U256_MAX, U64_MAX,
  abortNameOf, currentWindow, decodeAllowance, type AllowanceState,
} from "./allowance-move.ts"
import {
  CHAIN_CHECK_ORDER, LIMIT_BY_ABORT, PER_SPEND_UNHELD_WHY, RECIPIENTS_SUCCESSOR,
  chainLimitValue, chainOutsideWhy, chainWithinWhy, fmtDuration, fmtTime, heldWhy, limitValue, limitWords, line,
  periodPhrase, presentLimits, shortAddress, type SpendFacts,
} from "./explain.ts"
import type {
  AllowanceAdapter, AllowanceLimits, AllowanceReceipt, Caip2, Enforcement, HeldBy,
  LimitLine, LimitName, NativeAbort, Refusal, RefusalCode, Remaining, Verb,
} from "./interface.ts"
import { SUI, baseUnitsOf, type Scale } from "./scale.ts"

/**
 * Who holds each limit on Sui, in sweetrust-sui 0.1. The one declaration.
 *
 * - lifetime cap, rate, start, expiry: `sui::allowance` aborts a spend outside them.
 * - recipients: the plain allowance has no recipient list, so the library checks
 *   the payee in-process before sending. Successor: Sui Agent Payments' allowed
 *   services (testnet-only, no public package as of 2026-11-06).
 * - per-spend maximum: nobody, so open() refuses it. Successor: Sui Agent
 *   Payments' per-payment cap.
 */
export const enforces: Enforcement = Object.freeze({
  lifetimeCap: "chain",
  rate: "chain",
  start: "chain",
  expiry: "chain",
  recipients: "library",
  perSpendMax: "nobody",
})

/** Who holds a limit: every read of the declaration goes through here. */
const declaration: Enforcement = enforces
const holder = (l: LimitName): HeldBy => declaration[l]

/** An allowance this adapter opened: everything spend, revoke and remaining need. */
export interface SuiAllowance {
  readonly network: Caip2
  /** The coin type, e.g. `0x2::sui::SUI`. */
  readonly asset: string
  readonly allowanceId: string
  /** The soulbound `AllowanceCap`, owned by the funder; revoke consumes it. */
  readonly capId: string
  readonly funder: string
  readonly spender: string
  /**
   * The limits as granted. The chain-held ones also live in the on-chain object;
   * the library-held ones (recipients) live ONLY here, so persist this object if
   * the host restarts and keeps spending through the library.
   */
  readonly limits: AllowanceLimits
}

type Include = { effects: true; objectTypes: true }

/**
 * Any `@mysten/sui` 2.x client: `SuiGrpcClient`, `SuiGraphQLClient` or
 * `SuiJsonRpcClient`. The adapter talks to `client.core` only.
 */
export type SuiAllowanceClient = ClientWithCoreApi

/** Anything with SweeTrust's `ReceiptLog.append`: a `ReceiptLog` or a `SignedReceiptLog`. */
export type ReceiptAppender = Pick<ReceiptLog, "append">

export interface SuiAllowancesOptions {
  readonly client: SuiAllowanceClient
  /** `sui:testnet`, `sui:mainnet` or `sui:devnet`: must be the network the client talks to. */
  readonly network: Caip2
  /** How amounts read on receipts. Default: SUI for `0x2::sui::SUI`, raw base units otherwise. */
  readonly scale?: Scale
  /** Every receipt is also appended here, so `verifySignedChain` re-checks it. */
  readonly log?: ReceiptAppender
  /** Gas budget per transaction, in MIST. Set explicitly so a refused spend executes and leaves a digest. Default 10_000_000 (0.01 SUI). */
  readonly gasBudget?: bigint
  /**
   * How long to wait, in ms, for a transaction to confirm on chain after
   * `signAndExecuteTransaction` throws, before a verb returns `errored`. The
   * throw may mean the signed transaction was forwarded and will still finalize,
   * so the adapter re-reads the digest rather than guess. Default 30_000.
   */
  readonly confirmTimeoutMs?: number
  /** The explorer page for a digest, or null for none. Default: suiscan.xyz. */
  readonly explorer?: ((network: Caip2, digest: string) => string | null) | null
  /** This machine's clock, for receipts of refusals that never reached the chain. Default `Date.now`. */
  readonly now?: () => number
}

export type SuiAllowances = AllowanceAdapter<Signer, SuiAllowance>

const SUI_TYPE = "0x2::sui::SUI"
const DEFAULT_GAS_BUDGET = 10_000_000n
const DEFAULT_CONFIRM_TIMEOUT_MS = 30_000
const SCHEMA = "sweetrust-sui/receipt@1" as const

/**
 * The genesis checkpoint digest of each Sui network whose genesis never changes,
 * which is what every transport's `getChainIdentifier()` returns. Read from
 * graphql.{mainnet,testnet}.sui.io on 2026-11-07. Devnet and localnet are reset
 * to a new genesis, so a client on them cannot be checked and is taken at its word.
 */
const GENESIS: Readonly<Record<string, string>> = Object.freeze({
  "sui:mainnet": "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S",
  "sui:testnet": "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD",
})

/**
 * What the adapter says when `@mysten/sui` built a transaction without asking
 * for `resolveTransactionPlugin`. The adapter's bypass of the transport's
 * simulating resolver works through that one lookup; an SDK that no longer
 * makes it could simulate a spend Sui would refuse and drop the refusal's
 * digest, so the adapter sends nothing rather than send on an unknown path.
 */
const RESOLVER_UNCONSULTED = "this @mysten/sui built the transaction without consulting resolveTransactionPlugin, so sweetrust-sui cannot keep the transport from simulating it first, and a refusal might never reach the chain. Use a @mysten/sui release this adapter supports (tested: 2.35)."

const defaultExplorer = (network: Caip2, digest: string): string | null => {
  const net = network.slice("sui:".length)
  return net === "mainnet" || net === "testnet" || net === "devnet" ? `https://suiscan.xyz/${net}/tx/${digest}` : null
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
const typeErr = (where: string, what: string): TypeError => new TypeError(`sweetrust-sui ${where}: ${what}`)
const deepFreeze = <T>(v: T): T => {
  if (typeof v === "object" && v !== null && !Object.isFrozen(v)) {
    Object.freeze(v)
    for (const x of Object.values(v)) deepFreeze(x)
  }
  return v
}
const minBig = (a: bigint, b: bigint): bigint => (a < b ? a : b)
const normAddr = (a: string): string => normalizeSuiAddress(a)
const validAddr = (a: string): boolean => typeof a === "string" && isValidSuiAddress(normAddr(a))

/** The six limit names, as a set: anything else on a limits object is a typo, and a typo is refused, never dropped. */
const LIMIT_KEYS: ReadonlySet<string> = new Set(["lifetimeCap", "rate", "start", "expiry", "recipients", "perSpendMax"])

// ── Intake: every argument is read once, here, and never again ───────────────

function snapshotLimits(where: string, l: AllowanceLimits): AllowanceLimits {
  if (typeof l !== "object" || l === null) throw typeErr(where, "limits must be an object")
  // A key outside the six is refused, never ignored: `recipient` or `maxPerSpend`
  // would otherwise open with no recipient check and no per-spend refusal (ruling 1).
  for (const k of Object.keys(l)) {
    if (!LIMIT_KEYS.has(k)) throw typeErr(where, `limits has an unknown key ${JSON.stringify(k)}; the limits are lifetimeCap, rate, start, expiry, recipients, perSpendMax. A misspelled key would be dropped silently, so it is refused.`)
  }
  const lifetimeCap = l.lifetimeCap
  const rate = l.rate
  const start = l.start
  const expiry = l.expiry
  const recipients = l.recipients
  const perSpendMax = l.perSpendMax
  const out: { -readonly [K in keyof AllowanceLimits]: AllowanceLimits[K] } = {}
  if (lifetimeCap !== undefined) {
    if (typeof lifetimeCap !== "bigint") throw typeErr(where, "limits.lifetimeCap must be a bigint (base units)")
    out.lifetimeCap = lifetimeCap
  }
  if (rate !== undefined) {
    if (typeof rate !== "object" || rate === null) throw typeErr(where, "limits.rate must be { amount, windowMs }")
    const amount = rate.amount
    const windowMs = rate.windowMs
    if (typeof amount !== "bigint") throw typeErr(where, "limits.rate.amount must be a bigint (base units)")
    if (typeof windowMs !== "number") throw typeErr(where, "limits.rate.windowMs must be a number of milliseconds")
    out.rate = Object.freeze({ amount, windowMs })
  }
  if (start !== undefined) {
    if (!(start instanceof Date)) throw typeErr(where, "limits.start must be a Date")
    out.start = new Date(start.getTime())
  }
  if (expiry !== undefined) {
    if (!(expiry instanceof Date)) throw typeErr(where, "limits.expiry must be a Date")
    out.expiry = new Date(expiry.getTime())
  }
  if (recipients !== undefined) {
    if (!Array.isArray(recipients)) throw typeErr(where, "limits.recipients must be an array of addresses")
    const copy = [...recipients]
    for (const r of copy) if (typeof r !== "string") throw typeErr(where, "limits.recipients must hold strings")
    out.recipients = Object.freeze(copy)
  }
  if (perSpendMax !== undefined) {
    if (typeof perSpendMax !== "bigint") throw typeErr(where, "limits.perSpendMax must be a bigint (base units)")
    out.perSpendMax = perSpendMax
  }
  return Object.freeze(out)
}

function snapshotHandle(where: string, h: SuiAllowance): SuiAllowance {
  if (typeof h !== "object" || h === null) throw typeErr(where, "allowance must be the object open() returned")
  const network = h.network
  const asset = h.asset
  const allowanceId = h.allowanceId
  const capId = h.capId
  const funder = h.funder
  const spender = h.spender
  const limits = h.limits
  for (const [k, v] of [["network", network], ["asset", asset], ["allowanceId", allowanceId], ["capId", capId], ["funder", funder], ["spender", spender]] as const) {
    if (typeof v !== "string") throw typeErr(where, `allowance.${k} must be a string`)
  }
  const held = snapshotLimits(where, limits)
  // open() refuses a bad window as a result (EBadRateLimit), so a handle that
  // carries one was not made by open(). Caught here, before anything is sent,
  // because the receipt's arithmetic on it would otherwise throw after the
  // chain had moved.
  const w = held.rate?.windowMs
  if (w !== undefined && (!Number.isSafeInteger(w) || w <= 0)) throw typeErr(where, "allowance.limits.rate.windowMs must be a positive whole number of milliseconds, as open() returned it")
  return Object.freeze({ network, asset, allowanceId, capId, funder, spender, limits: held })
}

// ── The adapter ──────────────────────────────────────────────────────────────

export function suiAllowances(options: SuiAllowancesOptions): SuiAllowances {
  if (typeof options !== "object" || options === null) throw typeErr("suiAllowances", "options must be an object")
  const client = options.client
  const network = options.network
  const scaleOpt = options.scale
  const log = options.log
  const gasBudget = options.gasBudget ?? DEFAULT_GAS_BUDGET
  const confirmTimeoutMs = options.confirmTimeoutMs ?? DEFAULT_CONFIRM_TIMEOUT_MS
  const explorerOpt = options.explorer
  const localNow = options.now ?? Date.now
  if (typeof client !== "object" || client === null || typeof client.core !== "object") throw typeErr("suiAllowances", "client must be a @mysten/sui client (it needs client.core)")
  if (typeof network !== "string" || !/^sui:[-a-z0-9]{1,32}$/.test(network)) throw typeErr("suiAllowances", `network must be a CAIP-2 Sui chain id such as "sui:testnet", got ${JSON.stringify(network)}`)
  if (typeof gasBudget !== "bigint" || gasBudget <= 0n) throw typeErr("suiAllowances", "gasBudget must be a positive bigint (MIST)")
  if (typeof confirmTimeoutMs !== "number" || !Number.isFinite(confirmTimeoutMs) || confirmTimeoutMs < 0) throw typeErr("suiAllowances", "confirmTimeoutMs must be a non-negative number of milliseconds")
  if (log !== undefined && (typeof log !== "object" || log === null || typeof log.append !== "function")) throw typeErr("suiAllowances", "log must be a ReceiptLog (an object with append())")
  if (options.now !== undefined && typeof options.now !== "function") throw typeErr("suiAllowances", "now must be a function returning epoch milliseconds, e.g. Date.now (not Date.now())")
  if (explorerOpt !== undefined && explorerOpt !== null && typeof explorerOpt !== "function") throw typeErr("suiAllowances", "explorer must be a function (network, digest) => string | null, or null")
  if (scaleOpt !== undefined && (typeof scaleOpt !== "object" || scaleOpt === null || typeof scaleOpt.format !== "function")) throw typeErr("suiAllowances", "scale must be a Scale from defineScale()")
  const explorer = explorerOpt === undefined ? defaultExplorer : explorerOpt
  /**
   * The explorer link runs after the chain has moved, so it may not throw: a
   * host's link function that fails costs the receipt its link, never the receipt.
   */
  const explorerLink = (digest: string): string | null => {
    if (explorer === null) return null
    try {
      const url = explorer(network, digest)
      return typeof url === "string" ? url : null
    } catch {
      return null
    }
  }
  const core = client.core

  const scaleFor = (asset: string): Scale => scaleOpt ?? (normalizeStructTag(asset) === normalizeStructTag(SUI_TYPE) ? SUI : baseUnitsOf(asset))
  const balanceType = (asset: string): string => `0x2::balance::Balance<${asset}>`

  // ── Receipts ──

  const finish = (r: AllowanceReceipt): AllowanceReceipt => {
    const receipt = deepFreeze(r)
    if (log !== undefined) {
      try {
        log.append({
          at: receipt.at,
          sink: `sweetrust-sui.${receipt.verb}`,
          decision: receipt.verdict,
          // The adapter's account of what happened is a claim, so it enters the
          // log untrusted; the digest beside it is what a stranger re-checks on Sui.
          args: { receipt: { value: receipt, tier: "untrusted", provenance: `sweetrust-sui on ${receipt.network}${receipt.digest === null ? ", nothing sent" : `, tx ${receipt.digest}`}` } },
          ...(receipt.refusal === null ? {} : { reason: receipt.refusal.why }),
        })
      } catch (cause) {
        // The chain has already moved (or refused); losing the receipt would be worse than the throw.
        throw Object.assign(new Error("sweetrust-sui: the receipt log refused this receipt; it is attached as .receipt", { cause }), { receipt })
      }
    }
    return receipt
  }

  const refusal = (code: RefusalCode, refusedBy: "chain" | "library", native: NativeAbort | null, why: string): Refusal =>
    Object.freeze({ code, refusedBy, native, why })

  const preflightNative = (abortName: string): NativeAbort => ({ module: ALLOWANCE_MODULE, abortName, abortCode: ABORTS[abortName], rawAbortCode: null })

  type ReceiptFields = Omit<AllowanceReceipt, "schema" | "network" | "explorer"> & { readonly network?: Caip2 }
  // Fields in reading order: what happened, where, the proof, when, who, how much, then why.
  const receiptOf = (f: ReceiptFields): AllowanceReceipt => ({
    schema: SCHEMA,
    verb: f.verb,
    verdict: f.verdict,
    network: f.network ?? network,
    asset: f.asset,
    allowanceId: f.allowanceId,
    digest: f.digest,
    explorer: f.digest === null ? null : explorerLink(f.digest),
    at: f.at,
    atSource: f.atSource,
    funder: f.funder,
    spender: f.spender,
    amount: f.amount,
    amountText: f.amountText,
    recipient: f.recipient,
    limits: f.limits,
    refusal: f.refusal,
    summary: f.summary,
  })

  /**
   * The local clock, as whole milliseconds. It runs after sends (an `errored`
   * receipt, a missing chain timestamp), so it may not throw: a host's clock that
   * throws or returns a fraction or NaN falls back to the system clock.
   */
  const nowLocal = (): number => {
    try {
      const v = localNow()
      if (typeof v === "number" && Number.isFinite(v)) return Math.floor(v)
    } catch {
      // fall through to the system clock
    }
    return Date.now()
  }
  const localAt = (): { at: string; atSource: "local" } => ({ at: new Date(nowLocal()).toISOString(), atSource: "local" })

  // ── Chain I/O ──

  /** Read the allowance. null = it does not exist (revoked or never opened); undefined = the read failed. */
  const readAllowance = async (id: string, minVersion: bigint | null): Promise<AllowanceState | null | undefined> => {
    for (let attempt = 0; attempt < 8; attempt++) {
      const res = await core.getObjects({ objectIds: [id], include: { content: true } }).catch(() => null)
      if (res === null) {
        await sleep(400)
        continue
      }
      const obj = res.objects[0]
      if (obj === undefined || obj instanceof Error) {
        const msg = obj instanceof Error ? obj.message : ""
        if (/not ?found|deleted|does ?not ?exist|notexists/i.test(msg) || obj === undefined) return null
        await sleep(400)
        continue
      }
      // A load-balanced fullnode can answer from a replica one transaction
      // behind; wait until the read reflects the transaction just executed.
      if (minVersion !== null && BigInt(obj.version) < minVersion) {
        await sleep(400)
        continue
      }
      try {
        return decodeAllowance(obj.content)
      } catch {
        return undefined
      }
    }
    return undefined
  }

  const readClockMs = async (): Promise<bigint | null> => {
    try {
      const res = await core.getObjects({ objectIds: [CLOCK_OBJECT_ID], include: { content: true } })
      const obj = res.objects[0]
      if (obj === undefined || obj instanceof Error) return null
      return decodeClockMs(obj.content)
    } catch {
      return null
    }
  }

  /** When the transaction reached the chain: its checkpoint's time, else the chain clock, else this machine. */
  const chainTime = async (digest: string): Promise<{ ms: bigint; source: "chain" | "local" }> => {
    for (let attempt = 0; attempt < 10; attempt++) {
      try {
        const res = await core.waitForTransaction({ digest, timeout: 30_000 })
        const tx = res.Transaction ?? res.FailedTransaction
        if (tx?.timestampMs !== null && tx?.timestampMs !== undefined) return { ms: BigInt(tx.timestampMs), source: "chain" }
      } catch {
        // fall through to the next attempt
      }
      await sleep(750)
    }
    const clock = await readClockMs()
    return clock === null ? { ms: BigInt(nowLocal()), source: "local" } : { ms: clock, source: "chain" }
  }

  type Executed = {
    readonly kind: "executed" | "failed"
    readonly digest: string
    readonly tx: SuiClientTypes.Transaction<Include>
  }
  /** Build or sign threw: the transaction was never signed, so nothing reached Sui. Safe to refuse. */
  /** `own`: the adapter stopped before signing, so the message is its own, not the client's. */
  type NotSent = { readonly kind: "not-sent"; readonly message: string; readonly own?: true }
  /** Submit threw AFTER signing, and the chain could not confirm the digest: the outcome is unknown. */
  type Unknown = { readonly kind: "unknown"; readonly digest: string; readonly message: string }
  type Outcome = Executed | NotSent | Unknown

  /** Who said why nothing was sent: the client's error, or the adapter's own stop. */
  const notSentWords = (o: NotSent): string => o.own === true ? `sweetrust-sui stopped before signing: ${o.message}` : `The Sui client said: ${o.message}`
  const clip = (e: unknown): string => (e instanceof Error ? e.message : String(e)).replace(/\s+/g, " ").slice(0, 400)

  /**
   * The client every transaction is BUILT with: the caller's client, minus its
   * transport's own resolver. The gRPC and GraphQL resolvers simulate every
   * transaction server-side and throw when the simulation aborts, so a spend
   * Sui would refuse never reaches the chain and leaves no digest (Basecamp's
   * 2026-10-08 refusal has none for exactly this reason). Without a transport
   * resolver the SDK falls back to its generic one, which simulates only to
   * estimate gas, and the budget is always set here. So the transaction is
   * executed, a refusal is a failed transaction with a digest, and the abort is
   * on chain for anyone to read.
   */
  /**
   * One build client per build, which records whether the SDK asked for the
   * transport's resolver. The adapter never sets a gas price, so every build
   * needs resolving and must ask; a build that never asked means the SDK found
   * its resolver some other way, and `execute()` sends nothing (fail closed,
   * whatever `@mysten/sui` release is installed).
   */
  const buildClientFor = (): { readonly client: ClientWithCoreApi; readonly consulted: () => boolean } => {
    let consulted = false
    const client = {
      core: new Proxy(core, {
        get(target, prop) {
          if (prop === "resolveTransactionPlugin") {
            consulted = true
            return () => undefined
          }
          const v: unknown = Reflect.get(target, prop, target)
          return typeof v === "function" ? (v as (...a: Array<unknown>) => unknown).bind(target) : v
        },
      }),
    } as unknown as ClientWithCoreApi
    return { client, consulted: () => consulted }
  }

  /**
   * Is the client really on `network`? Asked once per adapter, before the first
   * transaction it sends: a client on another chain would execute there while
   * every receipt named `network`. A failed read is not cached, so the next
   * send asks again. null = on `network`, or `network` has no fixed genesis.
   */
  let chainCheck: Promise<{ code: RefusalCode; reason: string } | null> | null = null
  const wrongChain = (): Promise<{ code: RefusalCode; reason: string } | null> => {
    const expected = GENESIS[network]
    if (expected === undefined) return Promise.resolve(null)
    if (chainCheck === null) {
      chainCheck = Promise.resolve()
        .then(() => core.getChainIdentifier())
        .then((r) => {
          const id: unknown = r?.chainIdentifier
          if (typeof id !== "string") throw new Error("the client returned no chain identifier")
          if (id === expected) return null
          const known = Object.keys(GENESIS).find((k) => GENESIS[k] === id)
          return { code: "wrong-network" as RefusalCode, reason: `This adapter is set up for ${network}, but its Sui client is connected to ${known ?? `another chain (genesis checkpoint ${id})`}; a receipt from it would name the wrong network.` }
        })
        .catch((e: unknown) => {
          chainCheck = null
          return { code: "not-submitted" as RefusalCode, reason: `This adapter could not confirm that its Sui client is connected to ${network}. The Sui client said: ${clip(e)}` }
        })
    }
    return chainCheck
  }

  /**
   * Ask the chain whether a digest finalized. null = still unknown after the
   * wait (not forwarded, or forwarded but not yet — the caller treats it as
   * unknown, never as a refusal). A finalized transaction that aborted comes
   * back as `failed`, with its digest, exactly like the direct path.
   */
  const resolveDigest = async (digest: string): Promise<Executed | null> => {
    try {
      const res = await core.waitForTransaction({ digest, timeout: confirmTimeoutMs, include: { effects: true, objectTypes: true } })
      if (res.$kind === "Transaction") return { kind: "executed", digest, tx: res.Transaction }
      return { kind: "failed", digest, tx: res.FailedTransaction }
    } catch {
      return null
    }
  }

  /**
   * Build, then sign-and-submit, as two steps split at the point of no return.
   *
   * `tx.build()` produces unsigned bytes: if it throws, nothing was signed and
   * nothing reached Sui (`not-sent`), so the verb refuses in-process. The
   * transaction's digest is derived from those bytes BEFORE submit (the Sui
   * digest is over the transaction data, not the signature), so if
   * `signAndExecuteTransaction` then throws — the signed bytes may already have
   * been forwarded and may finalize — the adapter re-reads that exact digest
   * instead of guessing. Only when the chain cannot confirm it is the outcome
   * `unknown`; a thrown submit is never reported as a definite refusal.
   */
  const execute = async (tx: Transaction, signer: Signer): Promise<Outcome> => {
    let bytes: Uint8Array
    try {
      tx.setSenderIfNotSet(signer.toSuiAddress())
      tx.setGasBudgetIfNotSet(gasBudget)
      const b = buildClientFor()
      bytes = await tx.build({ client: b.client })
      if (!b.consulted()) return { kind: "not-sent", message: RESOLVER_UNCONSULTED, own: true }
    } catch (e) {
      return { kind: "not-sent", message: clip(e) }
    }
    const digest = TransactionDataBuilder.getDigestFromBytes(bytes)
    try {
      const res = await core.signAndExecuteTransaction({ transaction: bytes, signer, include: { effects: true, objectTypes: true } })
      if (res.$kind === "Transaction") return { kind: "executed", digest: res.Transaction.digest, tx: res.Transaction }
      return { kind: "failed", digest: res.FailedTransaction.digest, tx: res.FailedTransaction }
    } catch (e) {
      return (await resolveDigest(digest)) ?? { kind: "unknown", digest, message: clip(e) }
    }
  }

  /** Quote a Move abort from the effects, naming the allowance constant when it is one. */
  const nativeOf = (err: SuiClientTypes.ExecutionError | null | undefined): NativeAbort | null => {
    if (err === null || err === undefined || err.$kind !== "MoveAbort") return null
    const a = err.MoveAbort
    const pkg = a.location?.package
    const mod = a.location?.module
    const isAllowance = mod === "allowance" && pkg !== undefined && normAddr(pkg) === normAddr("0x2")
    const clever = a.cleverError
    const name = clever?.constantName ?? (isAllowance ? abortNameOf(Number(clever?.errorCode ?? a.abortCode)) : null)
    const module = isAllowance ? ALLOWANCE_MODULE : `${pkg === undefined ? "?" : normAddr(pkg)}::${mod ?? "?"}`
    const declared = isAllowance && name !== null && name in ABORTS ? ABORTS[name] : clever?.errorCode ?? Number(a.abortCode)
    return { module, abortName: name ?? "abort", abortCode: declared, rawAbortCode: String(a.abortCode) }
  }

  const versionOf = (tx: SuiClientTypes.Transaction<Include>, id: string): bigint | null => {
    const changed = tx.effects?.changedObjects?.find((c) => normAddr(c.objectId) === normAddr(id))
    return changed?.outputVersion === null || changed?.outputVersion === undefined ? null : BigInt(changed.outputVersion)
  }

  // ── open ──

  const open: SuiAllowances["open"] = async (args) => {
    if (typeof args !== "object" || args === null) throw typeErr("open", "arguments must be an object")
    const signer = args.signer
    const grant = args.allowance
    const nameArg = args.name
    if (typeof signer !== "object" || signer === null || typeof signer.toSuiAddress !== "function") throw typeErr("open", "signer must be a @mysten/sui Signer (the funder's keypair)")
    if (typeof grant !== "object" || grant === null) throw typeErr("open", "allowance must be a DelegatedAllowance")
    const gNetwork = grant.network
    const asset = grant.asset
    const spenderRaw = grant.spender
    const limits = snapshotLimits("open", grant.limits)
    const name = nameArg ?? "sweetrust-sui allowance"
    if (typeof asset !== "string") throw typeErr("open", "allowance.asset must be a coin type string")
    if (typeof spenderRaw !== "string") throw typeErr("open", "allowance.spender must be an address string")
    if (typeof name !== "string") throw typeErr("open", "name must be a string")
    let assetType: string
    try {
      assetType = normalizeStructTag(asset)
    } catch {
      throw typeErr("open", `allowance.asset ${JSON.stringify(asset)} is not a Move type`)
    }
    const funder = normAddr(signer.toSuiAddress())
    const scale = scaleFor(assetType)
    const present = presentLimits(limits)

    const refused = (r: Refusal, lineFor: (l: LimitName) => LimitLine | null): { receipt: AllowanceReceipt; allowance: null } => {
      const lines = present.map((l) => lineFor(l) ?? line(l, limitValue(l, limits, scale), holder(l), "unchecked",
        "Not opened: the allowance was refused at open(), so this limit holds nothing."))
      return {
        receipt: finish(receiptOf({
          verb: "open", verdict: "refused", asset: assetType, allowanceId: null, digest: null, ...localAt(),
          funder, spender: spenderRaw, amount: null, amountText: null, recipient: null,
          limits: lines, refusal: r, summary: r.why,
        })),
        allowance: null,
      }
    }
    const plain = (code: RefusalCode, why: string, native: NativeAbort | null = null, outside: ReadonlyArray<LimitName> = []) =>
      refused(refusal(code, "library", native, why), (l) => outside.includes(l) ? line(l, limitValue(l, limits, scale), holder(l), "outside", why) : null)

    // 1. The right chain.
    if (gNetwork !== network) {
      return plain("wrong-network", `Refused at open(); nothing was sent. The allowance names ${JSON.stringify(gNetwork)}, and this adapter is connected to ${network}.`)
    }
    // 2. A limit nobody can hold is refused, never dropped (ruling 1).
    const unheld = present.filter((l) => holder(l) === "nobody")
    if (unheld.length > 0) {
      const r = refusal("limit-unheld", "library", null, PER_SPEND_UNHELD_WHY)
      return refused(r, (l) => unheld.includes(l) ? line(l, limitValue(l, limits, scale), "nobody", "unheld", PER_SPEND_UNHELD_WHY) : null)
    }
    // 3. Addresses.
    if (!validAddr(spenderRaw)) return plain("invalid-address", `Refused at open(); nothing was sent. The spender ${JSON.stringify(spenderRaw)} is not a Sui address.`)
    const spender = normAddr(spenderRaw)
    if (limits.recipients !== undefined) {
      const bad = limits.recipients.filter((r) => !validAddr(r))
      if (bad.length > 0) return plain("invalid-address", `Refused at open(); nothing was sent. ${bad.map((b) => JSON.stringify(b)).join(", ")} ${bad.length === 1 ? "is" : "are"} not a Sui address, so the recipient list cannot be held.`, null, ["recipients"])
      if (limits.recipients.length === 0) return plain("invalid-limit", "Refused at open(); nothing was sent. An empty recipient list would refuse every spend; leave recipients out to allow any payee.", null, ["recipients"])
    }
    // 4. Sui's own rules, checked before sending so the refusal costs no gas.
    //    Order: periodic_rate_limit runs first in the transaction, then new_settings (allowance.move:177, :473).
    const pre = (abortName: string, code: RefusalCode, rule: string, outside: ReadonlyArray<LimitName> = []) =>
      plain(code, `Refused at open(); nothing was sent to Sui. Sui's rule (${ALLOWANCE_MODULE}::${abortName}, abort code ${ABORTS[abortName]}): ${rule}`, preflightNative(abortName), outside)
    const r = limits.rate
    if (r !== undefined) {
      if (!Number.isSafeInteger(r.windowMs) || r.windowMs <= 0 || r.amount <= 0n) {
        return pre("EBadRateLimit", "invalid-limit", `a rate needs a positive window and a positive amount; this one is ${scale.format(r.amount)} per ${r.windowMs} ms.`, ["rate"])
      }
      if (r.amount > U256_MAX || BigInt(r.windowMs) > U64_MAX) return plain("invalid-limit", "Refused at open(); nothing was sent. The rate does not fit Sui's integer types (u256 amount, u64 window).", null, ["rate"])
    }
    if (limits.lifetimeCap === undefined && r === undefined) {
      return pre("ENoLimit", "unbounded-amount", "every allowance has a lifetime cap or a rate, so it can never be unbounded in amount. This one has neither; add a lifetimeCap, a rate, or both.")
    }
    if (limits.expiry === undefined && r === undefined) {
      return pre("ENoExpiration", "unbounded-time", "every allowance has an expiry or a rate, so it can never be unbounded in time. A lifetime cap alone never ends; add an expiry, or a rate.")
    }
    if (new TextEncoder().encode(name).length > MAX_NAME_BYTES) {
      return pre("ENameTooLong", "invalid-limit", `the allowance's name is at most ${MAX_NAME_BYTES} bytes; this one is ${new TextEncoder().encode(name).length}.`)
    }
    if (limits.lifetimeCap !== undefined) {
      if (limits.lifetimeCap <= 0n) return pre("EZeroLifetimeCap", "invalid-limit", `a lifetime cap must be greater than zero; this one is ${scale.format(limits.lifetimeCap)}.`, ["lifetimeCap"])
      if (limits.lifetimeCap > U256_MAX) return plain("invalid-limit", "Refused at open(); nothing was sent. The lifetime cap does not fit Sui's u256.", null, ["lifetimeCap"])
    }
    const startMs = limits.start?.getTime()
    const expiryMs = limits.expiry?.getTime()
    for (const [l, ms] of [["start", startMs], ["expiry", expiryMs]] as const) {
      if (ms !== undefined && (!Number.isSafeInteger(ms) || ms < 0)) return plain("invalid-limit", `Refused at open(); nothing was sent. The ${limitWords(l)} is not a valid time.`, null, [l])
    }
    if (startMs !== undefined && expiryMs !== undefined && startMs >= expiryMs) {
      return pre("EBadTimeWindow", "invalid-limit", `the expiry must come after the start; the start is ${fmtTime(startMs)} and the expiry ${fmtTime(expiryMs)}.`, ["start", "expiry"])
    }

    // 5. The client is on the network the allowance names (checked once, after every local rule,
    //    so a refusal that needs no network never waits on one).
    const offChain = await wrongChain()
    if (offChain !== null) return plain(offChain.code, `Refused at open(); nothing was sent. ${offChain.reason}`)

    // 6. Send it.
    const tx = new Transaction()
    const rateArg = r === undefined
      ? tx.moveCall({ target: "0x1::option::none", typeArguments: ["0x2::allowance::RateLimit"] })
      : tx.moveCall({
          target: "0x1::option::some",
          typeArguments: ["0x2::allowance::RateLimit"],
          arguments: [tx.moveCall({ target: "0x2::allowance::periodic_rate_limit", arguments: [tx.pure.u64(BigInt(r.windowMs)), tx.pure.u256(r.amount)] })],
        })
    tx.moveCall({
      target: "0x2::allowance::new",
      typeArguments: [balanceType(assetType)],
      arguments: [
        tx.pure.string(name),
        tx.pure.address(spender),
        tx.pure.option("u256", limits.lifetimeCap ?? null),
        tx.pure.option("u64", startMs === undefined ? null : BigInt(startMs)),
        tx.pure.option("u64", expiryMs === undefined ? null : BigInt(expiryMs)),
        rateArg,
      ],
    })
    const out = await execute(tx, signer)
    if (out.kind === "not-sent") {
      return refused(refusal("not-submitted", "library", null, `Refused in-process; nothing was sent to Sui. The transaction could not be built or signed, so no allowance was opened. ${notSentWords(out)}`), () => null)
    }
    if (out.kind === "unknown") {
      const why = `Could not confirm the open: the transaction was signed and may have reached ${network}, but sweetrust-sui could not read its outcome within ${confirmTimeoutMs} ms. The allowance MAY or MAY NOT have been created, so do not retry blindly — a retry could open a SECOND allowance and double the spender's budget. Look up ${out.digest} on ${network} first. The Sui client said: ${out.message}`
      return {
        receipt: finish(receiptOf({
          verb: "open", verdict: "errored", asset: assetType, allowanceId: null, digest: out.digest, ...localAt(),
          funder, spender, amount: null, amountText: null, recipient: null,
          limits: present.map((l) => line(l, limitValue(l, limits, scale), holder(l), "unchecked",
            "Not confirmed: the open's outcome is unknown, so this library can vouch for nothing it holds.")),
          refusal: null, summary: why,
        })),
        allowance: null,
      }
    }
    const when = await chainTime(out.digest)
    const at = { at: new Date(Number(when.ms)).toISOString(), atSource: when.source }
    if (out.kind === "failed") {
      const native = nativeOf(out.tx.status.error)
      const why = `Refused by Sui validators${native === null ? "" : ` (allowance::${native.abortName})`}: the transaction that would have opened the allowance aborted, so nothing was opened. Sui said: ${out.tx.status.error?.message ?? "no message"}.`
      return {
        receipt: finish(receiptOf({
          verb: "open", verdict: "refused", asset: assetType, allowanceId: null, digest: out.digest, ...at,
          funder, spender, amount: null, amountText: null, recipient: null,
          limits: present.map((l) => line(l, limitValue(l, limits, scale), holder(l), "unchecked", "Not opened: Sui refused the transaction.")),
          refusal: refusal(native?.abortName === "ENoLimit" ? "unbounded-amount" : native?.abortName === "ENoExpiration" ? "unbounded-time" : "chain-error", "chain", native, why),
          summary: why,
        })),
        allowance: null,
      }
    }
    // Find the shared Allowance and the soulbound AllowanceCap among the created objects.
    const types = out.tx.objectTypes ?? {}
    let allowanceId: string | null = null
    let capId: string | null = null
    for (const c of out.tx.effects?.changedObjects ?? []) {
      if (c.idOperation !== "Created") continue
      const t = types[c.objectId] ?? ""
      if (/::allowance::AllowanceCap</.test(t)) capId = normAddr(c.objectId)
      else if (/::allowance::Allowance</.test(t)) allowanceId = normAddr(c.objectId)
      else if (t === "" && c.outputOwner?.$kind === "Shared") allowanceId = normAddr(c.objectId)
      else if (t === "" && c.outputOwner?.$kind === "AddressOwner") capId = normAddr(c.objectId)
    }
    if (allowanceId === null || capId === null) {
      // The transaction executed, so something may have been opened: a throw here
      // would lose the receipt and invite a second open. It is `errored`, with the digest.
      const why = `Could not confirm the open: transaction ${out.digest} executed on ${network}, but sweetrust-sui could not find the Allowance and AllowanceCap among its effects. An allowance MAY have been opened, so do not retry blindly — a retry could open a SECOND allowance and double the spender's budget. Look up ${out.digest} on ${network} first.`
      return {
        receipt: finish(receiptOf({
          verb: "open", verdict: "errored", asset: assetType, allowanceId, digest: out.digest, ...at,
          funder, spender, amount: null, amountText: null, recipient: null,
          limits: present.map((l) => line(l, limitValue(l, limits, scale), holder(l), "unchecked", "Unknown: the opened allowance could not be identified in the transaction's effects.")),
          refusal: null, summary: why,
        })),
        allowance: null,
      }
    }
    const handle: SuiAllowance = Object.freeze({ network, asset: assetType, allowanceId, capId, funder, spender, limits })
    const chainHeld = present.filter((l) => holder(l) === "chain").map(limitWords)
    const libHeld = present.filter((l) => holder(l) === "library").map(limitWords)
    const summary = `Opened allowance ${allowanceId} on ${network}: ${spender} may spend ${scale.unit} from ${funder}'s address balance. ` +
      `Sui holds ${chainHeld.join(", ") || "nothing"}${libHeld.length > 0 ? `; the library holds ${libHeld.join(", ")} in-process` : ""}.`
    return {
      receipt: finish(receiptOf({
        verb: "open", verdict: "executed", asset: assetType, allowanceId, digest: out.digest, ...at,
        funder, spender, amount: null, amountText: null, recipient: null,
        limits: present.map((l) => line(l, limitValue(l, limits, scale), holder(l), "held", heldWhy(l, limits, scale))),
        refusal: null, summary,
      })),
      allowance: handle,
    }
  }

  // ── spend ──

  const spend: SuiAllowances["spend"] = async (args) => {
    if (typeof args !== "object" || args === null) throw typeErr("spend", "arguments must be an object")
    const signer = args.signer
    const h = snapshotHandle("spend", args.allowance)
    const amount = args.amount
    const recipientRaw = args.recipient
    if (typeof signer !== "object" || signer === null || typeof signer.toSuiAddress !== "function") throw typeErr("spend", "signer must be a @mysten/sui Signer (the spender's keypair)")
    if (typeof amount !== "bigint") throw typeErr("spend", "amount must be a bigint (base units)")
    if (typeof recipientRaw !== "string") throw typeErr("spend", "recipient must be an address string")
    const scale = scaleFor(h.asset)
    const present = presentLimits(h.limits)
    const amountText = scale.format(amount)
    // The receipt's spender is who actually signed, not what the handle claims.
    const signerAddr = normAddr(signer.toSuiAddress())

    const base = {
      verb: "spend" as Verb, asset: h.asset, allowanceId: h.allowanceId, funder: h.funder, spender: signerAddr,
      amount: amount.toString(), amountText, recipient: recipientRaw,
    }
    // A chain-held limit's value comes from the chain object, never the handle; a
    // disagreement is flagged on the receipt, not hidden.
    const heldValue = (l: LimitName, st: AllowanceState | null): { value: string; flag: string } => {
      if (holder(l) !== "chain" || st === null) return { value: limitValue(l, h.limits, scale), flag: "" }
      const chain = chainLimitValue(l, st, scale)
      const claimed = limitValue(l, h.limits, scale)
      return { value: chain, flag: chain === claimed ? "" : ` (the handle passed to spend() said ${claimed}; the chain's value shown here is authoritative.)` }
    }
    /**
     * A chain-held limit the handle claims but the allowance on chain does not
     * hold: Sui checked nothing, so the line says so instead of reading the
     * missing value as zero.
     */
    const absentOnChain = (l: LimitName, st: AllowanceState | null): LimitLine | null => {
      if (holder(l) !== "chain" || st === null) return null
      const missing = l === "lifetimeCap" ? st.lifetimeCap === null : l === "rate" ? st.rate === null : l === "start" ? st.startMs === null : l === "expiry" ? st.expiryMs === null : false
      if (!missing) return null
      return line(l, "none on chain", "chain", "unchecked", `Not checked by Sui: the handle passed to spend() says ${limitValue(l, h.limits, scale)}, but allowance ${h.allowanceId} on chain holds no ${limitWords(l)}, so Sui checked none.`)
    }
    const notSent = (code: RefusalCode, why: string, own: Partial<Record<LimitName, LimitLine>> = {}): AllowanceReceipt =>
      finish(receiptOf({
        ...base, verdict: "refused", digest: null, ...localAt(),
        limits: present.map((l) => own[l] ?? line(l, limitValue(l, h.limits, scale), holder(l), "unchecked", "Not evaluated: nothing was sent to Sui.")),
        refusal: refusal(code, "library", null, why), summary: why,
      }))

    if (h.network !== network) return notSent("wrong-network", `Refused in-process; nothing was sent. The allowance is on ${h.network}, and this adapter is connected to ${network}.`)
    if (amount <= 0n || amount > U64_MAX) return notSent("invalid-amount", `Refused in-process; nothing was sent. A spend must be a whole number of base units from 1 to ${U64_MAX}; this one is ${amount}.`)
    if (!validAddr(recipientRaw)) return notSent("invalid-address", `Refused in-process; nothing was sent. The recipient ${JSON.stringify(recipientRaw)} is not a Sui address.`)
    const recipient = normAddr(recipientRaw)
    // A hand-built handle can carry a limit nobody holds; refuse rather than ignore it (ruling 1).
    const unheld = present.filter((l) => holder(l) === "nobody")
    if (unheld.length > 0) {
      const why = `Refused in-process; nothing was sent. This allowance carries ${unheld.map(limitWords).join(", ")}, which nobody holds on Sui in sweetrust-sui 0.1, and a limit nobody holds is refused rather than ignored. ${PER_SPEND_UNHELD_WHY.replace(/^Refused at open\(\); nothing was sent to Sui\. /, "")}`
      return notSent("limit-unheld", why, Object.fromEntries(unheld.map((l) => [l, line(l, limitValue(l, h.limits, scale), "nobody", "unheld", why)])))
    }
    // The library-held limit: the payee, checked before anything is sent.
    const allowed = h.limits.recipients
    const recipientsLine = (verdict: "within" | "outside", why: string): LimitLine =>
      line("recipients", limitValue("recipients", h.limits, scale), "library", verdict, why)
    if (allowed !== undefined && !allowed.some((a) => validAddr(a) && normAddr(a) === recipient)) {
      const why = `Refused in-process by sweetrust-sui; nothing was sent to Sui. ${recipient} is not on this allowance's allowed list (${allowed.length} address${allowed.length === 1 ? "" : "es"}: ${allowed.map(shortAddress).join(", ")}). ` +
        "Held by the library, in-process: this protects only spends routed through this library, and the spender's key can still pay any address through another Sui client, up to the limits Sui holds. " +
        RECIPIENTS_SUCCESSOR
      return notSent("recipient-not-allowed", why, { recipients: recipientsLine("outside", why) })
    }

    // The client is on the network the allowance names, checked after every local rule.
    const offChain = await wrongChain()
    if (offChain !== null) return notSent(offChain.code, `Refused in-process; nothing was sent. ${offChain.reason}`)

    // Send it. The chain holds the rest; a refusal comes back as a failed transaction with a digest.
    const tx = new Transaction()
    const coin = tx.coin({ type: h.asset, balance: amount, allowance: { objectId: h.allowanceId, funder: h.funder } })
    tx.transferObjects([coin], tx.pure.address(recipient))
    const out = await execute(tx, signer)
    const recipientsWithin = (): LimitLine => recipientsLine("within",
      `Held by the library, in-process: the payee ${shortAddress(recipient)} was checked against the allowed list before sending. ${RECIPIENTS_SUCCESSOR}`)

    if (out.kind === "not-sent" || out.kind === "unknown") {
      // Re-read the allowance first: if it is gone, a spend against it cannot have
      // executed (its input object no longer exists), so nothing moved — a safe refusal.
      const state = await readAllowance(h.allowanceId, null)
      if (state === null) {
        const why = `Refused: allowance ${h.allowanceId} no longer exists on ${network}, so there was nothing to spend against. It was revoked (revoke deletes it), or it never existed. No transaction was recorded.`
        return finish(receiptOf({
          ...base, recipient, verdict: "refused", digest: null, ...localAt(),
          limits: present.map((l) => l === "recipients" ? recipientsWithin()
            : line(l, limitValue(l, h.limits, scale), holder(l), "unchecked", "Not evaluated: the allowance is gone, so nothing was spent.")),
          refusal: refusal("allowance-gone", "chain", null, why), summary: why,
        }))
      }
      if (out.kind === "not-sent") {
        const why = `Refused in-process; nothing was sent to Sui. The transaction could not be built or signed, so nothing was spent. ${notSentWords(out)}`
        return finish(receiptOf({
          ...base, recipient, verdict: "refused", digest: null, ...localAt(),
          limits: present.map((l) => l === "recipients" ? recipientsWithin()
            : line(l, limitValue(l, h.limits, scale), holder(l), "unchecked", "Not evaluated: nothing was sent to Sui.")),
          refusal: refusal("not-submitted", "library", null, why), summary: why,
        }))
      }
      // Signed, submitted, and the chain could not confirm the digest: the outcome is unknown.
      const why = `Could not confirm the spend: the transaction was signed and may have reached ${network}, but sweetrust-sui could not read its outcome within ${confirmTimeoutMs} ms. The ${amountText} MAY or MAY NOT have moved, so do not retry blindly — a retry could pay twice. Look up ${out.digest} on ${network}, or call remaining(), before retrying. The Sui client said: ${out.message}`
      return finish(receiptOf({
        ...base, recipient, verdict: "errored", digest: out.digest, ...localAt(),
        limits: present.map((l) => l === "recipients" ? recipientsWithin()
          : line(l, limitValue(l, h.limits, scale), holder(l), "unchecked", "Not confirmed: the spend's outcome is unknown.")),
        refusal: null, summary: why,
      }))
    }

    const when = await chainTime(out.digest)
    const at = { at: new Date(Number(when.ms)).toISOString(), atSource: when.source }
    const state = await readAllowance(h.allowanceId, versionOf(out.tx, h.allowanceId))
    const facts: SpendFacts | null = state === null || state === undefined ? null : { scale, amount, nowMs: when.ms, state, executed: out.kind === "executed" }

    if (out.kind === "executed") {
      const lines = present.map((l) => {
        if (l === "recipients") return recipientsWithin()
        const absent = absentOnChain(l, facts === null ? null : facts.state)
        if (absent !== null) return absent
        const { value, flag } = heldValue(l, facts === null ? null : facts.state)
        return line(l, value, holder(l), "within", (facts === null ? "Sui checked it: the spend executed." : chainWithinWhy(l, facts)) + flag)
      })
      return finish(receiptOf({
        ...base, recipient, verdict: "executed", digest: out.digest, ...at, limits: lines, refusal: null,
        summary: `Sent ${amountText} to ${recipient} under allowance ${h.allowanceId} on ${network} (tx ${out.digest}).`,
      }))
    }

    // Refused on chain.
    const err = out.tx.status.error
    const native = nativeOf(err)
    const failed: LimitName | null = native !== null && native.module === ALLOWANCE_MODULE ? LIMIT_BY_ABORT[native.abortName] ?? null : null
    const failedAt = failed === null ? -1 : CHAIN_CHECK_ORDER.indexOf(failed)
    let why: string
    let code: RefusalCode
    if (failed !== null && facts !== null) {
      why = chainOutsideWhy(failed, facts)
      code = failed === "lifetimeCap" ? "lifetime-cap-exceeded" : failed === "rate" ? "rate-exceeded" : failed === "start" ? "not-started" : "expired"
    } else if (failed !== null) {
      code = failed === "lifetimeCap" ? "lifetime-cap-exceeded" : failed === "rate" ? "rate-exceeded" : failed === "start" ? "not-started" : "expired"
      why = `Refused by Sui validators (allowance::${native?.abortName}): this spend was outside ${limitWords(failed)}. sweetrust-sui could not read the allowance afterwards, so the numbers are not shown; the digest has them.`
    } else if (native?.abortName === "ENotSpender") {
      code = "not-spender"
      why = `Refused by Sui validators (allowance::ENotSpender): the transaction was signed by ${normAddr(signer.toSuiAddress())}, and only the allowance's spender ${h.spender} may spend from it.`
    } else {
      code = /insufficient/i.test(err?.message ?? "") ? "insufficient-funds" : "chain-error"
      why = `Refused by Sui validators${native === null ? "" : ` (${native.module}::${native.abortName})`}: ${err?.message ?? "the transaction failed"}.`
    }
    const lines = present.map((l): LimitLine => {
      if (l === "recipients") return recipientsWithin()
      const absent = absentOnChain(l, facts === null ? null : facts.state)
      if (absent !== null) return absent
      const { value, flag } = heldValue(l, facts === null ? null : facts.state)
      const idx = CHAIN_CHECK_ORDER.indexOf(l)
      if (failed !== null && l === failed) return line(l, value, "chain", "outside", why + flag)
      if (failed !== null && idx < failedAt && facts !== null) return line(l, value, "chain", "within", chainWithinWhy(l, facts) + flag)
      if (failed !== null) return line(l, value, "chain", "unchecked", `Not evaluated: Sui checks the start, the expiry, the lifetime cap and then the rate, and stops at the first that fails; ${limitWords(failed)} failed first.` + flag)
      return line(l, value, "chain", "unchecked", `Not evaluated: Sui refused the transaction before its limit checks${native === null ? "" : `, on ${native.abortName}`}.` + flag)
    })
    return finish(receiptOf({
      ...base, recipient, verdict: "refused", digest: out.digest, ...at, limits: lines,
      refusal: refusal(code, "chain", native, why), summary: why,
    }))
  }

  // ── revoke ──

  const revoke: SuiAllowances["revoke"] = async (args) => {
    if (typeof args !== "object" || args === null) throw typeErr("revoke", "arguments must be an object")
    const signer = args.signer
    const h = snapshotHandle("revoke", args.allowance)
    if (typeof signer !== "object" || signer === null || typeof signer.toSuiAddress !== "function") throw typeErr("revoke", "signer must be a @mysten/sui Signer (the funder's keypair)")
    const scale = scaleFor(h.asset)
    const present = presentLimits(h.limits)
    const base = { verb: "revoke" as Verb, asset: h.asset, allowanceId: h.allowanceId, funder: h.funder, spender: h.spender, amount: null, amountText: null, recipient: null }
    if (h.network !== network) {
      const why = `Refused in-process; nothing was sent. The allowance is on ${h.network}, and this adapter is connected to ${network}.`
      return finish(receiptOf({ ...base, verdict: "refused", digest: null, ...localAt(), limits: [], refusal: refusal("wrong-network", "library", null, why), summary: why }))
    }
    const offChain = await wrongChain()
    if (offChain !== null) {
      const why = `Refused in-process; nothing was sent. ${offChain.reason}`
      return finish(receiptOf({ ...base, verdict: "refused", digest: null, ...localAt(), limits: [], refusal: refusal(offChain.code, "library", null, why), summary: why }))
    }
    const tx = new Transaction()
    // Mutability stated, so the build needs no function-signature lookup (the SDK's own pattern for 0x8 Random).
    const byValue = (objectId: string) => tx.object({ $kind: "UnresolvedObject", UnresolvedObject: { objectId, mutable: true } })
    tx.moveCall({ target: "0x2::allowance::revoke", typeArguments: [balanceType(h.asset)], arguments: [byValue(h.capId), byValue(h.allowanceId)] })
    const out = await execute(tx, signer)
    if (out.kind === "not-sent" || out.kind === "unknown") {
      const state = await readAllowance(h.allowanceId, null)
      if (state === null) {
        const why = `Refused: allowance ${h.allowanceId} no longer exists on ${network}; it was already revoked, so there is nothing to revoke. No transaction was recorded.`
        return finish(receiptOf({ ...base, verdict: "refused", digest: null, ...localAt(), limits: [], refusal: refusal("allowance-gone", "chain", null, why), summary: why }))
      }
      if (out.kind === "not-sent") {
        const why = `Refused in-process; nothing was sent to Sui. The revoke could not be built or signed. Only the funder ${h.funder}, who holds the AllowanceCap ${h.capId}, can revoke. ${notSentWords(out)}`
        return finish(receiptOf({ ...base, verdict: "refused", digest: null, ...localAt(), limits: [], refusal: refusal("not-submitted", "library", null, why), summary: why }))
      }
      const why = `Could not confirm the revoke: the transaction was signed and may have reached ${network}, but sweetrust-sui could not read its outcome within ${confirmTimeoutMs} ms. The allowance MAY or MAY NOT still be live. Look up ${out.digest} on ${network}, or call remaining(), before relying on it. The Sui client said: ${out.message}`
      return finish(receiptOf({ ...base, verdict: "errored", digest: out.digest, ...localAt(), limits: [], refusal: null, summary: why }))
    }
    const when = await chainTime(out.digest)
    const at = { at: new Date(Number(when.ms)).toISOString(), atSource: when.source }
    if (out.kind === "failed") {
      const native = nativeOf(out.tx.status.error)
      const why = `Refused by Sui validators${native === null ? "" : ` (${native.module}::${native.abortName})`}: ${out.tx.status.error?.message ?? "the revoke failed"}. The allowance is still live.`
      return finish(receiptOf({ ...base, verdict: "refused", digest: out.digest, ...at, limits: [], refusal: refusal("chain-error", "chain", native, why), summary: why }))
    }
    const lines = present.map((l) => line(l, limitValue(l, h.limits, scale), holder(l), "revoked",
      holder(l) === "chain"
        ? "Revoked on chain: the Allowance object is deleted, so Sui refuses every later spend against it, from any client."
        : "Revoked: the library refuses nothing more because there is nothing left to spend against; the on-chain object is gone."))
    return finish(receiptOf({
      ...base, verdict: "executed", digest: out.digest, ...at, limits: lines, refusal: null,
      summary: `Revoked allowance ${h.allowanceId} on ${network}: the funder's AllowanceCap deleted it, so Sui refuses every later spend against it (tx ${out.digest}).`,
    }))
  }

  // ── remaining ──

  const remaining: SuiAllowances["remaining"] = async (args) => {
    if (typeof args !== "object" || args === null) throw typeErr("remaining", "arguments must be an object")
    const h = snapshotHandle("remaining", args.allowance)
    // Read on the wrong chain, the allowance would not be found and would be
    // reported as revoked: a confident false answer, so this read refuses to answer.
    if (h.network !== network) throw typeErr("remaining", `the allowance is on ${h.network}, and this adapter is connected to ${network}; read there, it would look revoked`)
    const offChain = await wrongChain()
    if (offChain !== null) throw new Error(`sweetrust-sui remaining: ${offChain.reason}`)
    const scale = scaleFor(h.asset)
    const fmt = scale.format
    const [state, clock] = await Promise.all([readAllowance(h.allowanceId, null), readClockMs()])
    const nowMs = clock ?? BigInt(nowLocal())
    const at = new Date(Number(nowMs)).toISOString()
    if (state === undefined) throw new Error(`sweetrust-sui remaining: could not read allowance ${h.allowanceId} on ${network}`)
    if (state === null) {
      return deepFreeze({
        network, allowanceId: h.allowanceId, exists: false, at, lifetime: null, rate: null, start: null, expiry: null,
        active: false, spendableNow: "0",
        limits: presentLimits(h.limits).map((l) => line(l, limitValue(l, h.limits, scale), holder(l), "revoked", "The allowance no longer exists on chain (revoked), so nothing can be spent.")),
        summary: `Allowance ${h.allowanceId} no longer exists on ${network}: it was revoked, so nothing can be spent.`,
      })
    }
    const lines: Array<LimitLine> = []
    let spendable: bigint | null = null
    let lifetime: Remaining["lifetime"] = null
    if (state.lifetimeCap !== null) {
      const left = state.lifetimeCap > state.currentSpend ? state.lifetimeCap - state.currentSpend : 0n
      lifetime = { cap: state.lifetimeCap.toString(), spent: state.currentSpend.toString(), remaining: left.toString() }
      spendable = left
      lines.push(line("lifetimeCap", `${fmt(state.lifetimeCap)} in total`, "chain", left > 0n ? "held" : "outside",
        `Read from the chain: ${fmt(state.currentSpend)} spent, ${fmt(left)} of ${fmt(state.lifetimeCap)} left.`))
    }
    let rate: Remaining["rate"] = null
    if (state.rate !== null) {
      const w = currentWindow(state.rate, nowMs)
      const left = state.rate.limit > w.spent ? state.rate.limit - w.spent : 0n
      const windowMs = state.rate.window.kind === "periodic" ? Number(state.rate.window.periodMs) : null
      rate = {
        limit: state.rate.limit.toString(), windowMs, spentInWindow: w.spent.toString(), remainingInWindow: left.toString(),
        windowStart: w.startMs === null ? null : new Date(Number(w.startMs)).toISOString(),
        windowEnd: w.endMs === null ? null : new Date(Number(w.endMs)).toISOString(),
      }
      spendable = spendable === null ? left : minBig(spendable, left)
      const period = state.rate.window.kind === "periodic" ? periodPhrase(state.rate.window.periodMs) : `${state.rate.window.months}-month window`
      const where = !w.anchored
        ? "No charge yet: the first spend opens the first window."
        : w.endMs === null ? "Calendar-month windows, counted from the first charge." : `The current window opened at ${fmtTime(w.startMs ?? 0n)} and resets at ${fmtTime(w.endMs)}.`
      lines.push(line("rate", `${fmt(state.rate.limit)} per ${period}`, "chain", left > 0n ? "held" : "outside",
        `Read from the chain: ${fmt(w.spent)} spent in the current window, ${fmt(left)} of ${fmt(state.rate.limit)} left. ${where}`))
    }
    const started = state.startMs === null || nowMs >= state.startMs
    const unexpired = state.expiryMs === null || nowMs < state.expiryMs
    if (state.startMs !== null) {
      lines.push(line("start", `from ${fmtTime(state.startMs)}`, "chain", started ? "held" : "outside",
        started ? `Started at ${fmtTime(state.startMs)}.` : `Not started: it starts at ${fmtTime(state.startMs)}, in ${fmtDuration(state.startMs - nowMs)}.`))
    }
    if (state.expiryMs !== null) {
      lines.push(line("expiry", `until ${fmtTime(state.expiryMs)} (exclusive)`, "chain", unexpired ? "held" : "outside",
        unexpired ? `Expires at ${fmtTime(state.expiryMs)}, in ${fmtDuration(state.expiryMs - nowMs)}.` : `Expired at ${fmtTime(state.expiryMs)}, ${fmtDuration(nowMs - state.expiryMs)} ago.`))
    }
    if (h.limits.recipients !== undefined) {
      lines.push(line("recipients", limitValue("recipients", h.limits, scale), "library", "held",
        `Held by the library, in-process, from this handle (the chain object has no recipient list). ${RECIPIENTS_SUCCESSOR}`))
    }
    const active = started && unexpired
    const spendableNow = active ? (spendable ?? 0n) : 0n
    const summary = !active
      ? `Nothing can be spent now: the allowance ${started ? "has expired" : "has not started"}.`
      : `Up to ${fmt(spendableNow)} can be spent now under the limits Sui holds (the funder's address balance may be lower).`
    return deepFreeze({
      network, allowanceId: h.allowanceId, exists: true, at, lifetime, rate,
      start: state.startMs === null ? null : new Date(Number(state.startMs)).toISOString(),
      expiry: state.expiryMs === null ? null : new Date(Number(state.expiryMs)).toISOString(),
      active, spendableNow: spendableNow.toString(), limits: lines, summary,
    })
  }

  return Object.freeze({ network, enforces: declaration, open, spend, revoke, remaining })
}
