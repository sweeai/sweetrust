/**
 * The delegated-allowance interface (ADR 0003), chain-agnostic.
 *
 * A principal grants a spender the right to spend from the principal's own
 * balance, within limits. Nothing here names a chain: the Sui adapter in
 * `./sui.ts` implements it, and a Solana or Base adapter would implement the
 * same types. Each adapter declares, limit by limit, who holds that limit on its
 * chain, and every receipt it writes repeats the label beside the verdict.
 *
 * Amounts are integers in the asset's base units (MIST for SUI), as bigint.
 * Times are `Date`s; receipts render them as ISO strings.
 */

/** A CAIP-2 chain id, e.g. `sui:testnet`, `sui:mainnet`. */
export type Caip2 = `${string}:${string}`

/** The six limits an allowance can carry. */
export type LimitName = "lifetimeCap" | "rate" | "start" | "expiry" | "recipients" | "perSpendMax"

/**
 * Who holds a limit.
 *
 * - `chain`: the chain's own program refuses a spend outside it, so it binds
 *   every spend the spender's key makes, through any client.
 * - `library`: this library refuses in-process, before anything is sent, so it
 *   binds only spends routed through this library.
 * - `nobody`: no layer can hold it. `open()` refuses an allowance that asks for
 *   it, so it is never silently dropped. Only a refused open's receipt carries
 *   this label.
 */
export type HeldBy = "chain" | "library" | "nobody"

/** An adapter's declaration: who holds each limit on its chain. */
export type Enforcement = Readonly<Record<LimitName, HeldBy>>

export interface RateLimit {
  /** The most that may be spent in one window, in base units. */
  readonly amount: bigint
  /** The window length in milliseconds. */
  readonly windowMs: number
}

export interface AllowanceLimits {
  /** The most that may ever be spent, in base units. */
  readonly lifetimeCap?: bigint
  readonly rate?: RateLimit
  /** No spend before this instant (inclusive). */
  readonly start?: Date
  /** No spend at or after this instant (exclusive). */
  readonly expiry?: Date
  /** The only addresses a spend may pay. */
  readonly recipients?: ReadonlyArray<string>
  /** The most one spend may move, in base units. */
  readonly perSpendMax?: bigint
}

/** What a principal grants a spender against the principal's own balance. */
export interface DelegatedAllowance {
  readonly network: Caip2
  /** The asset's type on its chain; on Sui a coin type such as `0x2::sui::SUI`. */
  readonly asset: string
  /** The address allowed to spend. */
  readonly spender: string
  readonly limits: AllowanceLimits
}

/**
 * A refusal's neutral reason. The same code means the same thing on every
 * chain; `native` beside it quotes what the chain itself said.
 */
export type RefusalCode =
  | "lifetime-cap-exceeded"
  | "rate-exceeded"
  | "not-started"
  | "expired"
  | "recipient-not-allowed"
  /** open(): the allowance asks for a limit nobody can hold on this chain. */
  | "limit-unheld"
  /** open(): no limit on how much may be spent. */
  | "unbounded-amount"
  /** open(): no limit on how long it may be spent. */
  | "unbounded-time"
  /** open(): a limit the chain's rules reject (a zero cap, a start after the expiry, ...). */
  | "invalid-limit"
  | "invalid-amount"
  | "invalid-address"
  | "wrong-network"
  | "not-spender"
  /**
   * Nothing was sent, and explicit reads after retries did not find the
   * allowance. Not proof of why: never opened, deleted, or a node that is behind
   * all answer the same way. A revoke with this code did NOT run.
   */
  | "allowance-not-found"
  | "insufficient-funds"
  /** The transaction could not be built or signed, so nothing was sent; the library refused in-process. */
  | "not-submitted"
  /** spend(): the adapter requires a verdict, and this payment names none, or names one for a different payment. */
  | "not-authorized"
  /** The chain refused for a reason this library does not classify; `native` and `why` quote it. */
  | "chain-error"

/** What the chain itself said, quoted beside the neutral code. */
export interface NativeAbort {
  /** The Move module that aborted, fully qualified, e.g. `0x2::allowance`. */
  readonly module: string
  /** The abort constant's name, e.g. `EExceedsRateLimit`. */
  readonly abortName: string
  /** The error code the module declares for that constant, e.g. 4. */
  readonly abortCode: number
  /**
   * The raw u64 abort code as it appears in the transaction's effects (Sui
   * encodes the line and constant into it), or null when nothing was sent and
   * the refusal is a pre-flight check of the chain's rule.
   */
  readonly rawAbortCode: string | null
}

/**
 * The verdict that approved a payment, and the payment it approved. Both are
 * SweeTrust gate digests (`verdictDigest`, `paymentDigest` from `sweetrust/gate`):
 * 64 lowercase hex characters.
 */
export interface AuthorizedBy {
  readonly verdictDigest: string
  /** Null when the judged sink named no payment fields; a null never passes `requireAuthorization`. */
  readonly paymentDigest: string | null
}

export interface Refusal {
  readonly code: RefusalCode
  /** Who refused: the chain's validators, or this library in-process. */
  readonly refusedBy: "chain" | "library"
  /**
   * The chain's own words for the refusal. Set when the chain aborted; also set,
   * with `rawAbortCode` null, when the library refused before sending because
   * the chain's own rule would have aborted (a pre-flight of Sui's `ENoLimit`,
   * `ENoExpiration`). Null when the library refused on a rule of its own.
   */
  readonly native: NativeAbort | null
  /** Plain English: what was refused, by whom, and why. */
  readonly why: string
}

/**
 * One limit's line on a receipt.
 *
 * - `held`: in force (an executed open, a `remaining()` read).
 * - `within`: this spend was inside it.
 * - `outside`: this spend (or this open request) was outside it.
 * - `unchecked`: not evaluated, because an earlier check refused first,
 *   nothing was sent, or the chain could not be read.
 * - `unheld`: nobody can hold it, so the open was refused.
 * - `revoked`: an executed revoke deleted the allowance. Only that receipt
 *   carries it; a read that finds nothing is `unchecked`.
 */
export type LimitVerdict = "held" | "within" | "outside" | "unchecked" | "unheld" | "revoked"

export interface LimitLine {
  readonly limit: LimitName
  /** The limit's value in plain words, e.g. "30.00 testUSD per day". */
  readonly value: string
  readonly heldBy: HeldBy
  readonly verdict: LimitVerdict
  /** Plain English: why this verdict. */
  readonly why: string
}

export type Verb = "open" | "spend" | "revoke"

/**
 * The record every verb returns. JSON-safe: amounts are base-unit strings,
 * times are ISO strings, absent values are null.
 *
 * `verdict` is a RETRY CONTRACT, not just a label:
 * - `executed`: it happened. The chain finalized the transaction.
 * - `refused`: it provably did NOT happen — nothing moved. Either the library
 *   refused in-process before anything was signed, or the chain finalized a
 *   failed transaction. Safe to act on and, where the refusal was transient,
 *   safe to retry. A signed transaction whose outcome is unknown is never
 *   `refused`, even when the allowance is gone: the spend may have landed before
 *   whatever removed it. A `refused` revoke did NOT run; it never means done.
 * - `errored`: UNKNOWN. The transaction was signed and may have reached the
 *   chain, but this adapter could not read its outcome. It MAY have executed.
 *   Do not retry blindly — a blind retry can pay twice or open a second
 *   allowance. The `digest` is set so the outcome can be looked up on chain, or
 *   read back with `remaining()`, before anything is retried.
 */
export interface AllowanceReceipt {
  readonly schema: "sweetrust-sui/receipt@2"
  readonly verb: Verb
  readonly verdict: "executed" | "refused" | "errored"
  readonly network: Caip2
  readonly asset: string
  /** The allowance object, or null when an open was refused or could not be confirmed before anything was sent. */
  readonly allowanceId: string | null
  /**
   * The digest of the signed transaction bytes, or null when nothing was sent;
   * never a digest a node reported. A refused spend that reached the chain has
   * one, and an `errored` receipt has one so the outcome can be looked up on chain.
   */
  readonly digest: string | null
  /** A public explorer page for the digest, or null. */
  readonly explorer: string | null
  /** When it happened: the chain's checkpoint time when the chain was reached, else this machine's clock. */
  readonly at: string
  readonly atSource: "chain" | "local"
  readonly funder: string | null
  readonly spender: string
  /** Spend only: base units, and the same amount in the adapter's display scale. */
  readonly amount: string | null
  readonly amountText: string | null
  readonly recipient: string | null
  /**
   * Spend only: the verdict this payment named, exactly as supplied, refusals
   * included; null when it named none. Checked against the payment only when the
   * adapter requires authorization; otherwise it is the caller's claim, repeated.
   */
  readonly authorizedBy: AuthorizedBy | null
  readonly limits: ReadonlyArray<LimitLine>
  readonly refusal: Refusal | null
  /** One plain-English sentence: what happened. */
  readonly summary: string
}

/** What is left, read from the chain's own object. */
export interface Remaining {
  readonly network: Caip2
  readonly allowanceId: string
  /**
   * True when the object was read. False when explicit reads after retries did
   * not find it, which does not say why. Null when the read could not say.
   */
  readonly exists: boolean | null
  /** The chain's clock when this was read, ISO, or null when it could not be read. Never this machine's clock. */
  readonly at: string | null
  /** Lifetime cap minus everything spent so far, or null when there is no cap. */
  readonly lifetime: { readonly cap: string; readonly spent: string; readonly remaining: string } | null
  /** Rate limit minus what was spent in the current window, or null when there is no rate. */
  readonly rate: {
    readonly limit: string
    readonly windowMs: number | null
    /** Null, like the next field, when the chain's clock could not be read: which window is current depends on it. */
    readonly spentInWindow: string | null
    readonly remainingInWindow: string | null
    /** The current window's bounds, or null before the first charge opens one (or for calendar windows). */
    readonly windowStart: string | null
    readonly windowEnd: string | null
  } | null
  readonly start: string | null
  readonly expiry: string | null
  /** Whether a spend now would pass the start and expiry checks, or null when that could not be determined. */
  readonly active: boolean | null
  /**
   * The most one spend could move right now under the chain-held amount limits
   * (0 when inactive or not found, null when that could not be determined). It
   * does not read the funder's balance, which can be lower.
   */
  readonly spendableNow: string | null
  readonly limits: ReadonlyArray<LimitLine>
  readonly summary: string
}

/** The four verbs, chain-agnostic. `S` is the chain's signer, `H` its handle on an open allowance. */
export interface AllowanceAdapter<S, H> {
  readonly network: Caip2
  /** Who holds each limit on this chain. */
  readonly enforces: Enforcement
  open(args: { signer: S; allowance: DelegatedAllowance; name?: string }): Promise<{ receipt: AllowanceReceipt; allowance: H | null }>
  spend(args: { signer: S; allowance: H; amount: bigint; recipient: string; authorizedBy?: AuthorizedBy }): Promise<AllowanceReceipt>
  revoke(args: { signer: S; allowance: H }): Promise<AllowanceReceipt>
  remaining(args: { allowance: H }): Promise<Remaining>
}
