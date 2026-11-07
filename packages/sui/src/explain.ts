/**
 * The words on a receipt. Danny's bar (2026-11-06): "be very communicative on
 * the receipt about WHY SweeTrust judged something outside a limit." Every
 * sentence here says what was judged, who judged it (Sui's validators or this
 * library in-process), and the numbers that decided it.
 */
import type { AllowanceLimits, HeldBy, LimitLine, LimitName, LimitVerdict } from "./interface.ts"
import type { Scale } from "./scale.ts"
import { ABORTS, ALLOWANCE_MODULE, currentWindow, type AllowanceState } from "./allowance-move.ts"

// ── Formatting ───────────────────────────────────────────────────────────────

const pad = (n: number): string => String(n).padStart(2, "0")

/** "2026-11-06 18:02:07 UTC" */
export function fmtTime(ms: bigint | number): string {
  const d = new Date(Number(ms))
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`
}

const UNITS: ReadonlyArray<readonly [bigint, string]> = [
  [86_400_000n, "day"],
  [3_600_000n, "hour"],
  [60_000n, "minute"],
  [1_000n, "second"],
]
const plural = (n: bigint, word: string): string => `${n} ${word}${n === 1n ? "" : "s"}`

/** "1 day", "2 hours 5 minutes", "45 seconds", "350 ms": the two largest units. */
export function fmtDuration(ms: bigint): string {
  let rest = ms < 0n ? -ms : ms
  if (rest < 1_000n) return `${rest} ms`
  const parts: Array<string> = []
  for (const [size, word] of UNITS) {
    if (rest >= size && parts.length < 2) {
      parts.push(plural(rest / size, word))
      rest %= size
    } else if (parts.length > 0) {
      break
    }
  }
  return parts.join(" ")
}

/** The rate's window as a phrase: "day", "6 hours", "90 minutes". */
export function periodPhrase(ms: bigint): string {
  for (const [size, word] of UNITS) {
    if (ms % size === 0n) return ms === size ? word : plural(ms / size, word)
  }
  return `${ms} ms`
}

/** "0x16b7c5…3be713" */
export const shortAddress = (a: string): string => (a.length > 16 ? `${a.slice(0, 8)}…${a.slice(-6)}` : a)

const abortRef = (name: string): string => `allowance::${name}`
const nativeTag = (name: string): string => `${abortRef(name)}, abort code ${ABORTS[name]}`

// ── What each limit is, in words ─────────────────────────────────────────────

export function limitValue(limit: LimitName, limits: AllowanceLimits, scale: Scale): string {
  switch (limit) {
    case "lifetimeCap":
      return `${scale.format(limits.lifetimeCap ?? 0n)} in total`
    case "rate": {
      const r = limits.rate
      return r === undefined ? "none" : `${scale.format(r.amount)} per ${periodPhrase(BigInt(r.windowMs))}, in fixed windows counted from the first charge`
    }
    case "start":
      return limits.start === undefined ? "none" : `from ${fmtTime(limits.start.getTime())}`
    case "expiry":
      return limits.expiry === undefined ? "none" : `until ${fmtTime(limits.expiry.getTime())} (exclusive)`
    case "recipients": {
      const r = limits.recipients ?? []
      return `${r.length} address${r.length === 1 ? "" : "es"}: ${r.map(shortAddress).join(", ")}`
    }
    case "perSpendMax":
      return `${scale.format(limits.perSpendMax ?? 0n)} per spend`
  }
}

/** The limits this allowance actually carries, in a fixed order. */
export function presentLimits(limits: AllowanceLimits): Array<LimitName> {
  const out: Array<LimitName> = []
  if (limits.lifetimeCap !== undefined) out.push("lifetimeCap")
  if (limits.rate !== undefined) out.push("rate")
  if (limits.start !== undefined) out.push("start")
  if (limits.expiry !== undefined) out.push("expiry")
  if (limits.recipients !== undefined) out.push("recipients")
  if (limits.perSpendMax !== undefined) out.push("perSpendMax")
  return out
}

export const line = (limit: LimitName, value: string, heldBy: HeldBy, verdict: LimitVerdict, why: string): LimitLine =>
  Object.freeze({ limit, value, heldBy, verdict, why })

// ── open() ───────────────────────────────────────────────────────────────────

/** Why a held limit is held, for an executed open. */
export function heldWhy(limit: LimitName, limits: AllowanceLimits, scale: Scale): string {
  switch (limit) {
    case "lifetimeCap":
      return `Held by Sui: a spend that would bring the total past ${scale.format(limits.lifetimeCap ?? 0n)} aborts on chain (${nativeTag("EExceedsLifetimeCap")}).`
    case "rate": {
      const r = limits.rate
      const amount = r === undefined ? "?" : scale.format(r.amount)
      const period = r === undefined ? "?" : periodPhrase(BigInt(r.windowMs))
      const length = r === undefined ? "?" : fmtDuration(BigInt(r.windowMs))
      return `Held by Sui: at most ${amount} per ${period}; a spend past it aborts on chain (${nativeTag("EExceedsRateLimit")}). Sui's windows are fixed, not rolling: the first charge opens the first window, and each window lasts exactly ${length}.`
    }
    case "start":
      return `Held by Sui: a spend that reaches the chain before ${fmtTime(limits.start?.getTime() ?? 0)} aborts (${nativeTag("ENotStarted")}).`
    case "expiry":
      return `Held by Sui: a spend that reaches the chain at or after ${fmtTime(limits.expiry?.getTime() ?? 0)} aborts (${nativeTag("EExpired")}).`
    case "recipients":
      return `Held by the library, in-process: every payee is checked against this allowed list before anything is sent, so this binds only spends routed through sweetrust-sui. Sui's plain allowance has no recipient list. ${RECIPIENTS_SUCCESSOR}`
    case "perSpendMax":
      return `Nobody holds this on Sui in sweetrust-sui 0.1. ${PER_SPEND_SUCCESSOR}`
  }
}

/**
 * The on-chain successor of each limit Sui's plain allowance cannot hold, named
 * on every receipt that labels such a limit `library` or refuses it (Danny,
 * 2026-11-06: "Anything in the Sui stack or repos ecosystem that is going to
 * help us, we have got to leverage"). The inventory behind these sentences is
 * ADR 0003 § "What on Sui could hold each limit". Status as read 2026-11-06.
 */
export const RECIPIENTS_SUCCESSOR =
  "On Sui this limit can move on-chain through Sui Agent Payments' allowed services, which is testnet-only with no public package yet, " +
  "or through an app-bound allowance (allowance::propose_for_app), which needs an audited app module; none is public."

export const PER_SPEND_SUCCESSOR =
  "Its on-chain successor is Sui Agent Payments' per-payment cap (\"enforced onchain at settlement\"), which is testnet-only with no public package yet."

export const PER_SPEND_UNHELD_WHY =
  "Refused at open(); nothing was sent to Sui. No layer in sweetrust-sui 0.1 holds a per-spend maximum. Sui's plain allowance has no per-spend field " +
  "(only an app-bound allowance could add one, and 0.1 opens plain allowances), and the library does not hold it " +
  "in-process, because a cap on one spend is undone by splitting the payment into several. " +
  `Opening anyway would drop the limit silently, so nothing was opened. ${PER_SPEND_SUCCESSOR} ` +
  "Until then, bound the total with the lifetime cap and the rate, which Sui holds."

// ── spend() ──────────────────────────────────────────────────────────────────

/** The chain-held limits in the order `consume` checks them (allowance.move:405–418). */
export const CHAIN_CHECK_ORDER: ReadonlyArray<LimitName> = ["start", "expiry", "lifetimeCap", "rate"]

const LIMIT_WORDS: Readonly<Record<LimitName, string>> = {
  lifetimeCap: "the lifetime cap",
  rate: "the rate",
  start: "the start time",
  expiry: "the expiry",
  recipients: "the recipient list",
  perSpendMax: "the per-spend maximum",
}
export const limitWords = (l: LimitName): string => LIMIT_WORDS[l]

export interface SpendFacts {
  readonly scale: Scale
  readonly amount: bigint
  /** When the transaction reached the chain, ms. */
  readonly nowMs: bigint
  /** The allowance as it stands after the transaction (unchanged by an abort). */
  readonly state: AllowanceState
  /** True when the spend executed (the state then includes it). */
  readonly executed: boolean
}

/** A chain-held limit's line when Sui checked it and it passed. */
export function chainWithinWhy(limit: LimitName, f: SpendFacts): string {
  const s = f.state
  const fmt = f.scale.format
  switch (limit) {
    case "start":
      return `Sui checked it: the spend reached the chain at ${fmtTime(f.nowMs)}, after the start at ${fmtTime(s.startMs ?? 0n)}.`
    case "expiry":
      return `Sui checked it: the spend reached the chain at ${fmtTime(f.nowMs)}, ${fmtDuration((s.expiryMs ?? 0n) - f.nowMs)} before the expiry at ${fmtTime(s.expiryMs ?? 0n)}.`
    case "lifetimeCap": {
      const cap = s.lifetimeCap ?? 0n
      const total = f.executed ? s.currentSpend : s.currentSpend + f.amount
      return f.executed
        ? `Sui checked it: ${fmt(total)} of the ${fmt(cap)} cap is now spent, ${fmt(cap - total)} left.`
        : `Sui checked it and it passed: ${fmt(s.currentSpend)} spent plus this ${fmt(f.amount)} is ${fmt(total)}, within the ${fmt(cap)} cap (the transaction was then refused, so nothing was charged).`
    }
    case "rate": {
      const r = s.rate
      if (r === null) return "Sui checked it."
      const w = currentWindow(r, f.nowMs)
      const ends = w.endMs === null ? "" : ` The window resets at ${fmtTime(w.endMs)}.`
      const opened = f.executed && r.anchorMs === f.nowMs ? ` This spend opened the first window (Sui anchors windows at the first charge, ${fmtTime(f.nowMs)}).` : ""
      return `Sui checked it: the current window now holds ${fmt(w.spent)} of ${fmt(r.limit)}.${opened}${ends}`
    }
    default:
      return "Checked."
  }
}

/** Why Sui refused, for the limit whose abort the effects quote. */
export function chainOutsideWhy(limit: LimitName, f: SpendFacts): string {
  const s = f.state
  const fmt = f.scale.format
  const by = (name: string): string => `Refused by Sui validators (${abortRef(name)})`
  switch (limit) {
    case "start": {
      const start = s.startMs ?? 0n
      const early = start - f.nowMs
      const when = early > 0n ? `, ${fmtDuration(early)} early` : ""
      return `${by("ENotStarted")}: the allowance starts at ${fmtTime(start)}, and this spend reached the chain at ${fmtTime(f.nowMs)}${when}. Sui refuses every spend before the start time.`
    }
    case "expiry": {
      const expiry = s.expiryMs ?? 0n
      const late = f.nowMs - expiry
      const when = late > 0n ? `, ${fmtDuration(late)} after it` : ""
      return `${by("EExpired")}: the allowance expired at ${fmtTime(expiry)}, and this spend reached the chain at ${fmtTime(f.nowMs)}${when}. The expiry is exclusive: from that instant on, every spend is refused.`
    }
    case "lifetimeCap": {
      const cap = s.lifetimeCap ?? 0n
      const left = cap > s.currentSpend ? cap - s.currentSpend : 0n
      return `${by("EExceedsLifetimeCap")}: this ${fmt(f.amount)} spend would bring the lifetime total to ${fmt(s.currentSpend + f.amount)}, over the ${fmt(cap)} lifetime cap. ${fmt(s.currentSpend)} had already been spent, so at most ${fmt(left)} more can ever go out.`
    }
    case "rate": {
      const r = s.rate
      if (r === null) return `${by("EExceedsRateLimit")}.`
      const w = currentWindow(r, f.nowMs)
      const period = r.window.kind === "periodic" ? periodPhrase(r.window.periodMs) : `${r.window.months} calendar month${r.window.months === 1 ? "" : "s"}`
      const rateText = `the rate of ${fmt(r.limit)} per ${period}`
      if (!w.anchored || w.spent === 0n) {
        const why = !w.anchored ? "no window is open yet, and the first charge opens one" : `the current window (${fmtTime(w.startMs ?? 0n)} to ${fmtTime(w.endMs ?? 0n)}) is still empty`
        return `${by("EExceedsRateLimit")}: this ${fmt(f.amount)} spend alone is over ${rateText}; ${why}, so no window can hold it.`
      }
      const fixed = w.startMs === null
        ? "Sui's windows are fixed calendar months, counted from the first charge."
        : w.index === 0n
          ? `Sui's window is fixed: it opened at the first charge (${fmtTime(w.startMs)}) and resets at ${fmtTime(w.endMs ?? 0n)}.`
          : `Sui's window is fixed: windows are counted from the first charge (${fmtTime(r.anchorMs ?? 0n)}); the current one opened at ${fmtTime(w.startMs)} and resets at ${fmtTime(w.endMs ?? 0n)}.`
      return `${by("EExceedsRateLimit")}: this ${fmt(f.amount)} spend would bring the current window to ${fmt(w.spent + f.amount)}, over ${rateText}. ${fixed}`
    }
    default:
      return "Refused by Sui validators."
  }
}

/** Which limit each chain abort speaks for. */
export const LIMIT_BY_ABORT: Readonly<Record<string, LimitName>> = Object.freeze({
  ENotStarted: "start",
  EExpired: "expiry",
  EExceedsLifetimeCap: "lifetimeCap",
  EExceedsRateLimit: "rate",
})

export { ALLOWANCE_MODULE }
