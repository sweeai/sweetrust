/**
 * What this package knows about Sui's native allowance module, `0x2::allowance`
 * (sui-framework `allowance.move`, mainnet since protocol 138). Everything here
 * is read from that source; line numbers below are from the copy Danny's
 * Basecamp build compiled against.
 *
 * No Move of our own: the adapter calls `allowance::new`, `balance_spend` (via
 * the SDK's allowance coin intent) and `revoke`, and reads the shared object.
 */
import { bcs } from "@mysten/sui/bcs"

export const ALLOWANCE_MODULE = "0x2::allowance"
export const CLOCK_OBJECT_ID = "0x6"

/**
 * The module's abort constants and the codes it declares for them
 * (`#[error(code = N)]`, allowance.move:26–62).
 */
export const ABORTS: Readonly<Record<string, number>> = Object.freeze({
  ENotSpender: 0,
  EWrongApp: 1,
  EExpired: 2,
  EExceedsLifetimeCap: 3,
  EExceedsRateLimit: 4,
  ENoLimit: 5,
  EWrongAllowance: 6,
  EBadRateLimit: 7,
  ENotStarted: 8,
  EHasApp: 9,
  EWrongFunder: 10,
  EWrongCap: 11,
  ENameTooLong: 12,
  EZeroLifetimeCap: 13,
  EBadTimeWindow: 14,
  ENoExpiration: 15,
  ENotEnabled: 16,
  ESponsorWithdrawalNotEnabled: 17,
})

const NAME_BY_CODE: ReadonlyMap<number, string> = new Map(Object.entries(ABORTS).map(([k, v]) => [v, k]))
export const abortNameOf = (code: number): string | null => NAME_BY_CODE.get(code) ?? null

/** `MAX_NAME_LENGTH` (allowance.move:64): the label is at most 128 bytes. */
export const MAX_NAME_BYTES = 128
export const U64_MAX = (1n << 64n) - 1n
export const U256_MAX = (1n << 256n) - 1n

// ── The shared object's layout (allowance.move:80–147) ──────────────────────
// `TypeName` is `struct { name: String }`, which serializes as a String.

const Window = bcs.enum("Window", {
  PeriodicMs: bcs.u64(),
  CalendarMonths: bcs.u8(),
})

const RateLimitBcs = bcs.enum("RateLimit", {
  Windowed: bcs.struct("Windowed", {
    limit: bcs.u256(),
    spent: bcs.u256(),
    anchor_ms: bcs.option(bcs.u64()),
    index: bcs.u64(),
    window: Window,
  }),
})

const Settings = bcs.struct("Settings", {
  funder: bcs.Address,
  spender: bcs.option(bcs.Address),
  app: bcs.option(bcs.string()),
  lifetime_cap: bcs.option(bcs.u256()),
  start_timestamp_ms: bcs.option(bcs.u64()),
  expiration_timestamp_ms: bcs.option(bcs.u64()),
  rate_limit: bcs.option(RateLimitBcs),
  name: bcs.string(),
})

/** `Allowance<T>`: `{ id: UID, settings: Settings, current_spend: u256 }`. */
const AllowanceBcs = bcs.struct("Allowance", {
  id: bcs.Address,
  settings: Settings,
  current_spend: bcs.u256(),
})

/** `Clock`: `{ id: UID, timestamp_ms: u64 }`. */
const ClockBcs = bcs.struct("Clock", { id: bcs.Address, timestamp_ms: bcs.u64() })

/** The chain clock's `timestamp_ms`, from the `0x6` object's content. */
export const decodeClockMs = (content: Uint8Array): bigint => BigInt(ClockBcs.parse(content).timestamp_ms)

/** Encode a Clock object's content. Used by the unit tests to stand in for a fullnode. */
export const encodeClock = (timestampMs: bigint): Uint8Array =>
  ClockBcs.serialize({ id: "0x6", timestamp_ms: timestampMs }).toBytes()

export type WindowKind = { readonly kind: "periodic"; readonly periodMs: bigint } | { readonly kind: "calendar"; readonly months: number }

/** The allowance's on-chain state, decoded. */
export interface AllowanceState {
  readonly id: string
  readonly funder: string
  readonly spender: string | null
  readonly app: string | null
  readonly lifetimeCap: bigint | null
  readonly startMs: bigint | null
  readonly expiryMs: bigint | null
  readonly rate: {
    readonly limit: bigint
    readonly spent: bigint
    readonly anchorMs: bigint | null
    readonly index: bigint
    readonly window: WindowKind
  } | null
  readonly name: string
  readonly currentSpend: bigint
}

const big = (v: string | number | bigint): bigint => BigInt(v)
const optBig = (v: string | number | bigint | null | undefined): bigint | null => (v === null || v === undefined ? null : BigInt(v))

export function decodeAllowance(content: Uint8Array): AllowanceState {
  const raw = AllowanceBcs.parse(content)
  const s = raw.settings
  const r = s.rate_limit
  let rate: AllowanceState["rate"] = null
  if (r !== null && r !== undefined) {
    const w = r.Windowed
    const win = w.window
    const window: WindowKind = win.$kind === "PeriodicMs"
      ? { kind: "periodic", periodMs: big(win.PeriodicMs) }
      : { kind: "calendar", months: Number(win.CalendarMonths) }
    rate = { limit: big(w.limit), spent: big(w.spent), anchorMs: optBig(w.anchor_ms), index: big(w.index), window }
  }
  return {
    id: raw.id,
    funder: s.funder,
    spender: s.spender ?? null,
    app: s.app ?? null,
    lifetimeCap: optBig(s.lifetime_cap),
    startMs: optBig(s.start_timestamp_ms),
    expiryMs: optBig(s.expiration_timestamp_ms),
    rate,
    name: s.name,
    currentSpend: big(raw.current_spend),
  }
}

/** Encode an allowance's content, the inverse of decodeAllowance. Used by the unit tests to stand in for a fullnode. */
export function encodeAllowance(s: AllowanceState): Uint8Array {
  const r = s.rate
  return AllowanceBcs.serialize({
    id: s.id,
    settings: {
      funder: s.funder,
      spender: s.spender,
      app: s.app,
      lifetime_cap: s.lifetimeCap,
      start_timestamp_ms: s.startMs,
      expiration_timestamp_ms: s.expiryMs,
      rate_limit: r === null ? null : {
        Windowed: {
          limit: r.limit,
          spent: r.spent,
          anchor_ms: r.anchorMs,
          index: r.index,
          window: r.window.kind === "periodic" ? { PeriodicMs: r.window.periodMs } : { CalendarMonths: r.window.months },
        },
      },
      name: s.name,
    },
    current_spend: s.currentSpend,
  }).toBytes()
}

// ── Window arithmetic, ported from allowance.move:428–470 ───────────────────
// The window is FIXED, not rolling: the first successful charge stamps
// `anchor_ms`, and window k is [anchor + k·period, anchor + (k+1)·period).

const MS_PER_DAY = 86_400_000n

/** `civil_from_ms` (allowance.move:358), Howard Hinnant's civil_from_days. */
function civilFromMs(ms: bigint): [bigint, bigint, bigint] {
  const z = ms / MS_PER_DAY + 719468n
  const era = z / 146097n
  const doe = z % 146097n
  const yoe = (doe - doe / 1460n + doe / 36524n - doe / 146096n) / 365n
  const doy = doe - (365n * yoe + yoe / 4n - yoe / 100n)
  const mp = (5n * doy + 2n) / 153n
  const day = doy - (153n * mp + 2n) / 5n + 1n
  return mp < 10n ? [era * 400n + yoe, mp + 3n, day] : [era * 400n + yoe + 1n, mp - 9n, day]
}

const isLeap = (y: bigint): boolean => y % 4n === 0n && (y % 100n !== 0n || y % 400n === 0n)
const daysInMonth = (y: bigint, m: bigint): bigint =>
  m === 2n ? (isLeap(y) ? 29n : 28n) : m === 4n || m === 6n || m === 9n || m === 11n ? 30n : 31n

/** `index_at` (allowance.move:448): which window `nowMs` falls in, counted from the anchor. */
export function windowIndexAt(window: WindowKind, anchorMs: bigint, nowMs: bigint): bigint {
  if (window.kind === "periodic") return (nowMs - anchorMs) / window.periodMs
  const [ay, am, ad] = civilFromMs(anchorMs)
  const [y, m, d] = civilFromMs(nowMs)
  let elapsed = (y * 12n + m) - (ay * 12n + am)
  const anniversary = ad < daysInMonth(y, m) ? ad : daysInMonth(y, m)
  if (elapsed > 0n && d < anniversary) elapsed -= 1n
  return elapsed / BigInt(window.months)
}

/**
 * The rate window as the chain would see it at `nowMs`: what is already spent
 * in it, and its bounds (periodic windows only; null before the first charge).
 * Mirrors `charge` (allowance.move:428): a later window starts at zero.
 */
export function currentWindow(
  rate: NonNullable<AllowanceState["rate"]>,
  nowMs: bigint,
): { spent: bigint; anchored: boolean; rolled: boolean; startMs: bigint | null; endMs: bigint | null; index: bigint } {
  if (rate.anchorMs === null) return { spent: 0n, anchored: false, rolled: false, startMs: null, endMs: null, index: 0n }
  const index = windowIndexAt(rate.window, rate.anchorMs, nowMs)
  const rolled = index > rate.index
  const spent = rolled ? 0n : rate.spent
  if (rate.window.kind !== "periodic") return { spent, anchored: true, rolled, startMs: null, endMs: null, index }
  const startMs = rate.anchorMs + index * rate.window.periodMs
  return { spent, anchored: true, rolled, startMs, endMs: startMs + rate.window.periodMs, index }
}
