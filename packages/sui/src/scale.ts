/**
 * How an amount reads in a receipt. The chain counts base units (MIST); a
 * person reads "24.00 testUSD" or "0.0024 SUI". A scale is only a label and a
 * divisor: it converts nothing on chain, and the receipt carries the base-unit
 * string beside every rendered amount.
 */

export interface Scale {
  /** The label printed after every amount, e.g. "SUI" or "testUSD". */
  readonly unit: string
  /** Base units in one display unit, e.g. 1_000_000_000n MIST per SUI. */
  readonly baseUnitsPerUnit: bigint
  /** Digits after the point when printing. */
  readonly decimals: number
  /** Drop trailing zeros after the point ("0.0024 SUI", not "0.002400000 SUI"). */
  readonly trim: boolean
  /**
   * Render base units in this scale, e.g. 2_400_000n → "24.00 testUSD". An
   * amount the decimals cannot show exactly is marked and carries its base
   * units: 2_400_049n → "≈24.00 testUSD (2,400,049 base units)".
   */
  format(baseUnits: bigint): string
  /** Base units for a display amount, e.g. of(24) or of("24.50"). Exact: no float arithmetic. */
  of(amount: number | string): bigint
}

const pow10 = (n: number): bigint => 10n ** BigInt(n)

/**
 * Define a display scale. `decimals` must not exceed the precision the divisor
 * can show, so for a power of ten it is at most its exponent.
 */
export function defineScale(args: { unit: string; baseUnitsPerUnit: bigint; decimals: number; trim?: boolean }): Scale {
  const unit = args.unit
  const per = args.baseUnitsPerUnit
  const decimals = args.decimals
  const trim = args.trim ?? false
  if (typeof unit !== "string" || unit.length === 0) throw new TypeError("defineScale: unit must be a non-empty string")
  if (typeof per !== "bigint" || per <= 0n) throw new TypeError("defineScale: baseUnitsPerUnit must be a positive bigint")
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 30) throw new TypeError("defineScale: decimals must be an integer from 0 to 30")

  const format = (baseUnits: bigint): string => {
    const negative = baseUnits < 0n
    const abs = negative ? -baseUnits : baseUnits
    const sign = negative ? "-" : ""
    // Fixed-point: scale to `decimals` digits, rounding half up, all in bigint.
    const scaled = (abs * pow10(decimals) * 2n + per) / (per * 2n)
    const whole = scaled / pow10(decimals)
    let frac = decimals === 0 ? "" : (scaled % pow10(decimals)).toString().padStart(decimals, "0")
    if (trim) frac = frac.replace(/0+$/, "")
    const digits = whole.toLocaleString("en-US") + (frac === "" ? "" : `.${frac}`)
    // A rounded amount says so and carries its exact base units, so the sums in
    // a receipt's WHY stay true: "≈24.00 testUSD (2,400,049 base units)" never
    // reads as exactly 24.00 beside a cap of 24.00.
    if ((abs * pow10(decimals)) % per !== 0n) return `≈${sign}${digits} ${unit} (${sign}${abs.toLocaleString("en-US")} base unit${abs === 1n ? "" : "s"})`
    return `${sign}${digits} ${unit}`
  }

  const of = (amount: number | string): bigint => {
    const text = typeof amount === "number" ? (Number.isFinite(amount) ? String(amount) : "") : amount
    const m = /^(\d+)(?:\.(\d+))?$/.exec(text)
    if (m === null) throw new TypeError(`${unit}.of: ${JSON.stringify(amount)} is not a non-negative decimal amount`)
    const fracDigits = m[2] ?? ""
    const numerator = BigInt(m[1] + fracDigits) * per
    const denominator = pow10(fracDigits.length)
    if (numerator % denominator !== 0n) {
      throw new TypeError(`${unit}.of: ${text} is finer than one base unit (1 ${unit} = ${per} base units)`)
    }
    return numerator / denominator
  }

  return Object.freeze({ unit, baseUnitsPerUnit: per, decimals, trim, format, of })
}

/** SUI as people write it: 1 SUI = 1,000,000,000 MIST. */
export const SUI = defineScale({ unit: "SUI", baseUnitsPerUnit: 1_000_000_000n, decimals: 9, trim: true })

/** Raw base units of an asset with no known scale. */
export const baseUnitsOf = (asset: string): Scale =>
  defineScale({ unit: `base units of ${asset}`, baseUnitsPerUnit: 1n, decimals: 0 })
