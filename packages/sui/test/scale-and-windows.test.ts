/**
 * The arithmetic under the words: display scales, and Sui's fixed rate windows
 * ported from allowance.move (index_at, elapsed_windows, charge).
 */
import { describe, expect, it } from "vitest"
import { SUI, defineScale } from "../src/scale.ts"
import { currentWindow, decodeAllowance, encodeAllowance, windowIndexAt } from "../src/allowance-move.ts"
import { fmtDuration, periodPhrase } from "../src/explain.ts"

describe("scales", () => {
  const testUSD = defineScale({ unit: "testUSD", baseUnitsPerUnit: 100_000n, decimals: 2 })
  it("formats base units with fixed decimals, or trimmed for SUI", () => {
    expect(testUSD.format(2_400_000n)).toBe("24.00 testUSD")
    expect(testUSD.format(123_456_789_00_000n)).toBe("123,456,789.00 testUSD")
    expect(SUI.format(2_400_000n)).toBe("0.0024 SUI")
    expect(SUI.format(1_000_000_000n)).toBe("1 SUI")
  })
  it("marks a rounded amount and carries its exact base units, so a receipt's sums stay true", () => {
    expect(testUSD.format(2_400_049n)).toBe("≈24.00 testUSD (2,400,049 base units)")
    expect(testUSD.format(2_400_500n)).toBe("≈24.01 testUSD (2,400,500 base units)")
    expect(testUSD.format(-1_234n)).toBe("≈-0.01 testUSD (-1,234 base units)")
    expect(testUSD.format(2_401_000n)).toBe("24.01 testUSD")
    expect(SUI.format(1n)).toBe("0.000000001 SUI")
    expect(testUSD.format(1n)).toBe("≈0.00 testUSD (1 base unit)")
  })
  it("converts display amounts exactly, never through a float", () => {
    expect(testUSD.of(24)).toBe(2_400_000n)
    expect(testUSD.of("0.10")).toBe(10_000n)
    expect(SUI.of("0.0024")).toBe(2_400_000n)
    expect(() => SUI.of("0.0000000001")).toThrow(/finer than one base unit/)
    expect(() => testUSD.of(-1)).toThrow(TypeError)
  })
})

describe("durations", () => {
  it("names the two largest units", () => {
    expect(fmtDuration(86_400_000n)).toBe("1 day")
    expect(fmtDuration(90n * 60_000n)).toBe("1 hour 30 minutes")
    expect(fmtDuration(42_000n)).toBe("42 seconds")
    expect(fmtDuration(350n)).toBe("350 ms")
    expect(periodPhrase(86_400_000n)).toBe("day")
    expect(periodPhrase(6n * 3_600_000n)).toBe("6 hours")
  })
})

describe("Sui's rate window is fixed, anchored at the first charge", () => {
  const DAY = 86_400_000n
  const anchor = BigInt(Date.parse("2026-11-06T18:02:00Z"))
  const rate = (spent: bigint, index: bigint) => ({ limit: 30n, spent, anchorMs: anchor, index, window: { kind: "periodic" as const, periodMs: DAY } })

  it("index_at counts whole periods from the anchor", () => {
    expect(windowIndexAt({ kind: "periodic", periodMs: DAY }, anchor, anchor)).toBe(0n)
    expect(windowIndexAt({ kind: "periodic", periodMs: DAY }, anchor, anchor + DAY - 1n)).toBe(0n)
    expect(windowIndexAt({ kind: "periodic", periodMs: DAY }, anchor, anchor + DAY)).toBe(1n)
  })

  it("charge() resets spend in a later window, so a full window just before the boundary and another just after is 2x the rate", () => {
    expect(currentWindow(rate(30n, 0n), anchor + DAY - 1n)).toMatchObject({ spent: 30n, rolled: false })
    expect(currentWindow(rate(30n, 0n), anchor + DAY)).toMatchObject({ spent: 0n, rolled: true, startMs: anchor + DAY, endMs: anchor + 2n * DAY })
  })

  it("calendar windows follow elapsed_windows: a Jan 31 anchor renews Feb 28, then Mar 31", () => {
    const jan31 = BigInt(Date.parse("2027-01-31T10:00:00Z"))
    const monthly = { kind: "calendar" as const, months: 1 }
    expect(windowIndexAt(monthly, jan31, BigInt(Date.parse("2027-02-27T23:59:59Z")))).toBe(0n)
    expect(windowIndexAt(monthly, jan31, BigInt(Date.parse("2027-02-28T00:00:00Z")))).toBe(1n)
    expect(windowIndexAt(monthly, jan31, BigInt(Date.parse("2027-03-30T00:00:00Z")))).toBe(1n)
    expect(windowIndexAt(monthly, jan31, BigInt(Date.parse("2027-03-31T00:00:00Z")))).toBe(2n)
  })
})

describe("the Allowance object's BCS layout", () => {
  it("round-trips every field, including the RateLimit and Window enums", () => {
    const s = {
      id: `0x${"a1".repeat(32)}`, funder: `0x${"0f".repeat(32)}`, spender: `0x${"5e".repeat(32)}`, app: null,
      lifetimeCap: (1n << 200n) + 7n, startMs: 1n, expiryMs: 1_800_000_000_000n,
      rate: { limit: 30n, spent: 24n, anchorMs: 1_793_000_000_000n, index: 3n, window: { kind: "calendar" as const, months: 3 } },
      name: "sweetrust-sui", currentSpend: 24n,
    }
    expect(decodeAllowance(encodeAllowance(s))).toEqual(s)
  })
})
