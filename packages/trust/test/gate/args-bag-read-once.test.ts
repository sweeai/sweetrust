/**
 * A sink reads every argument before it renders any (the 2026-11-08 series
 * review). A getter on a later key used to edit an earlier argument's object
 * after its receipt entry was written, so the receipt and execute() disagreed.
 */
import { describe, expect, it } from "vitest"
import { makeSink, ReceiptLog, Sourced } from "../../src/gate/index.ts"

const sinkFor = (requires: Record<string, "untrusted">, mode: "enforce" | "warn") => {
  const seen: { ran?: unknown } = {}
  const sink = makeSink<any, string>({
    name: "pay", requires, mode, log: new ReceiptLog(),
    execute: (a: any) => { seen.ran = structuredClone(a.order.value); return "sent" },
  })
  return { sink, seen }
}

describe("every argument is read before any is rendered", () => {
  it("a getter on a later declared key cannot make the receipt differ from what runs", async () => {
    const { sink, seen } = sinkFor({ order: "untrusted", memo: "untrusted" }, "enforce")
    const order = { to: "GOOD" }
    const args = { order: Sourced.fromChannel(order, "x"), get memo() { order.to = "EVIL"; return Sourced.fromChannel("m", "x") } }
    const r: any = await sink(args as any)
    expect(r.receipt.args.order.value).toEqual(seen.ran)
  })

  it("a getter on an undeclared key cannot either", async () => {
    const { sink, seen } = sinkFor({ order: "untrusted" }, "warn")
    const order = { to: "GOOD" }
    const args = { order: Sourced.fromChannel(order, "x"), get extra() { order.to = "EVIL"; return "m" } }
    const r: any = await sink(args as any)
    expect(r.receipt.args.order.value).toEqual(seen.ran)
  })

  it("CONTROL: each argument is still read exactly once", async () => {
    const { sink } = sinkFor({ order: "untrusted", memo: "untrusted" }, "enforce")
    let reads = 0
    const args = { order: Sourced.fromChannel({ to: "A" }, "x"), get memo() { reads++; return Sourced.fromChannel("m", "x") } }
    expect(((await sink(args as any)) as any).ok).toBe(true)
    expect(reads).toBe(1)
  })
})
