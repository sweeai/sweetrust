// makeSink's argument types (DAN-1159 item 4a). tsc is the runner for this file.
// ============================================================================
// A sink written without explicit generics gives `Args` no inference site:
// `requires` maps each key to a Tier and never mentions the argument's type, so
// `Args` falls back to its CONSTRAINT. While that constraint was
// `Record<string, Sourced<any>>`, every `.value` inside `execute` was `any`, and
// `amount.value.whateverNonsense.deep` compiled clean under `strict`: shape lost
// at the enforcement point, in a library whose opening line is "types constrain
// shape". Loosening `any` to `unknown` after a publish would break every sink
// that leaned on it, so the constraint is fixed before the first one.
//
// The `@ts-expect-error` lines are the assertions. Each is an UNUSED directive
// (TS2578, so `pnpm typecheck` is red) while the hole is open, and a satisfied
// one once the constraint is `Sourced<unknown>`. Everything else in this file
// must compile, which is the control: an explicit-generics sink and a narrowed
// read prove the new constraint still admits the honest paths, so the directive
// cannot be swallowing some unrelated error.
// ============================================================================

import { describe, expect, it } from "vitest"
import { makeSink, ReceiptLog, Sourced } from "../../src/gate/index.ts"

describe("makeSink argument types (DAN-1159 item 4a)", () => {
  it("without explicit generics, an argument's value is unknown until narrowed, never any", () => {
    const pay = makeSink({
      name: "pay",
      requires: { amount: "verified" },
      mode: "enforce",
      log: new ReceiptLog(),
      execute: (a) => {
        // @ts-expect-error `value` must be `unknown` here, not `any`
        return a.amount.value.whateverNonsense.deep
      },
    })
    expect(typeof pay).toBe("function")
  })

  it("CONTROL: a narrowed read compiles without generics", () => {
    const log = new ReceiptLog()
    const pay = makeSink({
      name: "pay",
      requires: { amount: "verified" },
      mode: "enforce",
      log,
      execute: (a) => {
        const v = a.amount.value
        return typeof v === "number" ? v.toFixed(2) : "not a number"
      },
    })
    expect(pay({ amount: Sourced.fromAuthority(5, "treasury") })).toMatchObject({ ok: true, result: "5.00" })
  })

  it("CONTROL: explicit generics still satisfy the constraint, and keep the full type", () => {
    const log = new ReceiptLog()
    const pay = makeSink<{ amount: Sourced<number> }, string>({
      name: "pay",
      requires: { amount: "verified" },
      mode: "enforce",
      log,
      execute: (a) => a.amount.value.toFixed(2),
    })
    expect(pay({ amount: Sourced.fromAuthority(5, "treasury") })).toMatchObject({ ok: true, result: "5.00" })
  })
})
