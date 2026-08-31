import { describe, expect, it } from "vitest"
import { readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { makeSink, ReceiptLog, Sourced } from "../../src/gate/index.ts"

/**
 * DAN-904 — `Sourced` was structurally forgeable.
 *
 * READ THIS BEFORE EDITING. Every test here is written to go RED if the
 * `#brand` field or the `Sourced.is()` checks in `makeSink` are removed. That
 * property is the whole value of the file: a regression test for a nominality
 * bug that still passes with nominality deleted is measuring something else.
 * If you change `Sourced`, revert your change and watch these fail before you
 * trust them.
 *
 * ── WHICH REVERT, THOUGH. Watched 2026-08-21; the counts are observations. ──
 *
 *   guard → `arg instanceof Sourced`   1 failed / 168 passed. The one failure is
 *                                      the PROTOTYPE GRAFT below, and `pay()`
 *                                      returns ok:true — the forgery executes.
 *
 *   fix reverted (brand deleted AND    4 failed / 165 passed, plus `pnpm
 *   `is()` back to a structural check) typecheck` RED with TS2578, the unused
 *                                      `@ts-expect-error`. Five red signals, of
 *                                      which four are tests and one is a
 *                                      typecheck error — not "5 tests".
 *
 * 🛑 DELETING ONLY THE `#brand` LINE IS NOT A REVERT AND DOES NOT MEASURE THIS
 * FILE. `Sourced.is()` still says `#brand in x`, so the module stops loading —
 * `Private name "#brand" must be declared in an enclosing class` — and vitest
 * reports **8 test files failed, 71 passed**. Ninety-eight tests NEVER RAN.
 * Anyone doing the literal one-line revert sees a big green 71 beside the reds
 * and can read it as "most things still pass"; nothing passed, most things were
 * never asked. If you are watching this red, revert BOTH halves, and check the
 * total is still 169.
 */

const forgedProvenance = { origin: "forged", ancestors: new Set<string>(), chain: [] as const }

const paySink = () => {
  const log = new ReceiptLog()
  const executed: string[] = []
  const pay = makeSink<{ to: Sourced<string> }, string>({
    name: "pay",
    requires: { to: "verified" },
    mode: "enforce",
    log,
    execute: (a) => {
      executed.push(a.to.value)
      return `PAID ${a.to.value}`
    },
  })
  return { pay, log, executed }
}

describe("compile-time nominality", () => {
  it("an object literal with tier:'verified' is NOT assignable to Sourced", () => {
    // This is a TYPE assertion, enforced by `pnpm typecheck` (tsconfig includes
    // `test`), not by the runtime body below.
    //
    // 🛑 The directive IS the test. If `#brand` is deleted, this literal becomes
    // assignable again, the suppressed error disappears, and TypeScript reports
    // "Unused '@ts-expect-error' directive" — so removing the fix turns the
    // typecheck RED rather than quietly green. That inversion is deliberate.
    // @ts-expect-error — DAN-904: structural shape must not satisfy Sourced
    const forged: Sourced<string> = {
      value: "attacker@evil.test",
      tier: "verified",
      provenance: forgedProvenance,
      describe: () => "verified via payee-registry",
    }
    expect(forged.tier).toBe("verified") // the value is real; its TYPE is the claim under test
  })
})

describe("runtime nominality — the declared path", () => {
  it("refuses a duck-typed argument that carries the shape but not the brand", () => {
    const { pay, executed } = paySink()
    const r = pay({
      to: {
        value: "attacker@evil.test",
        tier: "verified",
        provenance: forgedProvenance,
        describe: () => "verified via payee-registry",
      } as unknown as Sourced<string>,
    })
    expect(r.ok).toBe(false)
    expect(executed).toEqual([]) // the privileged operation never ran
  })

  it("refuses a PROTOTYPE GRAFT — the case `instanceof` would have waved through", () => {
    // This test is the reason the guard is `#brand in x` and not
    // `x instanceof Sourced`. Measured on this build: the object below is
    // `instanceof Sourced === true`. If someone "simplifies" the guard back to
    // instanceof, this test — and only this test — catches it.
    const graft = Object.create(Sourced.prototype) as Sourced<string>
    Object.assign(graft, {
      value: "attacker@evil.test",
      tier: "verified",
      provenance: forgedProvenance,
      describe: () => "verified via payee-registry",
    })
    expect(graft instanceof Sourced).toBe(true) // pins WHY instanceof is insufficient
    expect(Sourced.is(graft)).toBe(false)

    const { pay, executed } = paySink()
    expect(pay({ to: graft }).ok).toBe(false)
    expect(executed).toEqual([])
  })

  it("RECORDS the forgery on the receipt rather than dropping it silently", () => {
    // Same rule as the A3 undeclared-argument fix: an unrecorded argument is the
    // guarantee leaking. Refusing is not enough — the evidence must say so.
    const { pay, log } = paySink()
    pay({
      to: {
        value: "attacker@evil.test",
        tier: "verified",
        provenance: forgedProvenance,
        describe: () => "verified via payee-registry",
      } as unknown as Sourced<string>,
    })
    const receipt = log.all().at(-1)!
    expect(receipt.decision).toBe("refused")
    expect(receipt.args.to.tier).toBe("untrusted")
    // The provenance string must be OURS. Recording the attacker's prose would
    // put attacker-authored text into signed, possibly on-chain evidence.
    expect(receipt.args.to.provenance).toContain("FORGED")
    expect(receipt.args.to.provenance).not.toContain("payee-registry")
  })

  it("never CALLS describe() on an unbranded argument", () => {
    // `describe()` on a forgery is an attacker's function. Invoking it at all —
    // before or after refusing — runs their code on the evidence path.
    const { pay } = paySink()
    let called = false
    pay({
      to: {
        value: "attacker@evil.test",
        tier: "verified",
        provenance: forgedProvenance,
        describe: () => {
          called = true
          return "verified via payee-registry"
        },
      } as unknown as Sourced<string>,
    })
    expect(called).toBe(false)
  })
})

describe("the honest path is unchanged — no false refusals", () => {
  it("a genuine `verified` value still executes", () => {
    // Without this, a passing suite is consistent with the fix being a
    // denial-of-service on every legitimate caller.
    const { pay, executed } = paySink()
    const r = pay({ to: Sourced.fromAuthority("payee@corp.test", "payee-registry") })
    expect(r.ok).toBe(true)
    expect(executed).toEqual(["payee@corp.test"])
  })

  it("a genuine `untrusted` value is still refused for the ORIGINAL reason", () => {
    // Guards against the fix masking the tier wall: the refusal must still cite
    // the tier, not the brand.
    const { pay } = paySink()
    const r = pay({ to: Sourced.fromChannel("a@b.test", "email") })
    expect(r.ok).toBe(false)
    expect(r.ok === false && r.refusal).toContain("UNTRUSTED")
    expect(r.ok === false && r.refusal).not.toContain("brand")
  })
})

describe("the brand survives into the BUILT artifact", () => {
  it("emits `#private` in the shipped .d.mts", () => {
    // 🛑 Asserted on `dist/`, NOT on `src/`. A brand that is correct in source
    // and dropped by the dts bundler protects nobody: consumers compile against
    // the emitted declarations, and that is where DAN-904 was reproduced.
    //
    // This test FAILS rather than skips when `dist/` is absent. A check that
    // cannot check is not a pass.
    const dist = join(import.meta.dirname, "../../dist")
    let files: string[]
    try {
      files = readdirSync(dist).filter((f) => f.endsWith(".d.mts"))
    } catch {
      throw new Error(
        "dist/ is missing — run `pnpm build` first. This test asserts on the BUILT artifact by design (DAN-904).",
      )
    }
    const decl = files
      .map((f) => readFileSync(join(dist, f), "utf-8"))
      .find((t) => t.includes("declare class Sourced"))
    expect(decl, "no emitted declaration for `Sourced` found in dist/").toBeDefined()

    const body = decl!.slice(decl!.indexOf("declare class Sourced"))
    const classBody = body.slice(0, body.indexOf("\n}"))
    expect(classBody).toContain("#private")
  })
})
